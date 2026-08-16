#!/usr/bin/env python3
"""
ProvProxy P9 Contribution-Isolating Ablation
============================================

Purpose
-------
Consolidate the already-implemented V0-V4 tiers and fan-out control into one
paper-oriented comparison without changing runtime logic.

This is NOT yet an external-tool comparison. It is the controlled functional
ablation that isolates what each ProvProxy capability contributes:

    B0  Stateless policy/pattern baseline
    B1  Exact provenance
    B2  + transformation-aware decoding
    B3  + approximate provenance
    B4  + cross-call accumulation
    B5  + cross-destination fan-out REVIEW

Run from project root:

    py -m benchmarks.p9_contribution_ablation

The script first runs the existing evaluation/fan-out benchmarks, then reads
their generated artifacts and writes:

    benchmarks/results/p9_contribution_ablation.json
    benchmarks/results/p9_contribution_ablation.md

No new detection rules are introduced here.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarks" / "results"


@dataclass
class AblationRow:
    configuration: str
    capability: str
    detection_rate: Optional[float]
    enforcement_fpr: Optional[float]
    p50_ms: Optional[float]
    p95_ms: Optional[float]
    p99_ms: Optional[float]
    peak_kb: Optional[float]
    distributed_destination_exposure: Optional[float]
    notes: str


def run_checked(args: list[str]) -> None:
    print(f"[RUN] {' '.join(args)}")
    proc = subprocess.run(args, cwd=ROOT)
    if proc.returncode != 0:
        raise SystemExit(
            f"Benchmark failed with exit code {proc.returncode}: {' '.join(args)}"
        )


def load_summary_csv() -> dict[str, dict[str, str]]:
    path = RESULTS / "summary.csv"
    if not path.exists():
        raise FileNotFoundError(path)
    rows: dict[str, dict[str, str]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            tier = (row.get("tier") or "").strip().lower()
            if tier:
                rows[tier] = row
    return rows


def parse_float(row: dict[str, str], *names: str) -> Optional[float]:
    for name in names:
        raw = row.get(name)
        if raw not in (None, ""):
            try:
                return float(raw)
            except ValueError:
                pass
    return None


def load_memory() -> dict[str, float]:
    # Prefer machine-readable extraction from memory.md because historical
    # artifacts use a compact markdown table rather than a dedicated CSV.
    path = RESULTS / "memory.md"
    if not path.exists():
        return {}
    out: dict[str, float] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 2:
            continue
        tier = cells[0].lower()
        try:
            value = float(cells[1])
        except ValueError:
            continue
        if tier.startswith("v"):
            out[tier] = value
    return out


def load_fanout() -> dict[str, dict]:
    path = RESULTS / "fanout_validation.jsonl"
    out: dict[str, dict] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        mode = row.get("mode")
        if mode:
            out[mode] = row
    return out


def exposure_fraction(row: dict) -> Optional[float]:
    # Historical artifact may store exposure either as 0..1 or percentage.
    for key in ("exposure", "exposure_fraction", "exposure_pct"):
        if key not in row:
            continue
        try:
            value = float(row[key])
        except (TypeError, ValueError):
            continue
        if key == "exposure_pct" or value > 1.0:
            return value / 100.0
        return value
    return None


def tier_row(
    tier: str,
    label: str,
    capability: str,
    summary: dict[str, dict[str, str]],
    memory: dict[str, float],
    notes: str,
) -> AblationRow:
    row = summary[tier]
    return AblationRow(
        configuration=label,
        capability=capability,
        detection_rate=parse_float(row, "detection_rate"),
        enforcement_fpr=parse_float(row, "enforcement_false_positive_rate", "fpr_enforce", "enforcement_fpr"),
        p50_ms=parse_float(row, "p50_ms"),
        p95_ms=parse_float(row, "p95_ms"),
        p99_ms=parse_float(row, "p99_ms"),
        peak_kb=memory.get(tier),
        distributed_destination_exposure=None,
        notes=notes,
    )


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)

    # Freshly regenerate the underlying evidence using existing project code.
    run_checked([sys.executable, "run_evaluation.py"])
    run_checked([sys.executable, "-m", "benchmarks.fanout_validation"])

    summary = load_summary_csv()
    missing = [tier for tier in ("v0", "v1", "v2", "v3", "v4") if tier not in summary]
    if missing:
        raise SystemExit(f"summary.csv missing tiers: {missing}")

    memory = load_memory()
    fanout = load_fanout()

    rows = [
        tier_row(
            "v0", "B0 / V0", "Stateless policy baseline",
            summary, memory,
            "No provenance correlation."
        ),
        tier_row(
            "v1", "B1 / V1", "Exact provenance",
            summary, memory,
            "Adds exact source-to-egress correlation."
        ),
        tier_row(
            "v2", "B2 / V2", "Exact + transformation-aware",
            summary, memory,
            "Adds bounded Base64/Hex/URL/JSON decoding."
        ),
        tier_row(
            "v3", "B3 / V3", "Exact + transform + approximate",
            summary, memory,
            "Adds N-gram approximate correlation."
        ),
        tier_row(
            "v4", "B4 / V4", "Exact + transform + approximate + cross-call",
            summary, memory,
            "Adds per-session/per-destination accumulation."
        ),
    ]

    strict = fanout.get("strict_destination_only", {})
    guarded = fanout.get("fanout_guard", {})

    # B5 is the same V4 detector plus the separately validated review-only
    # cross-destination control. We therefore inherit core V4 DR/FPR/latency
    # metrics and add the distributed-destination exposure measurement.
    v4 = rows[-1]
    rows.append(
        AblationRow(
            configuration="B5 / V4+fanout",
            capability="V4 + cross-destination REVIEW",
            detection_rate=v4.detection_rate,
            enforcement_fpr=v4.enforcement_fpr,
            p50_ms=None,  # not measured in the fanout benchmark; do not invent it
            p95_ms=None,
            p99_ms=None,
            peak_kb=None,
            distributed_destination_exposure=exposure_fraction(guarded),
            notes=(
                "Fan-out is REVIEW-only. Core V4 metrics are not re-labeled as "
                "fan-out latency/memory measurements."
            ),
        )
    )

    strict_exposure = exposure_fraction(strict)
    guarded_exposure = exposure_fraction(guarded)
    if strict_exposure is not None:
        rows[4].distributed_destination_exposure = strict_exposure

    payload = {
        "scope": (
            "Controlled functional ablation. These are ProvProxy variants, "
            "not independent external products."
        ),
        "rows": [asdict(r) for r in rows],
        "fanout_before_after": {
            "strict_destination_exposure": strict_exposure,
            "fanout_guard_exposure": guarded_exposure,
            "absolute_reduction": (
                strict_exposure - guarded_exposure
                if strict_exposure is not None and guarded_exposure is not None
                else None
            ),
        },
    }

    json_path = RESULTS / "p9_contribution_ablation.json"
    md_path = RESULTS / "p9_contribution_ablation.md"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def fmt(value: Optional[float], digits: int = 3) -> str:
        return "N/M" if value is None else f"{value:.{digits}f}"

    md = [
        "# P9 Contribution-Isolating Ablation",
        "",
        "> **Scope:** controlled ProvProxy functional variants; not external products.",
        "",
        "| Config | Capability | DR | Enforcement FPR | p50 ms | p95 ms | p99 ms | Peak KB | Distributed-destination exposure |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        exp = (
            "N/M"
            if r.distributed_destination_exposure is None
            else f"{100*r.distributed_destination_exposure:.1f}%"
        )
        md.append(
            f"| {r.configuration} | {r.capability} | "
            f"{fmt(r.detection_rate)} | {fmt(r.enforcement_fpr)} | "
            f"{fmt(r.p50_ms)} | {fmt(r.p95_ms)} | {fmt(r.p99_ms)} | "
            f"{fmt(r.peak_kb)} | {exp} |"
        )

    md += [
        "",
        "## Interpretation",
        "",
        "- V0-V4 isolate the marginal security gain of stateful provenance capabilities.",
        "- B5 evaluates a separate review-only fan-out control for distributed-destination rotation.",
        "- `N/M` means **not measured**; the table deliberately avoids carrying metrics across experiments where they were not measured.",
        "- This table must not be described as an external-tool comparison.",
        "",
        "## Next P9 step",
        "",
        "Run independently implemented/reproducible external baselines on the same frozen attack corpus where their interfaces permit a fair comparison.",
        "",
    ]
    md_path.write_text("\n".join(md), encoding="utf-8")

    print("=" * 118)
    print("PROVPROXY P9 CONTRIBUTION-ISOLATING ABLATION")
    print("=" * 118)
    print(
        f"{'config':<16} {'DR':>7} {'FPR':>7} {'p95ms':>9} "
        f"{'peakKB':>9} {'dist-exposure':>14}"
    )
    print("-" * 118)
    for r in rows:
        exp = (
            "-"
            if r.distributed_destination_exposure is None
            else f"{100*r.distributed_destination_exposure:.1f}%"
        )
        print(
            f"{r.configuration:<16} {fmt(r.detection_rate):>7} "
            f"{fmt(r.enforcement_fpr):>7} {fmt(r.p95_ms):>9} "
            f"{fmt(r.peak_kb):>9} {exp:>14}"
        )
    print("-" * 118)
    print(f"JSON:     {json_path}")
    print(f"Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
