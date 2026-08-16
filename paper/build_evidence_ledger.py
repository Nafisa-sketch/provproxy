from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarks" / "results"

OUT_JSON = ROOT / "paper" / "EVIDENCE_LEDGER.json"
OUT_MD = ROOT / "paper" / "EVIDENCE_LEDGER.md"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]


def read_csv(path: Path) -> list[dict]:
    with path.open(
        "r",
        newline="",
        encoding="utf-8-sig",
    ) as f:
        return list(csv.DictReader(f))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def maybe_number(value):
    if value is None:
        return None

    if isinstance(value, (int, float, bool)):
        return value

    text = str(value).strip()

    if text == "":
        return text

    low = text.lower()

    if low == "true":
        return True

    if low == "false":
        return False

    try:
        if any(c in text for c in ".eE"):
            return float(text)
        return int(text)
    except ValueError:
        return text


def normalize_row(row: dict) -> dict:
    return {
        key: maybe_number(value)
        for key, value in row.items()
    }


def source(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


ledger: dict[str, Any] = {
    "ledger_version": "provproxy-evidence-v1",
    "purpose": (
        "Canonical manuscript evidence ledger. "
        "Numbers must be traced to committed artifacts, not chat history."
    ),
    "rules": {
        "p11_is_primary_core_evaluation": True,
        "p12_is_post_p11_semantic_extension": True,
        "semantic_review_is_not_hard_detection": True,
        "posthoc_p12_thresholds_do_not_replace_0_60": True,
        "negative_results_preserved": True,
    },
    "evidence": {},
}


# =====================================================================
# P11 — PRIMARY FROZEN CORE EVALUATION
# =====================================================================

p11_summary_path = RESULTS / "p11" / "p11_summary.csv"
p11_category_path = RESULTS / "p11" / "p11_category_summary.csv"
p11_sig_path = RESULTS / "p11" / "p11_paired_significance.md"
p11_summary_md_path = RESULTS / "p11" / "p11_summary.md"

p11_rows = [
    normalize_row(r)
    for r in read_csv(p11_summary_path)
]

p11_categories = [
    normalize_row(r)
    for r in read_csv(p11_category_path)
]

p11_sig_text = read_text(p11_sig_path)

p11 = {
    "role": "PRIMARY frozen detector-blind core evaluation",
    "sources": {
        "summary": source(p11_summary_path),
        "categories": source(p11_category_path),
        "paired_significance": source(p11_sig_path),
        "narrative_summary": source(p11_summary_md_path),
    },
    "summary_rows": p11_rows,
    "category_rows": p11_categories,
}


# Extract paired transitions directly from the committed Markdown table.
#
# Canonical artifact format:
#
# | Comparison | Both miss | New catches | Regressions | Both hit | McNemar p |
# | B0 -> B1   | 191       | 609         | 0           | 0        | ...       |
#
# We preserve ALL five transitions present in the artifact. Later manuscript
# claims may discuss a subset, but the evidence ledger should mirror the
# committed source rather than silently discard B0 -> B1.

paired = []

in_paired_section = False

for raw_line in p11_sig_text.splitlines():
    line = raw_line.strip()

    if line == "## Paired incremental contribution":
        in_paired_section = True
        continue

    if in_paired_section and line.startswith("## "):
        break

    if not in_paired_section:
        continue

    if not line.startswith("|"):
        continue

    cells = [
        cell.strip()
        for cell in line.strip("|").split("|")
    ]

    # Ignore header and Markdown separator rows.
    if not cells or cells[0] == "Comparison":
        continue

    if cells[0].startswith("---"):
        continue

    if len(cells) != 6:
        continue

    comparison = cells[0]

    if "->" not in comparison:
        continue

    left, right = [
        part.strip()
        for part in comparison.split("->", 1)
    ]

    try:
        paired.append(
            {
                "from": left,
                "to": right,
                "both_miss": int(cells[1]),
                "new_catches": int(cells[2]),
                "regressions": int(cells[3]),
                "both_hit": int(cells[4]),
                "p_value": float(cells[5]),
            }
        )
    except ValueError as exc:
        raise RuntimeError(
            f"Failed to parse P11 paired-significance row: {raw_line}"
        ) from exc

p11["paired_transitions"] = paired

# Canonical P11 limitation rows.
p11["partial_exfiltration"] = [
    row
    for row in p11_categories
    if row.get("category") == "partial_exfiltration"
]

p11["semantic_reformulation"] = [
    row
    for row in p11_categories
    if row.get("category") == "semantic_reformulation"
]

ledger["evidence"]["P11"] = p11


# =====================================================================
# P12 — FROZEN SEMANTIC REVIEW EXTENSION
# =====================================================================

p12_summary_path = RESULTS / "p12" / "p12_summary.json"
p12_category_path = RESULTS / "p12" / "p12_category_summary.csv"
p12_posthoc_path = RESULTS / "p12" / "p12_posthoc_threshold_analysis.json"

p12_summary = read_json(p12_summary_path)
p12_categories = [
    normalize_row(r)
    for r in read_csv(p12_category_path)
]
p12_posthoc = read_json(p12_posthoc_path)

ledger["evidence"]["P12"] = {
    "role": (
        "POST-P11 semantic REVIEW extension; "
        "does not replace P11 hard-detection results"
    ),
    "sources": {
        "summary": source(p12_summary_path),
        "categories": source(p12_category_path),
        "posthoc_threshold_analysis": source(p12_posthoc_path),
    },
    "frozen_primary": p12_summary,
    "category_rows": p12_categories,
    "posthoc": {
        "status": p12_posthoc.get("status"),
        "primary_threshold_remains": p12_posthoc.get(
            "primary_threshold_remains"
        ),
        "primary_result": p12_posthoc.get("primary_result"),
        "best_balanced_accuracy_posthoc_only": p12_posthoc.get(
            "descriptive_best_balanced_accuracy"
        ),
        "best_f1_posthoc_only": p12_posthoc.get(
            "descriptive_best_f1"
        ),
        "fpr_budgets": p12_posthoc.get(
            "best_detection_under_fpr_budgets"
        ),
        "score_distribution": p12_posthoc.get(
            "score_distribution"
        ),
    },
}


# =====================================================================
# REAL MCP EXTERNAL VALIDATION
# =====================================================================

mcp_path = RESULTS / "mcp_external_validation.jsonl"

if mcp_path.exists():
    ledger["evidence"]["real_mcp_validation"] = {
        "role": "supplementary implementation/external-feasibility validation",
        "source": source(mcp_path),
        "records": read_jsonl(mcp_path),
    }


# =====================================================================
# REAL LOCALHOST NETWORK EGRESS
# =====================================================================

network_path = RESULTS / "network_egress_validation.jsonl"

if network_path.exists():
    ledger["evidence"]["network_egress_validation"] = {
        "role": "supplementary real localhost HTTP egress validation",
        "source": source(network_path),
        "records": read_jsonl(network_path),
    }


# =====================================================================
# PRE-CONTAINMENT LEAKAGE
# =====================================================================

leakage_path = RESULTS / "precontainment_leakage.jsonl"

if leakage_path.exists():
    leakage_rows = read_jsonl(leakage_path)

    exposures = [
        float(r["exposure"])
        for r in leakage_rows
        if r.get("contain")
        and r.get("exposure") is not None
    ]

    ledger["evidence"]["precontainment_leakage"] = {
        "role": (
            "quantifies leakage before accumulated evidence triggers containment"
        ),
        "source": source(leakage_path),
        "records": leakage_rows,
        "derived_from_artifact": {
            "contained_cases": len(exposures),
            "mean_exposure": (
                sum(exposures) / len(exposures)
                if exposures
                else None
            ),
            "worst_exposure": max(exposures) if exposures else None,
        },
    }


# =====================================================================
# PERSISTENCE
# =====================================================================

persist_latency_path = (
    RESULTS / "persistence_latency_comparison.json"
)

if persist_latency_path.exists():
    ledger["evidence"]["persistence_latency"] = {
        "role": "supplementary durable-state systems-cost experiment",
        "source": source(persist_latency_path),
        "data": read_json(persist_latency_path),
    }


persist_validation_path = (
    RESULTS / "persistence_v2_validation.json"
)

if persist_validation_path.exists():
    ledger["evidence"]["persistence_validation"] = {
        "role": "supplementary persistence/restart correctness validation",
        "source": source(persist_validation_path),
        "data": read_json(persist_validation_path),
    }


# =====================================================================
# CONCURRENCY / SCALING
# =====================================================================

concurrency_path = (
    RESULTS / "concurrency_scaling_repeated.jsonl"
)

if concurrency_path.exists():
    ledger["evidence"]["concurrency_scaling"] = {
        "role": "supplementary concurrency/scaling experiment",
        "source": source(concurrency_path),
        "records": read_jsonl(concurrency_path),
    }


transaction_path = (
    RESULTS / "transaction_scaling.jsonl"
)

if transaction_path.exists():
    ledger["evidence"]["transaction_scaling"] = {
        "role": "supplementary transaction-scaling experiment",
        "source": source(transaction_path),
        "records": read_jsonl(transaction_path),
    }


# =====================================================================
# P9 CONTRIBUTION ABLATION
# =====================================================================

p9_path = RESULTS / "p9_contribution_ablation.json"

if p9_path.exists():
    ledger["evidence"]["P9"] = {
        "role": "supporting contribution ablation",
        "source": source(p9_path),
        "data": read_json(p9_path),
    }


# =====================================================================
# WRITE JSON
# =====================================================================

OUT_JSON.parent.mkdir(
    parents=True,
    exist_ok=True,
)

OUT_JSON.write_text(
    json.dumps(
        ledger,
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)


# =====================================================================
# HUMAN-READABLE MARKDOWN
# =====================================================================

lines = [
    "# ProvProxy Canonical Evidence Ledger",
    "",
    "This ledger is generated from committed experimental artifacts.",
    "",
    "**Rule:** manuscript numbers should be traced to these files, "
    "not reconstructed from chat history.",
    "",
    "## Evidence hierarchy",
    "",
    "1. **P11** — primary frozen detector-blind core evaluation.",
    "2. **P12** — post-P11 semantic review extension.",
    "3. Real MCP / localhost egress — supplementary implementation evidence.",
    "4. Persistence / leakage / concurrency — supplementary systems evidence.",
    "5. P9 — supporting contribution ablation.",
    "",
    "## P11",
    "",
    f"Source: `{source(p11_summary_path)}`",
    "",
]

if p11_rows:
    headers = list(p11_rows[0].keys())

    lines.append(
        "| " + " | ".join(headers) + " |"
    )
    lines.append(
        "|" + "|".join(["---"] * len(headers)) + "|"
    )

    for row in p11_rows:
        lines.append(
            "| "
            + " | ".join(str(row.get(h, "")) for h in headers)
            + " |"
        )

lines += [
    "",
    "### P11 paired transitions",
    "",
]

if paired:
    lines += [
        "| Transition | New catches | Regressions | p-value |",
        "|---|---:|---:|---:|",
    ]

    for row in paired:
        lines.append(
            f"| {row['from']}→{row['to']} | "
            f"{row['new_catches']} | "
            f"{row['regressions']} | "
            f"{row['p_value']:.12g} |"
        )
else:
    lines.append(
        "_Automatic transition extraction failed; inspect "
        f"`{source(p11_sig_path)}` manually._"
    )

lines += [
    "",
    "### P11 locked limitations",
    "",
    "Partial exfiltration rows are copied from "
    f"`{source(p11_category_path)}`.",
    "",
]

for row in p11["partial_exfiltration"]:
    lines.append(f"- `{row}`")

lines += [
    "",
    "Semantic reformulation rows:",
    "",
]

for row in p11["semantic_reformulation"]:
    lines.append(f"- `{row}`")


# P12 summary
p12 = ledger["evidence"]["P12"]["frozen_primary"]

lines += [
    "",
    "## P12 semantic review extension",
    "",
    f"Source: `{source(p12_summary_path)}`",
    "",
    f"- Malicious cases: **{p12['malicious']['n']}**",
    f"- Core hard detected: "
    f"**{p12['malicious']['core_hard_detected']}**",
    f"- Semantic reviewed malicious: "
    f"**{p12['malicious']['semantic_reviewed']}**",
    f"- Incremental semantic recovery: "
    f"**{p12['malicious']['semantic_incremental']}**",
    f"- Combined signal rate: "
    f"**{p12['malicious']['combined_signal_detection_rate']:.6f}**",
    f"- Benign semantic reviews: "
    f"**{p12['benign']['semantic_reviewed']}/{p12['benign']['n']}**",
    f"- Benign semantic review FPR: "
    f"**{p12['benign']['semantic_review_fpr']:.6f}**",
    f"- Semantic precision: "
    f"**{p12['semantic_precision']:.6f}**",
    f"- Semantic p50 latency: "
    f"**{p12['semantic_latency_ms']['p50']:.3f} ms**",
    f"- Semantic p95 latency: "
    f"**{p12['semantic_latency_ms']['p95']:.3f} ms**",
    "",
    "P12 semantic review is **not** hard provenance detection.",
    "",
    "### P12 post-hoc operating-point result",
    "",
]

posthoc = ledger["evidence"]["P12"]["posthoc"]

lines.append(
    f"- Frozen threshold remains: **{posthoc['primary_threshold_remains']}**"
)

best = posthoc["best_balanced_accuracy_posthoc_only"]

if best:
    lines += [
        f"- Post-hoc best balanced-accuracy threshold: "
        f"**{best['threshold']}**",
        f"- Detection there: "
        f"**{best['tpr_detection_rate']:.3f}**",
        f"- FPR there: **{best['fpr']:.3f}**",
        "",
        "**These post-hoc values must not replace the frozen 0.60 result.**",
    ]


# Sources inventory.
lines += [
    "",
    "## Supplementary evidence sources",
    "",
]

for key, value in ledger["evidence"].items():
    if key in {"P11", "P12"}:
        continue

    src = value.get("source")

    if src:
        lines.append(
            f"- **{key}** — `{src}`"
        )

OUT_MD.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)

print("=" * 100)
print("PROVPROXY CANONICAL EVIDENCE LEDGER")
print("=" * 100)
print(f"[WRITE] {OUT_JSON}")
print(f"[WRITE] {OUT_MD}")
print()
print(f"P11 summary rows       : {len(p11_rows)}")
print(f"P11 category rows      : {len(p11_categories)}")
print(f"P11 paired transitions : {len(paired)}")
print(
    "P12 frozen primary     : "
    f"{p12_summary['malicious']['combined_detected']}/"
    f"{p12_summary['malicious']['n']} combined semantic signal"
)
print()
print("[PASS] No detector executed.")
print("[PASS] No corpus modified.")
print("[PASS] Ledger generated only from existing result artifacts.")
print("=" * 100)
