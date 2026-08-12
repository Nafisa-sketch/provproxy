"""Week 4 Evaluation Harness (Section 7).

Automated runner that replays the M1-M4 / B1-B5 benchmark scenarios
(benchmarks/fixtures.py) across each ablation configuration, producing:

  - Per-run JSON records (one file per tier) — the raw data.
  - An aggregate CSV summary with detection rate (DR), false-positive rate
    (FPR), and p50/p95/p99 latency with bootstrap confidence intervals.

Per Section 7: results are reported with bootstrap CIs, not single-run
point estimates, since process/scheduling jitter is non-trivial at the
sub-5ms scale this project targets. Harness + raw per-run JSON are meant
to be committed alongside the code so these numbers are regeneratable.
"""
from __future__ import annotations

import json
import random
import re
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from provproxy.approx import ApproxMatcher
from provproxy.config import AblationTier, ApproxMatchingConfig, DecodeLimits, PolicyFile
from provproxy.decode import Decoder
from provproxy.session import Session
from provproxy import pipeline

from benchmarks.fixtures import FIXTURES, ScenarioFixture


@dataclass
class RunRecord:
    tier: str
    scenario_id: str
    category: str
    is_malicious: bool
    matched: bool
    matched_via: Optional[str]
    destination_allowed: bool
    enforcement_blocked: bool
    latency_seconds: float


def _make_policy(tier: AblationTier) -> PolicyFile:
    return PolicyFile(
        version="harness-1.0",
        active_tier=tier,
        server_bindings=[],
        approx_matching=ApproxMatchingConfig(),
        decode_limits=DecodeLimits(),
    )


def run_configuration(
    tier: AblationTier, fixtures: list[ScenarioFixture] = FIXTURES, repeats: int = 10
) -> list[RunRecord]:
    """Replay every fixture `repeats` times under one tier configuration.
    Repeats exist purely to characterize latency distribution — the
    matcher itself is deterministic given the same input, so detection
    outcome doesn't vary run-to-run for a fixed fixture/tier pair.

    Each fixture is one or more sequential `calls` (M4 fixtures are a
    short multi-call sequence against the same destination, so V4's
    cross-call window has something to accumulate; everything else is a
    single call). A fresh Session is created per repeat, so state never
    leaks between repeats — but state DOES persist across the calls
    within one repeat of a multi-call fixture, exactly like one
    continuous attacker session."""
    policy = _make_policy(tier)
    records: list[RunRecord] = []

    for fx in fixtures:
        for _ in range(repeats):
            session = Session(session_id=f"harness-{fx.id}", policy=policy, ttl_seconds=3600)
            if fx.sensitive_source:
                session.register_sensitive_fragment(f"frag-{fx.id}", fx.sensitive_source)

            for call in fx.calls:
                start = time.perf_counter()
                result = pipeline.evaluate(
                    policy, session, call.payload, policy.decode_limits,
                    destination_allowed=fx.destination_allowed,
                    destination_domain=call.destination_domain,
                )
                elapsed = time.perf_counter() - start
                records.append(
                    RunRecord(
                        tier=tier.value,
                        scenario_id=fx.id,
                        category=fx.category,
                        is_malicious=fx.is_malicious,
                        matched=result.matched,
                        matched_via=result.matched_via,
                        destination_allowed=fx.destination_allowed,
                        enforcement_blocked=result.enforcement_blocked,
                        latency_seconds=elapsed,
                    )
                )
    return records


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * pct
    f, c = int(k), min(int(k) + 1, len(sorted_values) - 1)
    if f == c:
        return sorted_values[f]
    return sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f)


def _bootstrap_ci(
    values: list[float], pct: float, iterations: int = 1000, ci: float = 0.95, seed: int = 42
) -> tuple[float, float, float]:
    """(point_estimate, ci_low, ci_high) for the given percentile, via
    resampling with a fixed seed — reproducible per Section 7."""
    if not values:
        return (0.0, 0.0, 0.0)
    point = _percentile(sorted(values), pct)
    rng = random.Random(seed)
    n = len(values)
    estimates = sorted(
        _percentile(sorted(values[rng.randrange(n)] for _ in range(n)), pct) for _ in range(iterations)
    )
    lo_idx = int((1 - ci) / 2 * iterations)
    hi_idx = int((1 + ci) / 2 * iterations) - 1
    return (point, estimates[lo_idx], estimates[hi_idx])


def category_detection_rates(records: list[RunRecord]) -> dict[str, float]:
    """Per-category detection rate (M1, M2, M3, M4 computed separately) —
    this is what a paper's Ablation Progress Table actually needs, not
    just one pooled DR number across all malicious scenarios."""
    total: dict[str, set[str]] = {}
    caught: dict[str, set[str]] = {}
    for r in records:
        if not r.is_malicious:
            continue
        total.setdefault(r.category, set()).add(r.scenario_id)
        if r.matched:
            caught.setdefault(r.category, set()).add(r.scenario_id)
    return {cat: len(caught.get(cat, set())) / len(ids) for cat, ids in total.items()}


def category_false_positive_rates(records: list[RunRecord]) -> dict[str, float]:
    """Same, but per benign category (B1-B5) and using enforcement_blocked
    — what actually gets blocked, which is the number that matters for
    user-facing FPR (see the two-FPR-columns note in README)."""
    total: dict[str, set[str]] = {}
    blocked: dict[str, set[str]] = {}
    for r in records:
        if r.is_malicious:
            continue
        total.setdefault(r.category, set()).add(r.scenario_id)
        if r.enforcement_blocked:
            blocked.setdefault(r.category, set()).add(r.scenario_id)
    return {cat: len(blocked.get(cat, set())) / len(ids) for cat, ids in total.items()}


@dataclass
class TierSummary:
    tier: str
    detection_rate: float
    false_positive_rate: float  # detection-level: did the matcher flag it at all (ignores destination)
    enforcement_false_positive_rate: float  # what actually gets blocked, after the V0 destination override
    malicious_total: int
    malicious_caught: int
    benign_total: int
    benign_flagged: int
    benign_actually_blocked: int
    p50_ms: float
    p50_ci_low_ms: float
    p50_ci_high_ms: float
    p95_ms: float
    p95_ci_low_ms: float
    p95_ci_high_ms: float
    p99_ms: float
    p99_ci_low_ms: float
    p99_ci_high_ms: float


def summarize(records: list[RunRecord]) -> TierSummary:
    tier = records[0].tier
    malicious = [r for r in records if r.is_malicious]
    benign = [r for r in records if not r.is_malicious]

    # DR/FPR are computed per-scenario (any repeat matching counts the
    # scenario as caught/flagged), not per-repeat — repeats exist purely
    # to characterize latency, not detection variance.
    malicious_scenarios = {r.scenario_id for r in malicious}
    benign_scenarios = {r.scenario_id for r in benign}
    malicious_caught = {r.scenario_id for r in malicious if r.matched}
    benign_flagged = {r.scenario_id for r in benign if r.matched}
    benign_actually_blocked = {r.scenario_id for r in benign if r.enforcement_blocked}

    latencies_ms = [r.latency_seconds * 1000 for r in records]
    p50, p50_lo, p50_hi = _bootstrap_ci(latencies_ms, 0.50)
    p95, p95_lo, p95_hi = _bootstrap_ci(latencies_ms, 0.95)
    p99, p99_lo, p99_hi = _bootstrap_ci(latencies_ms, 0.99)

    return TierSummary(
        tier=tier,
        detection_rate=len(malicious_caught) / len(malicious_scenarios) if malicious_scenarios else 0.0,
        false_positive_rate=len(benign_flagged) / len(benign_scenarios) if benign_scenarios else 0.0,
        enforcement_false_positive_rate=(
            len(benign_actually_blocked) / len(benign_scenarios) if benign_scenarios else 0.0
        ),
        malicious_total=len(malicious_scenarios),
        malicious_caught=len(malicious_caught),
        benign_total=len(benign_scenarios),
        benign_flagged=len(benign_flagged),
        benign_actually_blocked=len(benign_actually_blocked),
        p50_ms=p50, p50_ci_low_ms=p50_lo, p50_ci_high_ms=p50_hi,
        p95_ms=p95, p95_ci_low_ms=p95_lo, p95_ci_high_ms=p95_hi,
        p99_ms=p99, p99_ci_low_ms=p99_lo, p99_ci_high_ms=p99_hi,
    )


def run_all(
    tiers: Optional[list[AblationTier]] = None, repeats: int = 10, output_dir: Optional[Path] = None
) -> list[TierSummary]:
    tiers = tiers or [AblationTier.V0, AblationTier.V1, AblationTier.V2, AblationTier.V3, AblationTier.V4]
    output_dir = output_dir or (Path(__file__).parent / "results")
    output_dir.mkdir(parents=True, exist_ok=True)

    summaries = []
    category_rows = []
    for tier in tiers:
        records = run_configuration(tier, repeats=repeats)
        (output_dir / f"{tier.value}_runs.json").write_text(
            json.dumps([asdict(r) for r in records], indent=2)
        )
        summaries.append(summarize(records))

        dr_by_cat = category_detection_rates(records)
        fpr_by_cat = category_false_positive_rates(records)
        for cat in sorted(set(dr_by_cat) | set(fpr_by_cat)):
            category_rows.append(
                {
                    "tier": tier.value,
                    "category": cat,
                    "detection_rate": dr_by_cat.get(cat),
                    "enforcement_fpr": fpr_by_cat.get(cat),
                }
            )

    csv_path = output_dir / "summary.csv"
    fields = list(asdict(summaries[0]).keys())
    with open(csv_path, "w") as f:
        f.write(",".join(fields) + "\n")
        for s in summaries:
            f.write(",".join(str(v) for v in asdict(s).values()) + "\n")

    category_csv_path = output_dir / "category_breakdown.csv"
    with open(category_csv_path, "w") as f:
        f.write("tier,category,detection_rate,enforcement_fpr\n")
        for row in category_rows:
            f.write(f"{row['tier']},{row['category']},{row['detection_rate']},{row['enforcement_fpr']}\n")

    return summaries


# =====================================================================
# Baseline comparators — Section 2 of the evaluation design: how does
# ProvProxy's provenance-aware approach compare to (a) a stateless
# pattern matcher and (b) a transformation-aware but session-less DLP
# gateway? Neither baseline tracks WHICH secret is actually sensitive —
# they just look for text that's *shaped* like a credential, which is
# exactly the gap ProvProxy's provenance tracking is meant to close
# (see B4/B5's results below for where that gap shows up concretely).
# =====================================================================

_GENERIC_SECRET_REGEX = re.compile(r"AKIA[A-Z0-9]{12,}")
_DEFAULT_DECODE_LIMITS = DecodeLimits()


def baseline_stateless_scan(payload: str) -> bool:
    """Stateless pattern matcher: regex for "anything shaped like an AWS
    key", no session state, no idea which secret (if any) is real."""
    return bool(_GENERIC_SECRET_REGEX.search(payload))


def baseline_dlp_scan(payload: str) -> bool:
    """Transformation-aware DLP gateway: same regex, but also tries
    decoding Base64/Hex/URL/JSON-escape candidates first (like V2) —
    still no session state, no cross-call memory, no concept of "this
    exact secret was read earlier in this session"."""
    if baseline_stateless_scan(payload):
        return True
    decoder = Decoder(_DEFAULT_DECODE_LIMITS)
    return any(_GENERIC_SECRET_REGEX.search(c.text) for c in decoder.expand(payload))


def run_baseline(name: str, scan_fn, fixtures: list[ScenarioFixture] = FIXTURES) -> dict:
    """Run a baseline scan function (no Session/pipeline involved) over
    every fixture, computing the same DR/FPR ProvProxy's tiers report,
    for direct comparison."""
    malicious_total: set[str] = set()
    malicious_caught: set[str] = set()
    benign_total: set[str] = set()
    benign_flagged: set[str] = set()

    for fx in fixtures:
        matched_any = any(scan_fn(call.payload) for call in fx.calls)
        if fx.is_malicious:
            malicious_total.add(fx.id)
            if matched_any:
                malicious_caught.add(fx.id)
        else:
            benign_total.add(fx.id)
            if matched_any:
                benign_flagged.add(fx.id)

    return {
        "name": name,
        "detection_rate": len(malicious_caught) / len(malicious_total) if malicious_total else 0.0,
        "false_positive_rate": len(benign_flagged) / len(benign_total) if benign_total else 0.0,
    }


# =====================================================================
# Memory measurement — Section 2's requested metric alongside DR/FPR/
# latency. Uses tracemalloc rather than an external profiler to keep
# this dependency-free; peak allocation during a full tier run is the
# number that matters for "how much memory does the proxy actually use."
# =====================================================================

def measure_memory(tier: AblationTier, fixtures: list[ScenarioFixture] = FIXTURES) -> dict:
    tracemalloc.start()
    run_configuration(tier, fixtures=fixtures, repeats=1)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"tier": tier.value, "current_bytes": current, "peak_bytes": peak, "peak_kb": peak / 1024}


# =====================================================================
# Failure analysis — Section 2's explicit requirement to document WHERE
# this approach fails, not just report an aggregate success number.
# Chunk size is the single parameter that most directly controls M3/M4
# difficulty (smaller chunks -> weaker per-chunk n-gram signal), so
# breaking detection down by it is the most direct evidence of where the
# coverage-based approach's limits actually are.
# =====================================================================

def chunk_size_detection_breakdown(
    tier: AblationTier, category: str, fixtures: list[ScenarioFixture] = FIXTURES
) -> dict[int, tuple[int, int]]:
    """Returns {chunk_size: (caught, total)} for the given category (M3
    or M4) — concrete evidence of exactly where detection starts
    breaking down as chunks get smaller, rather than one pooled number
    that hides this."""
    relevant = [fx for fx in fixtures if fx.category == category and fx.chunk_size is not None]
    policy = _make_policy(tier)
    by_size: dict[int, list[bool]] = {}

    for fx in relevant:
        session = Session(session_id=f"cs-{fx.id}", policy=policy, ttl_seconds=3600)
        if fx.sensitive_source:
            session.register_sensitive_fragment(f"frag-{fx.id}", fx.sensitive_source)
        matched_any = False
        for call in fx.calls:
            result = pipeline.evaluate(
                policy, session, call.payload, policy.decode_limits,
                destination_allowed=fx.destination_allowed, destination_domain=call.destination_domain,
            )
            if result.matched:
                matched_any = True
        by_size.setdefault(fx.chunk_size, []).append(matched_any)

    return {size: (sum(vals), len(vals)) for size, vals in sorted(by_size.items())}


# =====================================================================
# Threshold sweep — Section 3: exercises ApproxMatcher.scan_sweep()
# directly to produce the DR/FPR trade-off curve across coverage_threshold
# operating points (the classic precision/recall-style curve for a
# paper's evaluation section).
# =====================================================================

def threshold_sweep(
    thresholds: Optional[list[float]] = None, fixtures: list[ScenarioFixture] = FIXTURES, ngram_size: int = 4
) -> list[dict]:
    """Sweep coverage_threshold and report DR/FPR at each operating
    point, split into two FPR series that mean genuinely different
    things:

      - `false_positive_rate`: every benign scenario flagged at the
        DETECTION layer, B5 included. This is a security *signal*, not
        a mistake — B5's payload genuinely contains the tracked secret.
        No threshold can or should suppress it, because doing so would
        mean failing to detect a real copy of the secret; B5 is only
        "safe" because the destination is separately allow-listed (see
        `destination.py` / the enforcement-level FPR reported elsewhere
        in this file, which correctly stays near 0%).
      - `noise_false_positive_rate`: benign scenarios EXCLUDING B5 —
        i.e. cases where any match would be genuine coincidental
        n-gram overlap with no real relationship to the tracked secret
        (see B4's "sibling/rotated credential" variants in
        fixtures.py). THIS is the series a coverage threshold should
        suppress as it gets stricter, and it does: it declines as
        `false_positive_rate` does but reaches exactly 0% by the point
        `false_positive_rate` plateaus at B5's fixed contribution.
    """
    thresholds = thresholds or [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    malicious_total: dict[float, set[str]] = {t: set() for t in thresholds}
    malicious_caught: dict[float, set[str]] = {t: set() for t in thresholds}
    benign_total: dict[float, set[str]] = {t: set() for t in thresholds}
    benign_flagged: dict[float, set[str]] = {t: set() for t in thresholds}
    noise_total: dict[float, set[str]] = {t: set() for t in thresholds}
    noise_flagged: dict[float, set[str]] = {t: set() for t in thresholds}

    for fx in fixtures:
        for t in thresholds:
            (malicious_total if fx.is_malicious else benign_total)[t].add(fx.id)
            if not fx.is_malicious and fx.category != "B5":
                noise_total[t].add(fx.id)

        if not fx.sensitive_source:
            continue  # nothing registered to test scan_sweep against — correctly contributes 0 matches

        matcher = ApproxMatcher(ngram_size=ngram_size, threshold=0.0)  # per-call threshold comes from scan_sweep itself
        matcher.register_source(f"frag-{fx.id}", fx.sensitive_source)

        matched_at: dict[float, bool] = {t: False for t in thresholds}
        for call in fx.calls:
            for t, count in matcher.scan_sweep(call.payload, thresholds):
                if count > 0:
                    matched_at[t] = True

        for t in thresholds:
            if matched_at[t]:
                (malicious_caught if fx.is_malicious else benign_flagged)[t].add(fx.id)
                if not fx.is_malicious and fx.category != "B5":
                    noise_flagged[t].add(fx.id)

    rows = []
    for t in thresholds:
        dr = len(malicious_caught[t]) / len(malicious_total[t]) if malicious_total[t] else 0.0
        fpr = len(benign_flagged[t]) / len(benign_total[t]) if benign_total[t] else 0.0
        noise_fpr = len(noise_flagged[t]) / len(noise_total[t]) if noise_total[t] else 0.0
        rows.append({
            "threshold": t, "detection_rate": dr,
            "false_positive_rate": fpr, "noise_false_positive_rate": noise_fpr,
        })
    return rows


# =====================================================================
# LaTeX/Markdown table export — Section 3: publication-ready output that
# plugs directly into a paper's Evaluation section.
# =====================================================================

def _latex_escape(s: str) -> str:
    return s.replace("_", "\\_").replace("%", "\\%").replace("&", "\\&")


def to_latex_table(rows: list[dict], columns: list[str], caption: str, label: str) -> str:
    col_spec = "l" + "r" * (len(columns) - 1)
    lines = [
        "\\begin{table}[t]",
        "\\centering",
        f"\\caption{{{caption}}}",
        f"\\label{{{label}}}",
        f"\\begin{{tabular}}{{{col_spec}}}",
        "\\toprule",
        " & ".join(_latex_escape(c) for c in columns) + " \\\\",
        "\\midrule",
    ]
    for row in rows:
        cells = []
        for col in columns:
            val = row.get(col, "")
            if isinstance(val, float):
                cells.append(f"{val:.3f}")
            elif val is None:
                cells.append("--")
            else:
                cells.append(_latex_escape(str(val)))
        lines.append(" & ".join(cells) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    return "\n".join(lines)


def to_markdown_table(rows: list[dict], columns: list[str]) -> str:
    lines = ["| " + " | ".join(columns) + " |", "|" + "|".join(["---"] * len(columns)) + "|"]
    for row in rows:
        cells = []
        for col in columns:
            val = row.get(col, "")
            cells.append(f"{val:.3f}" if isinstance(val, float) else str(val))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)
