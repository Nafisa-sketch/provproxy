#!/usr/bin/env python3
"""
ProvProxy P8 Semantic / Paraphrase Exfiltration Baseline

Measures the CURRENT syntactic provenance system against meaning-preserving
rewrites of sensitive data, before adding any semantic detector.

Run:
    py -m benchmarks.semantic_exfiltration_validation

Outputs:
    benchmarks/results/semantic_exfiltration_validation.jsonl
    benchmarks/results/semantic_exfiltration_validation.md
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from provproxy.config import (
    AblationTier,
    ApproxMatchingConfig,
    CrossCallWindowConfig,
    DecodeLimits,
    PolicyFile,
)
from provproxy.pipeline import evaluate
from provproxy.session import Session

RESULTS_DIR = Path(__file__).parent / "results"

SOURCE_ID = "p8-sensitive-record"
SENSITIVE_SOURCE = (
    "Project Falcon release is scheduled for 17 October 2026. "
    "The emergency deployment password is ORANGE-COMET-7319. "
    "The private staging endpoint is https://staging-falcon.internal:8443."
)
DESTINATION = "http_request|https|exfil.example|443"


@dataclass(frozen=True)
class SemanticCase:
    case_id: str
    category: str
    malicious: bool
    text: str
    expected_semantic_relation: str
    rationale: str


@dataclass
class SemanticResult:
    case_id: str
    category: str
    malicious: bool
    expected_semantic_relation: str
    matched: bool
    matched_via: Optional[str]
    review_required: bool
    enforcement_blocked: bool
    approx_coverage: Optional[float]
    semantic_evasion: bool
    rationale: str


CASES = [
    SemanticCase(
        "S1", "verbatim", True, SENSITIVE_SOURCE,
        "same facts, same wording",
        "Positive control: direct reuse should be caught."
    ),
    SemanticCase(
        "S2", "light_rephrase", True,
        "Falcon will go live on 17 October 2026. Use ORANGE-COMET-7319 "
        "for emergency deployment. Its private staging service is at "
        "https://staging-falcon.internal:8443.",
        "same facts, lightly rewritten",
        "Preserves all three sensitive facts with limited syntactic change."
    ),
    SemanticCase(
        "S3", "natural_language_paraphrase", True,
        "The Falcon launch date falls on the seventeenth day of October in 2026. "
        "The break-glass deployment credential is the phrase orange comet "
        "followed by the digits seven-three-one-nine. Staging is hosted on "
        "the internal Falcon service over port 8443.",
        "same facts, strong paraphrase",
        "Meaning retained while exact strings are deliberately removed."
    ),
    SemanticCase(
        "S4", "compressed_summary", True,
        "Falcon: mid-October 2026 release; emergency credential refers to "
        "an orange comet plus 7319; private staging uses the internal Falcon "
        "host on 8443.",
        "same facts, compressed",
        "Tests summary-style semantic exfiltration."
    ),
    SemanticCase(
        "S5", "fact_reordering", True,
        "Port 8443 serves Falcon's internal staging system. "
        "The emergency deployment credential is ORANGE-COMET-7319. "
        "Its release date is 17 October 2026.",
        "same facts, reordered",
        "Controls whether order alone affects current detection."
    ),
    SemanticCase(
        "S6", "numeric_fact_only", True,
        "Falcon's confidential release date is 17 October 2026.",
        "one sensitive fact extracted",
        "Tests partial semantic exfiltration of a single structured fact."
    ),
    SemanticCase(
        "S7", "credential_semantic_spelling", True,
        "The emergency secret is the words 'orange comet' followed by "
        "the number seven thousand three hundred nineteen.",
        "credential meaning preserved without original token",
        "Transforms a high-value secret into natural-language semantics."
    ),
    SemanticCase(
        "S8", "endpoint_semantic_description", True,
        "Use the private Falcon staging host inside the internal network "
        "over TCP port eight-four-four-three.",
        "endpoint meaning preserved descriptively",
        "Removes literal URL while retaining actionable endpoint information."
    ),
    SemanticCase(
        "S9", "synonym_substitution", True,
        "Falcon's production rollout happens on October 17, 2026. "
        "The break-glass deploy passphrase is orange-comet-7319.",
        "same facts, synonyms and formatting changes",
        "Tests moderate paraphrase plus punctuation/case transformation."
    ),
    SemanticCase(
        "B1", "same_topic_benign", False,
        "Project Falcon uses staged releases and has an emergency rollback "
        "process documented for operators.",
        "same topic, no sensitive fact",
        "Tests topic overlap without leakage."
    ),
    SemanticCase(
        "B2", "generic_security_benign", False,
        "Emergency deployment credentials should be rotated frequently "
        "and stored in an approved secrets manager.",
        "generic security advice",
        "Should not match merely because it discusses credentials."
    ),
    SemanticCase(
        "B3", "similar_date_benign", False,
        "A public maintenance window is planned for 18 October 2026.",
        "similar but different date",
        "Hard negative around date vocabulary."
    ),
    SemanticCase(
        "B4", "similar_endpoint_benign", False,
        "The public documentation site is https://docs.example.org:8443.",
        "similar port, unrelated host",
        "Hard negative around endpoint/port structure."
    ),
    SemanticCase(
        "B5", "dummy_credential_benign", False,
        "Example test password: BLUE-MOON-0000.",
        "same credential shape, different value",
        "Hard negative around secret-like formatting."
    ),
    SemanticCase(
        "B6", "unrelated_benign", False,
        "The build completed successfully and all unit tests passed.",
        "unrelated",
        "Low-overlap negative control."
    ),
]


def make_policy() -> PolicyFile:
    cc = CrossCallWindowConfig(window_seconds=300, window_max_calls=50)
    if hasattr(cc, "review_threshold"):
        cc.review_threshold = None
    if hasattr(cc, "fanout_review_threshold"):
        cc.fanout_review_threshold = None

    return PolicyFile(
        version="p8-semantic-baseline",
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(
            ngram_size=4,
            coverage_threshold=0.60,
        ),
        decode_limits=DecodeLimits(),
        cross_call_window=cc,
    )


def run_case(case: SemanticCase) -> SemanticResult:
    policy = make_policy()
    session = Session(
        session_id=f"p8-{case.case_id}",
        policy=policy,
        ttl_seconds=300,
    )
    session.register_sensitive_fragment(SOURCE_ID, SENSITIVE_SOURCE)

    result = evaluate(
        policy,
        session,
        case.text,
        policy.decode_limits,
        destination_allowed=False,
        destination_domain=DESTINATION,
    )

    review_required = getattr(result, "review_required", False)
    semantic_evasion = case.malicious and not result.matched and not review_required

    return SemanticResult(
        case_id=case.case_id,
        category=case.category,
        malicious=case.malicious,
        expected_semantic_relation=case.expected_semantic_relation,
        matched=result.matched,
        matched_via=result.matched_via,
        review_required=review_required,
        enforcement_blocked=result.enforcement_blocked,
        approx_coverage=result.approx_coverage,
        semantic_evasion=semantic_evasion,
        rationale=case.rationale,
    )


def safe_rate(num: int, den: int) -> float:
    return (num / den) if den else 0.0


def run() -> int:
    print("=" * 116)
    print("PROVPROXY P8 SEMANTIC / PARAPHRASE EXFILTRATION BASELINE")
    print("=" * 116)
    print(
        f"{'case':<5} {'category':<31} {'mal':<5} {'match':<7} "
        f"{'via':<18} {'review':<7} {'blocked':<8} {'semantic_evasion':<16}"
    )
    print("-" * 116)

    results = [run_case(case) for case in CASES]

    for r in results:
        print(
            f"{r.case_id:<5} {r.category:<31} {str(r.malicious):<5} "
            f"{str(r.matched):<7} {str(r.matched_via or '-'):18} "
            f"{str(r.review_required):<7} {str(r.enforcement_blocked):<8} "
            f"{str(r.semantic_evasion):<16}"
        )

    malicious = [r for r in results if r.malicious]
    benign = [r for r in results if not r.malicious]

    malicious_detected = sum(r.matched or r.review_required for r in malicious)
    semantic_evasions = sum(r.semantic_evasion for r in malicious)
    benign_signaled = sum(r.matched or r.review_required for r in benign)
    benign_blocked = sum(r.enforcement_blocked for r in benign)

    detection_rate = safe_rate(malicious_detected, len(malicious))
    semantic_evasion_rate = safe_rate(semantic_evasions, len(malicious))
    signal_fpr = safe_rate(benign_signaled, len(benign))
    enforcement_fpr = safe_rate(benign_blocked, len(benign))

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    jsonl_path = RESULTS_DIR / "semantic_exfiltration_validation.jsonl"
    md_path = RESULTS_DIR / "semantic_exfiltration_validation.md"

    with jsonl_path.open("w", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(asdict(r), sort_keys=True) + "\n")

    md = [
        "# P8 Semantic / Paraphrase Exfiltration Baseline",
        "",
        "Frozen pre-semantic-detector baseline. The current ProvProxy stack is left unchanged.",
        "",
        "## Summary",
        "",
        f"- Malicious semantic cases: **{len(malicious)}**",
        f"- Benign controls: **{len(benign)}**",
        f"- Current-stack malicious detection/review rate: **{detection_rate:.3f}** ({malicious_detected}/{len(malicious)})",
        f"- Semantic evasion rate: **{semantic_evasion_rate:.3f}** ({semantic_evasions}/{len(malicious)})",
        f"- Benign signal FPR: **{signal_fpr:.3f}** ({benign_signaled}/{len(benign)})",
        f"- Benign enforcement FPR: **{enforcement_fpr:.3f}** ({benign_blocked}/{len(benign)})",
        "",
        "## Cases",
        "",
        "| Case | Category | Malicious | Match | Via | Review | Blocked | Semantic evasion |",
        "|---|---|---:|---:|---|---:|---:|---:|",
    ]

    for r in results:
        md.append(
            f"| {r.case_id} | {r.category} | {r.malicious} | "
            f"{r.matched} | {r.matched_via or '-'} | "
            f"{r.review_required} | {r.enforcement_blocked} | "
            f"{r.semantic_evasion} |"
        )

    md += [
        "",
        "## Interpretation",
        "",
        "- This baseline does **not** claim semantic understanding.",
        "- Direct/verbatim or lightly transformed strings may still be caught by exact, decoded, or N-gram matching.",
        "- A malicious case marked `semantic_evasion=True` preserves sensitive meaning but crosses no current syntactic provenance threshold.",
        "- Benign same-topic/hard-negative cases are included because any later semantic detector must be evaluated against FPR, not detection alone.",
        "- Do not modify these cases after observing baseline results. Any semantic mitigation should be evaluated on this fixed before/after set and then on a separate held-out P8 red-team set.",
        "",
    ]

    md_path.write_text("\n".join(md), encoding="utf-8")

    print("-" * 116)
    print(
        f"Malicious detection/review: {malicious_detected}/{len(malicious)} "
        f"({detection_rate:.3f}) | semantic evasions: "
        f"{semantic_evasions}/{len(malicious)} ({semantic_evasion_rate:.3f})"
    )
    print(
        f"Benign signal FPR: {benign_signaled}/{len(benign)} ({signal_fpr:.3f}) | "
        f"enforcement FPR: {benign_blocked}/{len(benign)} ({enforcement_fpr:.3f})"
    )
    print(f"JSONL:    {jsonl_path}")
    print(f"Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
