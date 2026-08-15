#!/usr/bin/env python3
"""
ProvProxy P7 Destination Identity Evasion Baseline
==================================================

Goal
----
Freeze and measure destination-identity behavior BEFORE changing mitigation.

This benchmark asks two separate questions:

1. Identity canonicalization:
   Do URL variants that represent the same endpoint collapse to the same
   destination key?

2. Stateful exfiltration:
   If secret fragments are rotated across those URL variants, does strict V4
   still accumulate them as one destination, or can representation changes
   reset the per-destination window?

This is a BASELINE / weakness-discovery benchmark. A "FAIL" is useful evidence
and must not be hidden or silently reclassified.

Run from the project root:

    py -m benchmarks.destination_identity_validation

Outputs:
    benchmarks/results/destination_identity_validation.jsonl
    benchmarks/results/destination_identity_validation.md

No Internet traffic is generated. All secrets and destinations are synthetic.
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
from provproxy.destination import primary_domain
from provproxy.pipeline import evaluate
from provproxy.session import Session


RESULTS_DIR = Path(__file__).parent / "results"

SECRET = "P7_DESTINATION_IDENTITY_SECRET_2026"
# All fragments are deliberately short enough that the experiment is about
# cross-call accumulation rather than one-shot exact detection.
FRAGMENTS = [
    "P7_D",
    "ESTI",
    "NATI",
    "ON_I",
    "DENT",
    "ITY_",
    "SECR",
    "ET_2",
    "026",
]


@dataclass(frozen=True)
class IdentityCase:
    case_id: str
    category: str
    url_a: str
    url_b: str
    expected_relation: str  # "same", "different", or "boundary"
    rationale: str


@dataclass
class IdentityResult:
    case_id: str
    category: str
    url_a: str
    url_b: str
    key_a: Optional[str]
    key_b: Optional[str]
    identity_equal: bool
    expected_relation: str
    canonicalization_pass: Optional[bool]
    strict_v4_detected: bool
    strict_v4_review: bool
    strict_v4_containment_call: Optional[int]
    fanout_detected: bool
    fanout_review: bool
    fanout_containment_call: Optional[int]
    representation_evasion_observed: bool
    notes: str


CASES = [
    IdentityCase(
        "D1",
        "host_case",
        "https://Example.COM/upload",
        "https://example.com/upload",
        "same",
        "DNS hostnames are case-insensitive; normalized host identity should collapse case.",
    ),
    IdentityCase(
        "D2",
        "trailing_dot",
        "https://example.com/upload",
        "https://example.com./upload",
        "same",
        "A trailing DNS root dot normally denotes the same fully-qualified hostname.",
    ),
    IdentityCase(
        "D3",
        "default_https_port",
        "https://example.com/upload",
        "https://example.com:443/upload",
        "same",
        "Omitted HTTPS port and explicit :443 represent the same default endpoint.",
    ),
    IdentityCase(
        "D4",
        "default_http_port",
        "http://example.com/upload",
        "http://example.com:80/upload",
        "same",
        "Omitted HTTP port and explicit :80 represent the same default endpoint.",
    ),
    IdentityCase(
        "D5",
        "path_variation",
        "https://example.com/a",
        "https://example.com/b/deeper/path",
        "same",
        "The project's destination model is endpoint-oriented; path changes should not reset host-level accumulation.",
    ),
    IdentityCase(
        "D6",
        "query_fragment_variation",
        "https://example.com/upload?x=1#one",
        "https://example.com/upload?x=2#two",
        "same",
        "Query/fragment changes should not create fresh destination identities.",
    ),
    IdentityCase(
        "D7",
        "scheme_change",
        "http://example.com:8080/upload",
        "https://example.com:8080/upload",
        "different",
        "The stated destination identity includes scheme, so HTTP and HTTPS should remain distinct.",
    ),
    IdentityCase(
        "D8",
        "port_change",
        "https://example.com:443/upload",
        "https://example.com:8443/upload",
        "different",
        "The stated destination identity includes port; distinct ports remain separate sinks.",
    ),
    IdentityCase(
        "D9",
        "localhost_ip_alias",
        "http://localhost:8765/upload",
        "http://127.0.0.1:8765/upload",
        "boundary",
        "These often reach the same local receiver, but collapsing hostname-to-IP aliases requires resolution-aware identity.",
    ),
    IdentityCase(
        "D10",
        "ipv6_textual_alias",
        "http://[::1]:8765/upload",
        "http://[0:0:0:0:0:0:0:1]:8765/upload",
        "boundary",
        "Equivalent IPv6 textual forms require IP-address canonicalization beyond raw host strings.",
    ),
    IdentityCase(
        "D11",
        "hostname_alias",
        "https://api.example.test/upload",
        "https://alias.example.test/upload",
        "boundary",
        "Distinct hostnames may resolve to one receiver; DNS/CNAME equivalence is adapter/network dependent.",
    ),
]


def destination_key(url: str) -> Optional[str]:
    return primary_domain("http_request", {"url": url})


def make_policy(*, fanout: bool) -> PolicyFile:
    # Keep persistence disabled: P7 measures identity semantics, not restart state.
    cc_kwargs = {
        "window_seconds": 300,
        "window_max_calls": 50,
    }

    # Newer ProvProxy builds expose review/fan-out thresholds. Keep this
    # benchmark compatible with older configs by setting them only when present.
    cc = CrossCallWindowConfig(**cc_kwargs)
    if hasattr(cc, "review_threshold"):
        cc.review_threshold = None
    if hasattr(cc, "fanout_review_threshold"):
        cc.fanout_review_threshold = 0.30 if fanout else None
    if hasattr(cc, "fanout_min_destinations"):
        cc.fanout_min_destinations = 2

    return PolicyFile(
        version="p7-destination-identity-baseline",
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(
            ngram_size=4,
            coverage_threshold=0.60,
        ),
        decode_limits=DecodeLimits(),
        cross_call_window=cc,
    )


def run_rotation(case: IdentityCase, *, fanout: bool) -> tuple[bool, bool, Optional[int]]:
    policy = make_policy(fanout=fanout)
    session = Session(
        f"p7-{case.case_id}-{'fanout' if fanout else 'strict'}",
        policy,
        ttl_seconds=300,
    )
    session.register_sensitive_fragment(f"src-{case.case_id}", SECRET)

    urls = [case.url_a, case.url_b]
    detected = False
    review = False
    containment_call = None

    for call_no, fragment in enumerate(FRAGMENTS, 1):
        url = urls[(call_no - 1) % len(urls)]
        key = destination_key(url)

        result = evaluate(
            policy,
            session,
            fragment,
            policy.decode_limits,
            destination_allowed=False,
            destination_domain=key,
        )

        if result.matched:
            detected = True
        if getattr(result, "review_required", False):
            review = True

        if containment_call is None and (
            result.matched
            or getattr(result, "review_required", False)
            or getattr(result, "enforcement_blocked", False)
        ):
            # enforcement_blocked is only meaningful when a provenance/review
            # signal is present; direct destination policy is intentionally not
            # under test here.
            if result.matched or getattr(result, "review_required", False):
                containment_call = call_no

        if result.matched or getattr(result, "review_required", False):
            break

    return detected, review, containment_call


def canonicalization_pass(case: IdentityCase, equal: bool) -> Optional[bool]:
    if case.expected_relation == "same":
        return equal
    if case.expected_relation == "different":
        return not equal
    return None


def run() -> int:
    assert "".join(FRAGMENTS) == SECRET, (
        "FRAGMENTS must reconstruct SECRET exactly; benchmark definition is invalid."
    )

    results: list[IdentityResult] = []

    print("=" * 112)
    print("PROVPROXY P7 DESTINATION IDENTITY EVASION BASELINE")
    print("=" * 112)
    print(
        f"{'case':<5} {'category':<27} {'equal':<6} {'expect':<9} "
        f"{'canon':<7} {'strict':<8} {'fanout':<8} {'evasion':<8}"
    )
    print("-" * 112)

    for case in CASES:
        key_a = destination_key(case.url_a)
        key_b = destination_key(case.url_b)
        equal = key_a == key_b
        canon_pass = canonicalization_pass(case, equal)

        strict_detected, strict_review, strict_call = run_rotation(
            case, fanout=False
        )
        fan_detected, fan_review, fan_call = run_rotation(
            case, fanout=True
        )

        # For "same" endpoint representations, strict V4 should ideally
        # accumulate them as one sink. If it does not detect/review, the
        # representation change produced an identity-reset evasion.
        representation_evasion = (
            case.expected_relation == "same"
            and not strict_detected
            and not strict_review
        )

        if case.expected_relation == "boundary":
            notes = (
                "Threat-model boundary: report observed identity behavior; "
                "do not call it a correctness failure without resolution-aware policy."
            )
        elif representation_evasion:
            notes = (
                "Same-endpoint representation split strict V4 state. "
                "Measure first; mitigation should canonicalize identity before accumulation."
            )
        elif canon_pass is False:
            notes = (
                "Canonicalization behavior disagrees with the stated destination-identity model."
            )
        else:
            notes = "Observed behavior is consistent with the declared relation."

        row = IdentityResult(
            case_id=case.case_id,
            category=case.category,
            url_a=case.url_a,
            url_b=case.url_b,
            key_a=key_a,
            key_b=key_b,
            identity_equal=equal,
            expected_relation=case.expected_relation,
            canonicalization_pass=canon_pass,
            strict_v4_detected=strict_detected,
            strict_v4_review=strict_review,
            strict_v4_containment_call=strict_call,
            fanout_detected=fan_detected,
            fanout_review=fan_review,
            fanout_containment_call=fan_call,
            representation_evasion_observed=representation_evasion,
            notes=notes,
        )
        results.append(row)

        canon_text = (
            "-"
            if canon_pass is None
            else ("PASS" if canon_pass else "FAIL")
        )
        strict_text = (
            "MATCH" if strict_detected else ("REVIEW" if strict_review else "MISS")
        )
        fanout_text = (
            "MATCH" if fan_detected else ("REVIEW" if fan_review else "MISS")
        )

        print(
            f"{case.case_id:<5} {case.category:<27} {str(equal):<6} "
            f"{case.expected_relation:<9} {canon_text:<7} "
            f"{strict_text:<8} {fanout_text:<8} "
            f"{str(representation_evasion):<8}"
        )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    jsonl_path = RESULTS_DIR / "destination_identity_validation.jsonl"
    md_path = RESULTS_DIR / "destination_identity_validation.md"

    with jsonl_path.open("w", encoding="utf-8") as fh:
        for row in results:
            fh.write(json.dumps(asdict(row), sort_keys=True) + "\n")

    same_cases = [r for r in results if r.expected_relation == "same"]
    diff_cases = [r for r in results if r.expected_relation == "different"]
    boundary_cases = [r for r in results if r.expected_relation == "boundary"]

    same_canon_pass = sum(r.canonicalization_pass is True for r in same_cases)
    diff_canon_pass = sum(r.canonicalization_pass is True for r in diff_cases)
    evasions = sum(r.representation_evasion_observed for r in same_cases)
    fanout_contained_same = sum(
        (r.fanout_detected or r.fanout_review) for r in same_cases
    )

    md = [
        "# P7 Destination Identity Evasion Baseline",
        "",
        "This is a frozen **pre-mitigation** baseline. Failures are evidence, not test noise.",
        "",
        "## Summary",
        "",
        f"- Same-endpoint canonicalization passes: **{same_canon_pass}/{len(same_cases)}**",
        f"- Intentionally-distinct canonicalization passes: **{diff_canon_pass}/{len(diff_cases)}**",
        f"- Same-endpoint strict-V4 representation evasions: **{evasions}/{len(same_cases)}**",
        f"- Same-endpoint cases contained by optional fan-out guard: **{fanout_contained_same}/{len(same_cases)}**",
        f"- Threat-model boundary cases: **{len(boundary_cases)}**",
        "",
        "## Case table",
        "",
        "| Case | Category | Key A | Key B | Equal | Expected | Canon | Strict V4 | Fan-out | Representation evasion |",
        "|---|---|---|---|---:|---|---|---|---|---:|",
    ]

    for r in results:
        canon = (
            "N/A"
            if r.canonicalization_pass is None
            else ("PASS" if r.canonicalization_pass else "FAIL")
        )
        strict = (
            "MATCH"
            if r.strict_v4_detected
            else ("REVIEW" if r.strict_v4_review else "MISS")
        )
        fanout = (
            "MATCH"
            if r.fanout_detected
            else ("REVIEW" if r.fanout_review else "MISS")
        )
        md.append(
            f"| {r.case_id} | {r.category} | `{r.key_a}` | `{r.key_b}` | "
            f"{r.identity_equal} | {r.expected_relation} | {canon} | "
            f"{strict} | {fanout} | {r.representation_evasion_observed} |"
        )

    md += [
        "",
        "## Interpretation rules",
        "",
        "- `expected_relation=same`: identity should normally canonicalize to one destination key.",
        "- `expected_relation=different`: identity should remain separate under the stated scheme+host+port model.",
        "- `expected_relation=boundary`: DNS/IP alias equivalence requires resolution-aware policy or network-adapter observability; the baseline records behavior without declaring it automatically wrong.",
        "- A strict-V4 representation evasion means semantically equivalent endpoint spelling split accumulation state enough to avoid a hard/review signal.",
        "- Fan-out results are reported separately because fan-out is intentionally review-only and does not redefine strict destination identity.",
        "",
        "## Frozen P7 baseline principle",
        "",
        "Do not modify these cases after seeing results. If mitigation is added, rerun this same suite as the before/after comparison and create a separate held-out P7 set for final validation.",
        "",
    ]
    md_path.write_text("\n".join(md), encoding="utf-8")

    print("-" * 112)
    print(
        f"Same-endpoint canonicalization: {same_canon_pass}/{len(same_cases)} | "
        f"strict representation evasions: {evasions}/{len(same_cases)} | "
        f"fan-out contained same-endpoint cases: {fanout_contained_same}/{len(same_cases)}"
    )
    print(f"JSONL:    {jsonl_path}")
    print(f"Markdown: {md_path}")

    # Baseline discovery should always exit 0: observed weaknesses are results,
    # not infrastructure failures. Assertions/import failures still exit nonzero.
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
