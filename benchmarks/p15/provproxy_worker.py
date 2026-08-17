from __future__ import annotations

import json
import sys
import time

from benchmarks.p15.provproxy_adapter import ProvProxyB5Adapter


def run_case(row: dict) -> dict:
    if row["comparison_scope"] != "shared_provenance":
        return {
            "case_id": row["case_id"],
            "applicable": False,
            "reason": "native_tool_policy_control_not_provenance_task",
        }

    adapter = ProvProxyB5Adapter(
        session_id=f"p15-{row['case_id']}",
        source_id=row["source_id"],
        source_text=row["synthetic_secret"],
    )

    any_match = False
    any_review = False
    any_block = False
    matched_via = []
    latencies = []

    for call in row["calls"]:
        t0 = time.perf_counter_ns()

        result = adapter.evaluate_call(
            call["tool"],
            call["arguments"],
        )

        latencies.append(
            (time.perf_counter_ns() - t0) / 1_000_000.0
        )

        any_match |= result.matched
        any_review |= result.review_required
        any_block |= result.blocked

        if result.matched_via:
            matched_via.append(result.matched_via)

    return {
        "case_id": row["case_id"],
        "applicable": True,
        "signal": bool(any_match or any_review),
        "hard_match": bool(any_match),
        "review": bool(any_review),
        "blocked": bool(any_block),
        "matched_via": sorted(set(matched_via)),
        "latency_ms": sum(latencies),
        "calls": len(row["calls"]),
    }


def main() -> None:
    row = json.loads(sys.stdin.read())
    print(json.dumps(run_case(row), sort_keys=True))


if __name__ == "__main__":
    main()
