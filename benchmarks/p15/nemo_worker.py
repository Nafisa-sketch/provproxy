from __future__ import annotations

import asyncio
import json
import sys
import time

from benchmarks.p15.nemo_adapter import NemoIORailsAdapter


VALID_TOOLS = [
    "http_request",
    "send_request",
    "post_data",
    "publish_event",
    "submit_payload",
]


DECLARED_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": name,
            "description": "Synthetic P15 network egress tool.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "message": {"type": "string"},
                    "part_a": {"type": "string"},
                    "part_b": {"type": "string"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    }
    for name in VALID_TOOLS
]


async def run_case(
    adapter: NemoIORailsAdapter,
    row: dict,
) -> dict:

    any_block = False
    reasons = []
    latencies = []

    for index, call in enumerate(row["calls"], 1):
        t0 = time.perf_counter_ns()

        result = await adapter.validate_tool_call_async(
            call_id=f"{row['case_id']}-{index}",
            tool_name=call["tool"],
            arguments=call["arguments"],
            declared_tools=DECLARED_TOOLS,
        )

        latencies.append(
            (time.perf_counter_ns() - t0) / 1_000_000.0
        )

        if result.blocked:
            any_block = True

        if result.reason:
            reasons.append(result.reason)

    return {
        "case_id": row["case_id"],
        "applicable": True,
        "unsafe_signal": bool(any_block),
        "blocked": bool(any_block),
        "reasons": reasons,
        "latency_ms": sum(latencies),
        "calls": len(row["calls"]),
        "scope": row["comparison_scope"],
    }


PREFIX = "P15_RESULT\\t"


async def async_main() -> None:
    adapter = NemoIORailsAdapter()

    for line in sys.stdin:
        if not line.strip():
            continue

        row = json.loads(line)

        try:
            result = await run_case(adapter, row)
        except Exception as exc:
            result = {
                "case_id": row.get("case_id"),
                "applicable": True,
                "worker_error": type(exc).__name__,
                "worker_error_message": str(exc),
            }

        print(
            PREFIX + json.dumps(result, sort_keys=True),
            flush=True,
        )


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
