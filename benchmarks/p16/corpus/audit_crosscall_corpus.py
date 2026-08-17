from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path


CORPUS = Path(
    "benchmarks/p16/corpus/p16_crosscall_corpus.jsonl"
)

EXPECTED_TOTAL = 1600
EXPECTED_PER_GROUP = 400
EXPECTED_CHUNK_SIZES = {2, 3, 4, 5, 6, 7, 8, 10, 12}


def main() -> None:
    rows = [
        json.loads(line)
        for line in CORPUS.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    problems = []

    print("=" * 108)
    print("P16 CROSS-CALL CORPUS STRUCTURAL AUDIT")
    print("=" * 108)

    # Basic cardinality.
    print("Rows:", len(rows))

    if len(rows) != EXPECTED_TOTAL:
        problems.append(
            f"expected {EXPECTED_TOTAL} rows, got {len(rows)}"
        )

    ids = [r["case_id"] for r in rows]
    source_ids = [r["source_id"] for r in rows]
    source_texts = [r["source_text"] for r in rows]

    if len(set(ids)) != len(ids):
        problems.append("duplicate case_id")

    if len(set(source_ids)) != len(source_ids):
        problems.append("duplicate source_id")

    if len(set(source_texts)) != len(source_texts):
        problems.append("duplicate source_text")

    # Label/category balance.
    groups = Counter(
        (r["label"], r["category"])
        for r in rows
    )

    print("\nLabel/category counts:")
    for key in sorted(groups):
        print(f"  {key}: {groups[key]}")

    expected_groups = {
        ("malicious", "cross_call_fragmentation"),
        (
            "malicious",
            "interleaved_cross_call_fragmentation",
        ),
        ("benign", "cross_call_fragmentation"),
        (
            "benign",
            "interleaved_cross_call_fragmentation",
        ),
    }

    if set(groups) != expected_groups:
        problems.append(
            "unexpected label/category groups"
        )

    for key in expected_groups:
        if groups.get(key) != EXPECTED_PER_GROUP:
            problems.append(
                f"{key} count != {EXPECTED_PER_GROUP}"
            )

    # Chunk-size distributions.
    chunk_counts = defaultdict(Counter)

    for row in rows:
        key = (
            row["label"],
            row["category"],
        )
        chunk_counts[key][
            int(row["chunk_size"])
        ] += 1

    print("\nChunk-size distributions:")

    for key in sorted(chunk_counts):
        observed = set(chunk_counts[key])

        print(
            f"  {key}: "
            f"{dict(sorted(chunk_counts[key].items()))}"
        )

        if observed != EXPECTED_CHUNK_SIZES:
            problems.append(
                f"{key} missing/unexpected chunk sizes: "
                f"{sorted(observed)}"
            )

    # Structural invariants.
    for row in rows:
        expected_interleaved = (
            row["category"]
            == "interleaved_cross_call_fragmentation"
        )

        if bool(row["interleaved"]) != expected_interleaved:
            problems.append(
                f"{row['case_id']}: interleaved flag mismatch"
            )

        if row.get("synthetic_only") is not True:
            problems.append(
                f"{row['case_id']}: synthetic_only != True"
            )

        if not row["calls"]:
            problems.append(
                f"{row['case_id']}: empty calls"
            )
            continue

        for call in row["calls"]:
            if call.get("tool") != "http_request":
                problems.append(
                    f"{row['case_id']}: unexpected tool"
                )

            args = call.get("arguments", {})

            if (
                args.get("url")
                != "https://collector-p16.example/api"
            ):
                problems.append(
                    f"{row['case_id']}: unexpected destination"
                )

            if not isinstance(args.get("message"), str):
                problems.append(
                    f"{row['case_id']}: non-string message"
                )

    # Critical leakage check:
    # benign outbound messages must not accidentally contain
    # their registered protected source.
    benign_source_leaks = 0

    for row in rows:
        if row["label"] != "benign":
            continue

        joined = "".join(
            str(call["arguments"].get("message", ""))
            for call in row["calls"]
        )

        if row["source_text"] in joined:
            benign_source_leaks += 1

    print(
        "\nBenign rows containing complete protected source:",
        benign_source_leaks,
    )

    if benign_source_leaks:
        problems.append(
            f"{benign_source_leaks} benign rows contain source_text"
        )

    print("\n" + "-" * 108)

    if problems:
        for problem in problems[:30]:
            print("[FAIL]", problem)

        if len(problems) > 30:
            print(
                f"[FAIL] ... plus {len(problems) - 30} more"
            )

        raise SystemExit(1)

    print("[PASS] 1600 rows present.")
    print("[PASS] Case/source identifiers unique.")
    print("[PASS] Four experimental groups balanced 400/400/400/400.")
    print("[PASS] Required chunk sizes represented in every group.")
    print("[PASS] Interleaving metadata structurally consistent.")
    print("[PASS] Synthetic-only invariant preserved.")
    print("[PASS] Benign rows do not contain complete protected sources.")
    print("[PASS] No detector executed.")
    print("=" * 108)


if __name__ == "__main__":
    main()
