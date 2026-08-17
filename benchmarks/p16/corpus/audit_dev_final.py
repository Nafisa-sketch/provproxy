from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path


DEV = Path("benchmarks/p16/corpus/p16_dev.jsonl")
FINAL = Path("benchmarks/p16/corpus/p16_final_heldout.jsonl")

EXPECTED_DEV = "299749113B27CFFD56284644630D214D029FB00891F863AF417F31977314677F"
EXPECTED_FINAL = "D35A93AB2D48A44DC45F4E70211F00CFC8667ACD0DA965B3B92ED923D47F9BBE"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def load(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def summarize(name: str, rows: list[dict]) -> None:
    print(f"\n{name}")
    print("-" * 90)

    print("Rows:", len(rows))

    groups = Counter(
        (r["label"], r["category"])
        for r in rows
    )

    for key in sorted(groups):
        print(key, groups[key])

    chunks = Counter(
        r["chunk_size"]
        for r in rows
    )

    print("Chunk sizes:", dict(sorted(chunks.items())))


def main() -> None:
    dev_hash = sha256(DEV)
    final_hash = sha256(FINAL)

    dev = load(DEV)
    final = load(FINAL)

    print("=" * 100)
    print("P16 DEV / FINAL SPLIT AUDIT")
    print("=" * 100)

    print("DEV hash   :", dev_hash)
    print("FINAL hash :", final_hash)

    if dev_hash != EXPECTED_DEV:
        raise SystemExit("[FAIL] DEV hash mismatch")

    if final_hash != EXPECTED_FINAL:
        raise SystemExit("[FAIL] FINAL hash mismatch")

    if len(dev) != 800 or len(final) != 800:
        raise SystemExit("[FAIL] Expected 800/800 split")

    dev_ids = {r["case_id"] for r in dev}
    final_ids = {r["case_id"] for r in final}

    if dev_ids & final_ids:
        raise SystemExit("[FAIL] DEV/FINAL overlap detected")

    expected = {
        ("malicious", "cross_call_fragmentation"): 200,
        ("malicious", "interleaved_cross_call_fragmentation"): 200,
        ("benign", "cross_call_fragmentation"): 200,
        ("benign", "interleaved_cross_call_fragmentation"): 200,
    }

    if Counter((r["label"], r["category"]) for r in dev) != Counter(expected):
        raise SystemExit("[FAIL] DEV group imbalance")

    if Counter((r["label"], r["category"]) for r in final) != Counter(expected):
        raise SystemExit("[FAIL] FINAL group imbalance")

    summarize("DEVELOPMENT", dev)
    summarize("FINAL HELD-OUT", final)

    print()
    print("[PASS] Hashes verified.")
    print("[PASS] DEV/FINAL disjoint.")
    print("[PASS] 200 rows per group in both splits.")
    print("[PASS] Final held-out remains detector-unseen.")
    print("=" * 100)


if __name__ == "__main__":
    main()
