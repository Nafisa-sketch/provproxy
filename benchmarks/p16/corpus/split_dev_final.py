from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]

CORPUS = (
    ROOT
    / "benchmarks"
    / "p16"
    / "corpus"
    / "p16_crosscall_corpus.jsonl"
)

DEV_OUT = (
    ROOT
    / "benchmarks"
    / "p16"
    / "corpus"
    / "p16_dev.jsonl"
)

FINAL_OUT = (
    ROOT
    / "benchmarks"
    / "p16"
    / "corpus"
    / "p16_final_heldout.jsonl"
)


def stable_key(case_id: str) -> str:
    return hashlib.sha256(
        (
            "P16_SPLIT_V1|"
            + case_id
        ).encode("utf-8")
    ).hexdigest()


def write_jsonl(
    path: Path,
    rows: list[dict],
) -> None:
    with path.open(
        "w",
        encoding="utf-8",
    ) as f:
        for row in rows:
            f.write(
                json.dumps(
                    row,
                    sort_keys=True,
                )
                + "\n"
            )


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest().upper()


def main() -> None:
    rows = [
        json.loads(line)
        for line in CORPUS.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    groups = defaultdict(list)

    for row in rows:
        groups[
            (
                row["label"],
                row["category"],
            )
        ].append(row)

    dev = []
    final = []

    for key in sorted(groups):
        group = sorted(
            groups[key],
            key=lambda row: stable_key(
                row["case_id"]
            ),
        )

        if len(group) != 400:
            raise SystemExit(
                f"[FAIL] {key}: expected 400, "
                f"got {len(group)}"
            )

        dev.extend(
            group[:200]
        )

        final.extend(
            group[200:]
        )

    dev = sorted(
        dev,
        key=lambda row: stable_key(
            "DEV|" + row["case_id"]
        ),
    )

    final = sorted(
        final,
        key=lambda row: stable_key(
            "FINAL|" + row["case_id"]
        ),
    )

    write_jsonl(
        DEV_OUT,
        dev,
    )

    write_jsonl(
        FINAL_OUT,
        final,
    )

    print("=" * 108)
    print("P16 DETERMINISTIC DEVELOPMENT / FINAL SPLIT")
    print("=" * 108)

    print("Corpus cases :", len(rows))
    print("Development  :", len(dev))
    print("Final heldout:", len(final))

    print()
    print(
        "DEV SHA-256   :",
        sha256_file(DEV_OUT),
    )
    print(
        "FINAL SHA-256 :",
        sha256_file(FINAL_OUT),
    )

    print()
    print("[PASS] Exactly 200 rows/group assigned to development.")
    print("[PASS] Exactly 200 rows/group assigned to final held-out.")
    print("[PASS] Split based only on case_id hash.")
    print("[PASS] No detector executed.")
    print("=" * 108)


if __name__ == "__main__":
    main()
