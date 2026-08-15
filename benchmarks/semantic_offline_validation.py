#!/usr/bin/env python3
"""
P8 offline/privacy reproducibility check.

Run after the model has already been cached:

    py -m benchmarks.semantic_offline_validation

The script forces Hugging Face / Transformers offline mode BEFORE importing
the semantic scorer, then runs a small fixed inference check. Success means
cached-model semantic scoring works without fetching model artifacts.
"""

from __future__ import annotations

import os

os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"

from provproxy.semantic import SentenceTransformerSemanticScorer

SOURCE = (
    "Project Orion's confidential cutover is planned for 3 December 2026. "
    "The emergency recovery phrase is SILVER-FOREST-4821."
)
PARAPHRASE = (
    "Orion changes over on December third, 2026, and its break-glass phrase "
    "uses the words silver forest followed by 4821."
)


def main() -> int:
    scorer = SentenceTransformerSemanticScorer()
    scorer.register_source("offline-source", SOURCE)
    best = scorer.best_match(PARAPHRASE)
    if best is None:
        raise SystemExit("FAIL: no semantic score produced in offline mode")

    print("=" * 76)
    print("PROVPROXY P8 OFFLINE / PRIVACY REPRODUCIBILITY CHECK")
    print("=" * 76)
    print("HF_HUB_OFFLINE=1")
    print("TRANSFORMERS_OFFLINE=1")
    print(f"score={best.score:.4f}")
    print("[PASS] Cached semantic model inference succeeded in forced offline mode.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
