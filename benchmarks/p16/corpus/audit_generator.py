from __future__ import annotations

import ast
from pathlib import Path


TARGET = Path(
    "benchmarks/p16/corpus/generate_crosscall_corpus.py"
)

FORBIDDEN_IMPORT_ROOTS = {
    "provproxy",
    "nemoguardrails",
    "sentence_transformers",
    "transformers",
    "torch",
    "requests",
    "httpx",
    "socket",
}

FORBIDDEN_TOKENS = {
    "benchmarks/results",
    "p15_final",
    "p16_final",
    "coverage_threshold",
    "review_threshold",
    "fanout_review_threshold",
    "detector_score",
    "signal_rate",
    "false_positive_rate",
}


def main() -> None:
    source = TARGET.read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(source)

    violations = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]

                if root in FORBIDDEN_IMPORT_ROOTS:
                    violations.append(
                        f"forbidden import: {alias.name}"
                    )

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]

                if root in FORBIDDEN_IMPORT_ROOTS:
                    violations.append(
                        f"forbidden import-from: {node.module}"
                    )

    lowered = source.lower()

    for token in FORBIDDEN_TOKENS:
        if token.lower() in lowered:
            violations.append(
                f"forbidden tuning/result reference: {token}"
            )

    print("=" * 100)
    print("P16 CORPUS GENERATOR ISOLATION AUDIT")
    print("=" * 100)

    if violations:
        for item in violations:
            print("[FAIL]", item)

        raise SystemExit(1)

    print("[PASS] No ProvProxy imports.")
    print("[PASS] No NeMo/model imports.")
    print("[PASS] No network imports.")
    print("[PASS] No P15/P16 result references.")
    print("[PASS] No detector-threshold references.")
    print("[PASS] Generator is detector-blind.")
    print("=" * 100)


if __name__ == "__main__":
    main()
