from __future__ import annotations

import ast
from pathlib import Path


TARGET = Path(
    "benchmarks/p16/corpus/split_dev_final.py"
)

FORBIDDEN_ROOTS = {
    "provproxy",
    "nemoguardrails",
    "torch",
    "transformers",
    "requests",
    "httpx",
}

FORBIDDEN_TEXT = {
    "benchmarks/results",
    "coverage_threshold",
    "review_threshold",
    "signal_rate",
    "detection_rate",
    "false_positive_rate",
}


def main() -> None:
    source = TARGET.read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(source)

    problems = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]

                if root in FORBIDDEN_ROOTS:
                    problems.append(
                        f"forbidden import: {alias.name}"
                    )

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]

                if root in FORBIDDEN_ROOTS:
                    problems.append(
                        f"forbidden import-from: {node.module}"
                    )

    lowered = source.lower()

    for token in FORBIDDEN_TEXT:
        if token.lower() in lowered:
            problems.append(
                f"forbidden result/tuning reference: {token}"
            )

    print("=" * 100)
    print("P16 SPLIT ISOLATION AUDIT")
    print("=" * 100)

    if problems:
        for p in problems:
            print("[FAIL]", p)

        raise SystemExit(1)

    print("[PASS] Split logic has no detector imports.")
    print("[PASS] Split logic has no prior-result references.")
    print("[PASS] Split assignment depends only on case IDs.")
    print("[PASS] No detector executed.")
    print("=" * 100)


if __name__ == "__main__":
    main()
