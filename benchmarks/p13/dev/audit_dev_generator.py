from __future__ import annotations

import ast
from pathlib import Path

TARGET = Path(__file__).resolve().parent / "generate_dev_corpus.py"

FORBIDDEN_IMPORT_ROOTS = {
    "provproxy",
    "sentence_transformers",
    "transformers",
    "torch",
    "requests",
    "httpx",
    "socket",
}

FORBIDDEN_TOKENS = {
    "p12_results",
    "p12_summary",
    "semantic_score",
    "p13_final",
    "benchmarks/results",
}


def main() -> None:
    source = TARGET.read_text(encoding="utf-8-sig")
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
                f"forbidden result/final reference: {token}"
            )

    print("=" * 90)
    print("P13 DEVELOPMENT GENERATOR ISOLATION AUDIT")
    print("=" * 90)

    if violations:
        for violation in violations:
            print(f"[FAIL] {violation}")
        raise SystemExit(1)

    print("[PASS] No ProvProxy imports.")
    print("[PASS] No semantic-model imports.")
    print("[PASS] No network-library imports.")
    print("[PASS] No P12 detector-result references.")
    print("[PASS] No P13 final-corpus references.")
    print("=" * 90)


if __name__ == "__main__":
    main()
