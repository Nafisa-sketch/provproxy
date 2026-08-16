from __future__ import annotations

import ast
from pathlib import Path

TARGET = Path(__file__).resolve().parent / "generate_semantic_corpus.py"

FORBIDDEN_IMPORT_ROOTS = {
    "provproxy",
    "sentence_transformers",
    "transformers",
    "torch",
    "requests",
    "httpx",
    "urllib",
    "socket",
}

FORBIDDEN_PATH_TOKENS = {
    "semantic_threshold_sweep",
    "semantic_heldout_validation",
    "p11_frozen_results",
    "p10_frozen_results",
    "benchmarks/results",
}


def main() -> None:
    source = TARGET.read_text(encoding="utf-8-sig")
    tree = ast.parse(source)

    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_IMPORT_ROOTS:
                    violations.append(f"forbidden import: {alias.name}")

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]
                if root in FORBIDDEN_IMPORT_ROOTS:
                    violations.append(f"forbidden import-from: {node.module}")

    lowered = source.lower()

    for token in FORBIDDEN_PATH_TOKENS:
        if token.lower() in lowered:
            violations.append(f"forbidden previous-result reference: {token}")

    print("=" * 84)
    print("P12 GENERATOR ISOLATION AUDIT")
    print("=" * 84)

    if violations:
        for violation in violations:
            print(f"[FAIL] {violation}")
        raise SystemExit(1)

    print("[PASS] No detector-package imports found.")
    print("[PASS] No semantic-model imports found.")
    print("[PASS] No network-library imports found.")
    print("[PASS] No previous detector-result references found.")
    print("[PASS] Generator source is detector-blind by static audit.")
    print("=" * 84)


if __name__ == "__main__":
    main()
