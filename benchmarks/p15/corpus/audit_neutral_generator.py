from __future__ import annotations

import ast
from pathlib import Path


TARGET = Path(
    "benchmarks/p15/corpus/generate_neutral_corpus.py"
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
    "p11_results",
    "p12_results",
    "p13_results",
    "p14_results",
    "p15_results",
    "benchmarks/results",
    "semantic_score",
    "detector_score",
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
                f"forbidden result reference: {token}"
            )

    print("=" * 100)
    print("P15 NEUTRAL CORPUS GENERATOR ISOLATION AUDIT")
    print("=" * 100)

    if violations:
        for item in violations:
            print(f"[FAIL] {item}")

        raise SystemExit(1)

    print("[PASS] No ProvProxy imports.")
    print("[PASS] No NeMo Guardrails imports.")
    print("[PASS] No semantic/model imports.")
    print("[PASS] No network-library imports.")
    print("[PASS] No prior detector-result references.")
    print("[PASS] Generator is detector-blind.")
    print("=" * 100)


if __name__ == "__main__":
    main()
