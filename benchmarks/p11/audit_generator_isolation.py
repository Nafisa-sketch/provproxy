from pathlib import Path

ROOT = Path(__file__).resolve().parent

forbidden = (
    "import provproxy",
    "from provproxy",
    "p10_frozen_results",
    "p10_summary",
    "semantic_threshold_sweep",
)

violations = []

for path in ROOT.glob("*.py"):
    if path.name == "audit_generator_isolation.py":
        continue

    text = path.read_text(encoding="utf-8-sig").lower()

    for token in forbidden:
        if token.lower() in text:
            violations.append((path.name, token))

print("=" * 72)
print("P11 GENERATOR ISOLATION AUDIT")
print("=" * 72)

if violations:
    for path, token in violations:
        print(f"[FAIL] {path}: {token}")
    raise SystemExit(1)

print("[PASS] No ProvProxy or previous-result dependency detected.")
print("[PASS] Generator remains detector-blind.")
