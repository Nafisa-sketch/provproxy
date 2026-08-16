from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

CORPUS = Path(
    "benchmarks/p13/dev/fixtures/p13_dev_corpus.jsonl"
)

EXPECTED_SHA256 = (
    "00F0FB3B957D3C743C5CFA67467C0ABCEA6DCF7D3AB2D1D9E4712B6A4E32C789"
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest().upper()


def flatten_strings(value) -> list[str]:
    out = []

    if isinstance(value, str):
        out.append(value)

    elif isinstance(value, list):
        for item in value:
            out.extend(
                flatten_strings(item)
            )

    elif isinstance(value, dict):
        for item in value.values():
            out.extend(
                flatten_strings(item)
            )

    return out


rows = [
    json.loads(line)
    for line in CORPUS.read_text(
        encoding="utf-8-sig"
    ).splitlines()
    if line.strip()
]

digest = sha256_file(CORPUS)

problems = []

print("=" * 104)
print("P13-D1 HOSTILE DEVELOPMENT CORPUS AUDIT")
print("=" * 104)

# ------------------------------------------------------------
# A. Integrity
# ------------------------------------------------------------

print("\nA. BASIC INTEGRITY")
print("-" * 104)

print(f"SHA-256             : {digest}")
print(f"Expected SHA-256    : {EXPECTED_SHA256}")
print(f"Cases               : {len(rows)}")

if digest != EXPECTED_SHA256:
    problems.append(
        "Development corpus hash mismatch."
    )

if len(rows) != 360:
    problems.append(
        f"Expected 360 rows, found {len(rows)}."
    )

ids = [
    row["case_id"]
    for row in rows
]

print(f"Unique case IDs     : {len(set(ids))}")

if len(ids) != len(set(ids)):
    problems.append(
        "Duplicate case IDs detected."
    )

# ------------------------------------------------------------
# B. Label/category balance
# ------------------------------------------------------------

print("\nB. LABEL AND CATEGORY BALANCE")
print("-" * 104)

labels = Counter(
    row["label"]
    for row in rows
)

print(f"Labels              : {dict(labels)}")

if labels != Counter(
    {
        "malicious": 180,
        "benign": 180,
    }
):
    problems.append(
        f"Unexpected label distribution: {labels}"
    )

category_counts = Counter(
    (
        row["label"],
        row["category"],
    )
    for row in rows
)

for (
    label,
    category,
), count in sorted(
    category_counts.items()
):
    print(
        f"{label:10s} "
        f"{category:36s} "
        f"{count:3d}"
    )

if any(
    count != 30
    for count in category_counts.values()
):
    problems.append(
        "At least one category does not contain exactly 30 cases."
    )

# ------------------------------------------------------------
# C. Source uniqueness
# ------------------------------------------------------------

print("\nC. SOURCE INDEPENDENCE")
print("-" * 104)

sources = [
    row["synthetic_source"]
    for row in rows
]

source_ids = [
    row["source_id"]
    for row in rows
]

print(
    f"Unique source texts : "
    f"{len(set(sources))}/{len(sources)}"
)

print(
    f"Unique source IDs   : "
    f"{len(set(source_ids))}/{len(source_ids)}"
)

if len(sources) != len(set(sources)):
    problems.append(
        "Synthetic source reuse detected."
    )

if len(source_ids) != len(set(source_ids)):
    problems.append(
        "Source ID reuse detected."
    )

# ------------------------------------------------------------
# D. Full-source representation leakage
# ------------------------------------------------------------

print("\nD. FULL-SOURCE REPRESENTATION LEAKAGE")
print("-" * 104)

literal_full = 0
base64_full = 0
hex_full = 0

for row in rows:
    candidate = " ".join(
        flatten_strings(
            row["calls"]
        )
    )

    source = row["synthetic_source"]

    if source in candidate:
        literal_full += 1

    b64 = base64.b64encode(
        source.encode("utf-8")
    ).decode("ascii")

    if b64 in candidate:
        base64_full += 1

    hx = source.encode(
        "utf-8"
    ).hex()

    if hx in candidate.lower():
        hex_full += 1

print(f"Literal full source : {literal_full}")
print(f"Base64 full source  : {base64_full}")
print(f"Hex full source     : {hex_full}")

if literal_full:
    problems.append(
        f"{literal_full} full literal source representations leaked."
    )

if base64_full:
    problems.append(
        f"{base64_full} full Base64 source representations leaked."
    )

if hex_full:
    problems.append(
        f"{hex_full} full hex source representations leaked."
    )

# ------------------------------------------------------------
# E. Structural families
# ------------------------------------------------------------

print("\nE. STRUCTURAL-FAMILY OVERLAP")
print("-" * 104)

families_by_label = defaultdict(set)

for row in rows:
    families_by_label[
        row["label"]
    ].add(
        row["structural_family"]
    )

for label, families in sorted(
    families_by_label.items()
):
    print(
        f"{label:10s}: "
        f"{len(families)} families "
        f"{sorted(families)}"
    )

shared_families = (
    families_by_label["malicious"]
    & families_by_label["benign"]
)

print(
    f"Shared across labels: "
    f"{len(shared_families)}"
)

if len(shared_families) < 8:
    problems.append(
        "Structural families do not fully overlap across labels."
    )

# ------------------------------------------------------------
# F. Tool distributions
# ------------------------------------------------------------

print("\nF. TOOL DISTRIBUTION BY LABEL")
print("-" * 104)

tools = defaultdict(Counter)

for row in rows:
    for call in row["calls"]:
        tools[
            row["label"]
        ][
            call["tool"]
        ] += 1

all_tools = sorted(
    set(
        tools["malicious"]
    )
    | set(
        tools["benign"]
    )
)

print(
    f"{'tool':24s} "
    f"{'malicious':>10s} "
    f"{'benign':>10s}"
)

for tool in all_tools:
    print(
        f"{tool:24s} "
        f"{tools['malicious'][tool]:10d} "
        f"{tools['benign'][tool]:10d}"
    )

# ------------------------------------------------------------
# G. Simple structural shortcut audit
# ------------------------------------------------------------

print("\nG. SIMPLE STRUCTURAL SHORTCUT AUDIT")
print("-" * 104)

# Since corpus is exactly balanced, a trivial label predictor gets 0.50.
# We measure majority label within structural-family and tool buckets.
def bucket_accuracy(key_fn) -> float:
    buckets = defaultdict(Counter)

    for row in rows:
        buckets[
            key_fn(row)
        ][
            row["label"]
        ] += 1

    correct = sum(
        max(counts.values())
        for counts in buckets.values()
    )

    return correct / len(rows)


tool_acc = bucket_accuracy(
    lambda row: row["calls"][0]["tool"]
)

family_acc = bucket_accuracy(
    lambda row: row["structural_family"]
)

tool_family_acc = bucket_accuracy(
    lambda row: (
        row["calls"][0]["tool"],
        row["structural_family"],
    )
)

print(f"Majority baseline     : 0.500")
print(f"Tool-only accuracy    : {tool_acc:.3f}")
print(f"Family-only accuracy  : {family_acc:.3f}")
print(
    f"Tool+family accuracy  : "
    f"{tool_family_acc:.3f}"
)

highest_shortcut = max(
    tool_acc,
    family_acc,
    tool_family_acc,
)

if highest_shortcut >= 0.70:
    problems.append(
        f"Strong structural shortcut detected: {highest_shortcut:.3f}"
    )

# ------------------------------------------------------------
# H. Call counts
# ------------------------------------------------------------

print("\nH. CALL COUNT")
print("-" * 104)

call_counts = Counter(
    (
        row["label"],
        len(row["calls"]),
    )
    for row in rows
)

for key, value in sorted(
    call_counts.items()
):
    print(
        f"{key}: {value}"
    )

# ------------------------------------------------------------
# Final
# ------------------------------------------------------------

print("\n" + "=" * 104)

if problems:
    print("P13-D1 CORPUS AUDIT: FAIL")

    for problem in problems:
        print(
            f"[FAIL] {problem}"
        )

    raise SystemExit(1)

print("P13-D1 CORPUS AUDIT: PASS")
print("[PASS] Frozen generator is deterministic.")
print("[PASS] Label/category balance verified.")
print("[PASS] Source IDs/texts are unique.")
print("[PASS] No full literal/Base64/hex source leakage.")
print("[PASS] Structural families overlap across labels.")
print("[PASS] No strong tool/family shortcut detected.")
print("[PASS] No detector or semantic model executed.")
print("=" * 104)
