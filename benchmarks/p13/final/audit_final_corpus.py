from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


FINAL = Path(
    "benchmarks/p13/final/fixtures/p13_final_corpus.jsonl"
)

DEV = Path(
    "benchmarks/p13/dev/fixtures/p13_dev_corpus.jsonl"
)

EXPECTED_FINAL_HASH = (
    "C2EF14D344B0B34AD87D8736616AC4F3586FF61BFABAE0F37FED79289E5CAB31"
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest().upper()


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8-sig"
        ).splitlines()
        if line.strip()
    ]


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


final_rows = read_jsonl(FINAL)
dev_rows = read_jsonl(DEV)

problems = []

digest = sha256_file(FINAL)

print("=" * 108)
print("P13-F1 HOSTILE FINAL-CORPUS AUDIT")
print("=" * 108)


# ------------------------------------------------------------------
# A. Integrity
# ------------------------------------------------------------------

print("\nA. BASIC INTEGRITY")
print("-" * 108)

print(f"SHA-256             : {digest}")
print(f"Expected SHA-256    : {EXPECTED_FINAL_HASH}")
print(f"Cases               : {len(final_rows)}")

if digest != EXPECTED_FINAL_HASH:
    problems.append(
        "Final corpus hash mismatch."
    )

if len(final_rows) != 1200:
    problems.append(
        f"Expected 1200 final cases, found {len(final_rows)}."
    )

ids = [
    row["case_id"]
    for row in final_rows
]

print(f"Unique case IDs     : {len(set(ids))}")

if len(ids) != len(set(ids)):
    problems.append(
        "Duplicate final case IDs detected."
    )


# ------------------------------------------------------------------
# B. Label/category balance
# ------------------------------------------------------------------

print("\nB. LABEL AND CATEGORY BALANCE")
print("-" * 108)

labels = Counter(
    row["label"]
    for row in final_rows
)

print(f"Labels              : {dict(labels)}")

if labels != Counter(
    {
        "malicious": 600,
        "benign": 600,
    }
):
    problems.append(
        f"Unexpected label counts: {labels}"
    )

category_counts = Counter(
    (
        row["label"],
        row["category"],
    )
    for row in final_rows
)

for (label, category), count in sorted(
    category_counts.items()
):
    print(
        f"{label:10s} "
        f"{category:42s} "
        f"{count:3d}"
    )

if len(category_counts) != 20:
    problems.append(
        f"Expected 20 label/category groups, found {len(category_counts)}."
    )

if any(
    count != 60
    for count in category_counts.values()
):
    problems.append(
        "At least one final category does not contain exactly 60 cases."
    )


# ------------------------------------------------------------------
# C. Final-source independence
# ------------------------------------------------------------------

print("\nC. FINAL SOURCE INDEPENDENCE")
print("-" * 108)

final_sources = [
    row["synthetic_source"]
    for row in final_rows
]

final_source_ids = [
    row["source_id"]
    for row in final_rows
]

print(
    f"Unique source texts : "
    f"{len(set(final_sources))}/{len(final_sources)}"
)

print(
    f"Unique source IDs   : "
    f"{len(set(final_source_ids))}/{len(final_source_ids)}"
)

if len(final_sources) != len(set(final_sources)):
    problems.append(
        "Final synthetic-source reuse detected."
    )

if len(final_source_ids) != len(set(final_source_ids)):
    problems.append(
        "Final source-ID reuse detected."
    )


# ------------------------------------------------------------------
# D. Development/final independence
# ------------------------------------------------------------------

print("\nD. DEVELOPMENT / FINAL INDEPENDENCE")
print("-" * 108)

dev_sources = {
    row["synthetic_source"]
    for row in dev_rows
}

dev_ids = {
    row["case_id"]
    for row in dev_rows
}

dev_source_ids = {
    row["source_id"]
    for row in dev_rows
}

source_overlap = (
    set(final_sources)
    & dev_sources
)

case_id_overlap = (
    set(ids)
    & dev_ids
)

source_id_overlap = (
    set(final_source_ids)
    & dev_source_ids
)

print(f"Exact source overlap : {len(source_overlap)}")
print(f"Case-ID overlap      : {len(case_id_overlap)}")
print(f"Source-ID overlap    : {len(source_id_overlap)}")

if source_overlap:
    problems.append(
        f"Development/final exact source overlap: {len(source_overlap)}"
    )

if case_id_overlap:
    problems.append(
        f"Development/final case-ID overlap: {len(case_id_overlap)}"
    )

if source_id_overlap:
    problems.append(
        f"Development/final source-ID overlap: {len(source_id_overlap)}"
    )


# ------------------------------------------------------------------
# E. Full-source leakage
# ------------------------------------------------------------------

print("\nE. MALICIOUS FULL-SOURCE REPRESENTATION LEAKAGE")
print("-" * 108)

literal_full = 0
base64_full = 0
hex_full = 0

for row in final_rows:
    if row["label"] != "malicious":
        continue

    candidate = " ".join(
        flatten_strings(
            row["calls"]
        )
    )

    source = row["synthetic_source"]

    if source in candidate:
        literal_full += 1

    encoded = base64.b64encode(
        source.encode("utf-8")
    ).decode("ascii")

    if encoded in candidate:
        base64_full += 1

    source_hex = source.encode(
        "utf-8"
    ).hex()

    if source_hex in candidate.lower():
        hex_full += 1

print(f"Literal full source : {literal_full}")
print(f"Base64 full source  : {base64_full}")
print(f"Hex full source     : {hex_full}")

if literal_full:
    problems.append(
        f"{literal_full} malicious cases contain full literal source."
    )

if base64_full:
    problems.append(
        f"{base64_full} malicious cases contain full Base64 source."
    )

if hex_full:
    problems.append(
        f"{hex_full} malicious cases contain full hex source."
    )


# ------------------------------------------------------------------
# F. Structural-family overlap
# ------------------------------------------------------------------

print("\nF. STRUCTURAL-FAMILY BALANCE")
print("-" * 108)

families = defaultdict(Counter)

for row in final_rows:
    families[
        row["label"]
    ][
        row["structural_family"]
    ] += 1

for label in ["malicious", "benign"]:
    print(
        f"{label:10s}: "
        f"{dict(sorted(families[label].items()))}"
    )

mal_families = set(
    families["malicious"]
)

ben_families = set(
    families["benign"]
)

shared = (
    mal_families
    & ben_families
)

print(f"Shared families      : {len(shared)}")

if mal_families != ben_families:
    problems.append(
        "Final structural-family sets differ across labels."
    )

if len(shared) != 12:
    problems.append(
        f"Expected 12 shared structural families, found {len(shared)}."
    )


# ------------------------------------------------------------------
# G. Tool distribution
# ------------------------------------------------------------------

print("\nG. TOOL DISTRIBUTION BY LABEL")
print("-" * 108)

tools = defaultdict(Counter)

for row in final_rows:
    for call in row["calls"]:
        tools[
            row["label"]
        ][
            call["tool"]
        ] += 1

all_tools = sorted(
    set(tools["malicious"])
    | set(tools["benign"])
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


# ------------------------------------------------------------------
# H. Structural shortcut audit
# ------------------------------------------------------------------

print("\nH. STRUCTURAL SHORTCUT AUDIT")
print("-" * 108)


def bucket_accuracy(key_fn) -> float:
    buckets = defaultdict(Counter)

    for row in final_rows:
        buckets[
            key_fn(row)
        ][
            row["label"]
        ] += 1

    correct = sum(
        max(counts.values())
        for counts in buckets.values()
    )

    return correct / len(final_rows)


majority = (
    max(labels.values())
    / len(final_rows)
)

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

print(f"Majority baseline     : {majority:.3f}")
print(f"Tool-only accuracy    : {tool_acc:.3f}")
print(f"Family-only accuracy  : {family_acc:.3f}")
print(f"Tool+family accuracy  : {tool_family_acc:.3f}")

highest = max(
    tool_acc,
    family_acc,
    tool_family_acc,
)

if highest >= 0.70:
    problems.append(
        f"Strong structural shortcut detected: {highest:.3f}"
    )


# ------------------------------------------------------------------
# I. Call-count distribution
# ------------------------------------------------------------------

print("\nI. CALL-COUNT DISTRIBUTION")
print("-" * 108)

call_counts = Counter(
    (
        row["label"],
        len(row["calls"]),
    )
    for row in final_rows
)

for key, count in sorted(
    call_counts.items()
):
    print(
        f"{key}: {count}"
    )


# ------------------------------------------------------------------
# J. Source-schema compatibility
# ------------------------------------------------------------------

print("\nJ. FROZEN SOURCE-SCHEMA COMPATIBILITY")
print("-" * 108)

import re

schema = re.compile(
    r"Confidential recovery record for project "
    r"[A-Za-z0-9-]+\. "
    r"(?:The )?[Mm]aintenance (?:window is|is scheduled for) "
    r"\d{4}-\d{2}-\d{2} "
    r"at \d{2}:\d{2} UTC\. "
    r"The temporary recovery code is \d+\. "
    r"The recovery service is https://"
    r"[^:/\s]+:\d+/restore\. "
    r"The deployment belongs to the [^.]+\.",
    re.IGNORECASE,
)

schema_failures = sum(
    schema.fullmatch(
        row["synthetic_source"].strip()
    )
    is None
    for row in final_rows
)

print(
    f"Schema-compatible     : "
    f"{len(final_rows) - schema_failures}/{len(final_rows)}"
)

if schema_failures:
    problems.append(
        f"{schema_failures} final sources violate frozen verifier schema."
    )


# ------------------------------------------------------------------
# Final result
# ------------------------------------------------------------------

print("\n" + "=" * 108)

if problems:
    print("P13-F1 FINAL CORPUS AUDIT: FAIL")

    for problem in problems:
        print(
            f"[FAIL] {problem}"
        )

    raise SystemExit(1)

print("P13-F1 FINAL CORPUS AUDIT: PASS")
print("[PASS] Final corpus hash verified.")
print("[PASS] 600 malicious / 600 benign balance verified.")
print("[PASS] Category counts verified.")
print("[PASS] Final sources and IDs are unique.")
print("[PASS] No exact development/final overlap.")
print("[PASS] No full literal/Base64/hex source leakage.")
print("[PASS] Structural families overlap across labels.")
print("[PASS] No strong tool/family shortcut detected.")
print("[PASS] Frozen source schema remains compatible.")
print("[PASS] No detector or semantic model executed.")
print("=" * 108)
