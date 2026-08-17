from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


CORPUS = Path(
    "benchmarks/p15/corpus/fixtures/p15_neutral_corpus_v3.jsonl"
)

EXPECTED_SHA256 = (
    "36AAC3A1C8049608CE8E4205C5F39BDE8EBFAA387A02617411E1A504FF646809"
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def flatten_strings(value) -> list[str]:
    out = []

    if isinstance(value, str):
        out.append(value)

    elif isinstance(value, list):
        for item in value:
            out.extend(flatten_strings(item))

    elif isinstance(value, dict):
        for item in value.values():
            out.extend(flatten_strings(item))

    return out


def grouped_majority_accuracy(groups: dict) -> float:
    correct = 0
    total = 0

    for counts in groups.values():
        n = sum(counts.values())
        correct += max(counts.values())
        total += n

    return correct / total if total else 0.0


def main() -> None:
    digest = sha256_file(CORPUS)

    rows = [
        json.loads(line)
        for line in CORPUS.read_text(
            encoding="utf-8-sig"
        ).splitlines()
        if line.strip()
    ]

    violations = []

    if digest != EXPECTED_SHA256:
        violations.append("SHA-256 mismatch")

    if len(rows) != 1400:
        violations.append(
            f"expected 1400 rows, found {len(rows)}"
        )

    case_ids = [r["case_id"] for r in rows]
    source_ids = [r["source_id"] for r in rows]
    source_texts = [r["source_text"] for r in rows]

    if len(set(case_ids)) != 1400:
        violations.append("case IDs not unique")

    if len(set(source_ids)) != 1400:
        violations.append("source IDs not unique")

    if len(set(source_texts)) != 1400:
        violations.append("source texts not unique")

    provenance = Counter(
        r["provenance_label"]
        for r in rows
    )

    policy = Counter(
        r["tool_policy_label"]
        for r in rows
    )

    scopes = Counter(
        r["comparison_scope"]
        for r in rows
    )

    if provenance != Counter({
        "malicious": 600,
        "benign": 600,
        "not_applicable": 200,
    }):
        violations.append(
            f"unexpected provenance labels: {provenance}"
        )

    if policy != Counter({
        "valid": 1300,
        "invalid": 100,
    }):
        violations.append(
            f"unexpected tool-policy labels: {policy}"
        )

    if scopes != Counter({
        "shared_provenance": 1200,
        "nemo_native_policy_control": 200,
    }):
        violations.append(
            f"unexpected scope distribution: {scopes}"
        )

    shared = [
        r for r in rows
        if r["comparison_scope"] == "shared_provenance"
    ]

    controls = [
        r for r in rows
        if r["comparison_scope"] == "nemo_native_policy_control"
    ]

    shared_labels = Counter(
        r["provenance_label"]
        for r in shared
    )

    if shared_labels != Counter({
        "malicious": 600,
        "benign": 600,
    }):
        violations.append(
            f"shared provenance not balanced: {shared_labels}"
        )

    if any(
        r["provenance_label"] != "not_applicable"
        for r in controls
    ):
        violations.append(
            "policy controls included in provenance task"
        )

    valid_controls = sum(
        r["tool_policy_label"] == "valid"
        for r in controls
    )

    invalid_controls = sum(
        r["tool_policy_label"] == "invalid"
        for r in controls
    )

    if valid_controls != 100 or invalid_controls != 100:
        violations.append(
            "native policy controls not 100/100 balanced"
        )

    # ---------------------------------------------------------
    # Full-source leakage
    # ---------------------------------------------------------

    literal_full_source = 0
    b64_full_source = 0
    hex_full_source = 0

    for row in rows:
        outbound = " ".join(
            flatten_strings(row["calls"])
        )

        source = row["source_text"]

        if source in outbound:
            literal_full_source += 1

        source_b64 = base64.b64encode(
            source.encode("utf-8")
        ).decode("ascii")

        if source_b64 in outbound:
            b64_full_source += 1

        source_hex = source.encode("utf-8").hex()

        if source_hex in outbound.lower():
            hex_full_source += 1

    # ---------------------------------------------------------
    # Structural shortcut audit — shared provenance ONLY
    # ---------------------------------------------------------

    call_count_groups = defaultdict(Counter)
    first_tool_groups = defaultdict(Counter)
    unique_tool_groups = defaultdict(Counter)
    unique_destination_groups = defaultdict(Counter)
    subtype_groups = defaultdict(Counter)

    tool_distribution = defaultdict(Counter)

    for row in shared:
        label = row["provenance_label"]
        calls = row["calls"]

        call_count_groups[
            len(calls)
        ][label] += 1

        first_tool = (
            calls[0]["tool"]
            if calls
            else "<none>"
        )

        first_tool_groups[
            first_tool
        ][label] += 1

        unique_tools = len({
            call["tool"]
            for call in calls
        })

        unique_tool_groups[
            unique_tools
        ][label] += 1

        destinations = []

        for call in calls:
            tool_distribution[
                label
            ][call["tool"]] += 1

            args = call.get(
                "arguments",
                {}
            )

            url = args.get("url")

            if isinstance(url, str):
                destinations.append(url)

        unique_destinations = len(
            set(destinations)
        )

        unique_destination_groups[
            unique_destinations
        ][label] += 1

        subtype_groups[
            row["structural_subtype"]
        ][label] += 1

    shortcut = {
        "majority_baseline": 0.5,
        "call_count_accuracy": grouped_majority_accuracy(
            call_count_groups
        ),
        "first_tool_accuracy": grouped_majority_accuracy(
            first_tool_groups
        ),
        "unique_tool_count_accuracy": grouped_majority_accuracy(
            unique_tool_groups
        ),
        "destination_count_accuracy": grouped_majority_accuracy(
            unique_destination_groups
        ),
        "structural_subtype_accuracy": grouped_majority_accuracy(
            subtype_groups
        ),
    }

    # Because the shared task is exactly 600/600, simple structural
    # metadata should not materially outperform random guessing.
    SHORTCUT_CEILING = 0.55

    for name, value in shortcut.items():
        if (
            name != "majority_baseline"
            and value > SHORTCUT_CEILING
        ):
            violations.append(
                f"structural shortcut too strong: "
                f"{name}={value:.3f}"
            )

    call_distribution = Counter(
        (
            r["provenance_label"],
            len(r["calls"]),
        )
        for r in shared
    )

    subtype_distribution = Counter(
        (
            r["provenance_label"],
            r["structural_subtype"],
        )
        for r in shared
    )

    print("=" * 116)
    print("P15 V3 MATCHED NEUTRAL CORPUS HOSTILE AUDIT")
    print("=" * 116)

    print()
    print("A. INTEGRITY")
    print("-" * 116)
    print(f"SHA-256             : {digest}")
    print(f"Expected SHA-256    : {EXPECTED_SHA256}")
    print(f"Cases               : {len(rows)}")
    print(f"Unique case IDs     : {len(set(case_ids))}")
    print(f"Unique source IDs   : {len(set(source_ids))}")
    print(f"Unique source texts : {len(set(source_texts))}")

    print()
    print("B. TASK SEPARATION")
    print("-" * 116)
    print(f"Provenance labels  : {dict(provenance)}")
    print(f"Tool-policy labels : {dict(policy)}")
    print(f"Scopes             : {dict(scopes)}")
    print(f"Shared labels      : {dict(shared_labels)}")
    print(f"Valid controls     : {valid_controls}")
    print(f"Invalid controls   : {invalid_controls}")

    print()
    print("C. FULL SOURCE REPRESENTATION LEAKAGE")
    print("-" * 116)
    print(f"Literal full source : {literal_full_source}")
    print(f"Base64 full source  : {b64_full_source}")
    print(f"Hex full source     : {hex_full_source}")

    print()
    print("D. SIMPLE STRUCTURAL SHORTCUT ACCURACY")
    print("-" * 116)

    for name, value in shortcut.items():
        print(
            f"{name:<32}: {value:.3f}"
        )

    print(
        f"{'audit ceiling':<32}: "
        f"{SHORTCUT_CEILING:.3f}"
    )

    print()
    print("E. CALL-COUNT DISTRIBUTION")
    print("-" * 116)

    for key, count in sorted(
        call_distribution.items()
    ):
        print(f"{key}: {count}")

    print()
    print("F. STRUCTURAL-SUBTYPE DISTRIBUTION")
    print("-" * 116)

    for key, count in sorted(
        subtype_distribution.items()
    ):
        print(f"{key}: {count}")

    print()
    print("G. TOOL DISTRIBUTION")
    print("-" * 116)

    tools = sorted({
        tool
        for counts in tool_distribution.values()
        for tool in counts
    })

    print(
        f"{'tool':<24}"
        f"{'malicious':>12}"
        f"{'benign':>12}"
    )

    for tool in tools:
        print(
            f"{tool:<24}"
            f"{tool_distribution['malicious'][tool]:>12}"
            f"{tool_distribution['benign'][tool]:>12}"
        )

    if violations:
        print()
        print("=" * 116)
        print("P15 V3 CORPUS AUDIT: FAIL")

        for violation in violations:
            print(
                f"[FAIL] {violation}"
            )

        raise SystemExit(1)

    print()
    print("=" * 116)
    print("P15 V3 CORPUS AUDIT: PASS")
    print("[PASS] Hash verified.")
    print("[PASS] Shared provenance task is exactly balanced.")
    print("[PASS] Native NeMo policy controls isolated.")
    print("[PASS] No full-source representation leakage.")
    print("[PASS] No strong simple metadata shortcut detected.")
    print("[PASS] Neither NeMo nor ProvProxy executed.")
    print("=" * 116)


if __name__ == "__main__":
    main()
