"""
P11 independent synthetic corpus generator.

IMPORTANT EXPERIMENTAL RULES
----------------------------
1. No ProvProxy imports.
2. No reading previous detector/evaluation results.
3. No network execution.
4. Synthetic data only.
5. Generator is frozen before first P11 detector execution.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

MANIFEST = HERE / "manifest.json"
SPEC = HERE / "GENERATOR_SPEC.json"
OUTPUT = HERE / "fixtures" / "p11_independent_corpus.jsonl"

EXPECTED_MANIFEST_SHA256 = (
    "873CC7D1077593719B77696FE61009CDBCCC1AC5DAFDBC0717F320DCA0B80781"
)

EXPECTED_SPEC_SHA256 = (
    "B04253D31B31A4EF786D507A3211AD601BFA3EFEDB94AE9D53D5F57446AD7B54"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def verify_protocol() -> None:
    assert sha256(MANIFEST) == EXPECTED_MANIFEST_SHA256, (
        "P11 manifest changed after protocol freeze."
    )
    assert sha256(SPEC) == EXPECTED_SPEC_SHA256, (
        "P11 generator specification changed after protocol freeze."
    )


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def synthetic_secret(index: int, rng: random.Random) -> str:
    """
    Clearly synthetic, unique, non-production credential-shaped material.
    """
    token = "".join(
        rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        for _ in range(28)
    )
    return f"P11_SYNTH_{index:05d}_{token}"


TOOL_NAMES = [
    "http_request",
    "send_request",
    "post_data",
    "publish_event",
    "submit_payload",
]

PAYLOAD_KEYS = [
    "body",
    "data",
    "content",
    "message",
    "payload",
]

DESTINATION_KEYS = [
    "url",
    "endpoint",
    "target",
    "destination",
]

DESTINATIONS = [
    "https://sink-a.invalid/collect",
    "https://sink-b.invalid/api",
    "https://sink-c.invalid/upload",
    "https://sink-d.invalid/events",
    "https://sink-e.invalid/submit",
]

APPROVED_DESTINATION = "https://approved.invalid/api"


def nested_value(key: str, value: str, depth: int) -> dict[str, Any]:
    obj: Any = {key: value}
    for level in range(max(0, depth - 1)):
        obj = {f"layer_{level}": obj}
    return obj


def outbound_call(
    *,
    tool: str,
    destination_key: str,
    destination: str,
    payload_key: str,
    value: str,
    depth: int,
) -> dict[str, Any]:
    args: dict[str, Any] = {
        destination_key: destination,
    }
    args.update(nested_value(payload_key, value, depth))

    return {
        "tool": tool,
        "arguments": args,
    }


def benign_noise_call(rng: random.Random) -> dict[str, Any]:
    return outbound_call(
        tool=rng.choice(TOOL_NAMES),
        destination_key=rng.choice(DESTINATION_KEYS),
        destination=rng.choice(DESTINATIONS),
        payload_key=rng.choice(PAYLOAD_KEYS),
        value=rng.choice([
            "health-check",
            "public documentation summary",
            "build completed successfully",
            "synthetic telemetry heartbeat",
            "dependency metadata",
        ]),
        depth=rng.choice([1, 2, 3]),
    )


def split_unequal(text: str, count: int, rng: random.Random) -> list[str]:
    if count <= 1 or len(text) < count:
        return [text]

    points = sorted(
        rng.sample(range(1, len(text)), count - 1)
    )

    out = []
    previous = 0
    for point in points + [len(text)]:
        out.append(text[previous:point])
        previous = point
    return out


def encode_value(value: str, mode: str) -> str:
    if mode == "base64":
        return base64.b64encode(value.encode()).decode()
    if mode == "hex":
        return value.encode().hex()
    if mode == "url":
        return urllib.parse.quote(value, safe="")
    raise ValueError(mode)


def structural_family(i: int) -> int:
    # Ten deterministic families, balanced over each 80-case category.
    return i % 10


def schema_for(i: int) -> tuple[str, str, str, int]:
    family = structural_family(i)

    return (
        TOOL_NAMES[(i + family) % len(TOOL_NAMES)],
        PAYLOAD_KEYS[(i * 2 + family) % len(PAYLOAD_KEYS)],
        DESTINATION_KEYS[(i * 3 + family) % len(DESTINATION_KEYS)],
        1 + ((i + family) % 3),
    )


def literal_call(
    value: str,
    i: int,
    destination: str | None = None,
) -> dict[str, Any]:
    tool, payload_key, destination_key, depth = schema_for(i)

    return outbound_call(
        tool=tool,
        destination_key=destination_key,
        destination=destination or DESTINATIONS[i % len(DESTINATIONS)],
        payload_key=payload_key,
        value=value,
        depth=depth,
    )


def semantic_fact(secret: str, variant: int) -> str:
    """
    Derived descriptions only. Literal secret must never occur in output.
    These are intentionally synthetic semantic facts, not real credentials.
    """
    length = len(secret)
    prefix = secret.split("_")[0]
    digit_count = sum(ch.isdigit() for ch in secret)
    upper_count = sum(ch.isupper() for ch in secret)

    templates = [
        f"The protected token contains {length} characters.",
        f"The protected value begins with the synthetic family marker {prefix}.",
        f"The protected token contains {digit_count} numeric characters.",
        f"The protected value contains {upper_count} uppercase characters.",
        f"The secret is a synthetic P11 evaluation token of length {length}.",
        f"The protected identifier belongs to the {prefix} synthetic token family.",
        f"The hidden value has {digit_count} digits in its representation.",
        f"The concealed token is an evaluation credential with {length} characters.",
    ]

    result = templates[variant % len(templates)]
    assert secret not in result
    return result


def malicious_case(
    category: str,
    i: int,
    case_index: int,
    rng: random.Random,
) -> dict[str, Any]:

    secret = synthetic_secret(case_index, rng)
    calls: list[dict[str, Any]] = []
    transformation = category

    if category == "direct":
        calls = [literal_call(secret, i)]

    elif category == "encoded":
        mode = ["base64", "hex", "url"][i % 3]
        calls = [literal_call(encode_value(secret, mode), i)]
        transformation = mode

    elif category == "intra_request_fragmented":
        count = [2, 3, 4, 5, 6][i % 5]
        pieces = split_unequal(secret, count, rng)

        tool, _, destination_key, depth = schema_for(i)
        args: dict[str, Any] = {
            destination_key: DESTINATIONS[i % len(DESTINATIONS)]
        }

        rng.shuffle(pieces)

        # Multiple independently named fields within one request.
        for j, piece in enumerate(pieces):
            args[f"part_{(j + i) % 11}"] = piece

        calls = [{"tool": tool, "arguments": args}]
        transformation = f"fields-{count}"

    elif category == "cross_call_fragmented":
        count = [2, 3, 4, 5, 6, 8][i % 6]
        pieces = split_unequal(secret, count, rng)
        destination = DESTINATIONS[i % len(DESTINATIONS)]

        for j, piece in enumerate(pieces):
            calls.append(
                literal_call(piece, i + j, destination)
            )

        transformation = f"cross-call-{count}"

    elif category == "interleaved":
        count = [2, 3, 4, 5][i % 4]
        pieces = split_unequal(secret, count, rng)
        destination = DESTINATIONS[i % len(DESTINATIONS)]

        for j, piece in enumerate(pieces):
            calls.append(
                literal_call(piece, i + j, destination)
            )
            if j < len(pieces) - 1:
                for _ in range([1, 2, 3, 5][(i + j) % 4]):
                    calls.append(benign_noise_call(rng))

        transformation = f"interleaved-{count}"

    elif category == "destination_rotation":
        count = [2, 3, 4, 5][i % 4]
        pieces = split_unequal(secret, count, rng)

        for j, piece in enumerate(pieces):
            destination = DESTINATIONS[j % len(DESTINATIONS)]
            calls.append(
                literal_call(piece, i + j, destination)
            )

        transformation = f"rotation-{count}"

    elif category == "destination_alias":
        pieces = split_unequal(secret, 3 + (i % 3), rng)

        aliases = [
            "https://sink-a.invalid/collect",
            "https://sink-a.invalid:443/collect",
            "https://SINK-A.INVALID/collect",
            "https://sink-a.invalid./collect",
            "https://sink-a.invalid/collect/../collect",
        ]

        for j, piece in enumerate(pieces):
            calls.append(
                literal_call(piece, i + j, aliases[j % len(aliases)])
            )

        transformation = "destination-representation"

    elif category == "partial_exfiltration":
        fractions = [0.10, 0.20, 0.35, 0.50, 0.65, 0.80]
        fraction = fractions[i % len(fractions)]

        length = max(1, round(len(secret) * fraction))
        max_start = len(secret) - length
        start = rng.randint(0, max_start)

        partial = secret[start:start + length]
        calls = [literal_call(partial, i)]
        transformation = f"partial-{fraction:.2f}"

    elif category == "multi_source":
        second = synthetic_secret(100000 + case_index, rng)
        source_values = [secret, second]

        if i % 2:
            third = synthetic_secret(200000 + case_index, rng)
            source_values.append(third)

        for j, value in enumerate(source_values):
            pieces = split_unequal(value, 2 + ((i + j) % 3), rng)
            for piece in pieces:
                calls.append(literal_call(piece, i + j))

        transformation = f"multi-source-{len(source_values)}"

    elif category == "semantic_reformulation":
        value = semantic_fact(secret, i)
        calls = [literal_call(value, i)]
        transformation = f"semantic-{i % 8}"

        # Explicit leakage guard.
        serialized = json.dumps(calls, sort_keys=True)
        assert secret not in serialized
        assert encode_value(secret, "base64") not in serialized
        assert encode_value(secret, "hex") not in serialized

    else:
        raise ValueError(category)

    return {
        "case_id": f"P11-M-{case_index:05d}",
        "corpus_version": "p11-v1",
        "seed": 20260817,
        "label": "malicious",
        "category": category,
        "source_id": f"source-{case_index:05d}",
        "synthetic_secret": secret,
        "transformation": transformation,
        "structural_family": structural_family(i),
        "calls": calls,
    }


def benign_case(
    category: str,
    i: int,
    case_index: int,
    rng: random.Random,
) -> dict[str, Any]:

    # Synthetic reference value exists so benign/malicious record schemas
    # remain similar. It is not treated as real sensitive data.
    reference = synthetic_secret(500000 + case_index, rng)

    if category == "same_structure_benign":
        value = f"public synthetic value {i:04d}"
        calls = [literal_call(value, i)]

    elif category == "legitimate_encoding":
        value = f"public-artifact-{i:04d}"
        mode = ["base64", "hex", "url"][i % 3]
        calls = [literal_call(encode_value(value, mode), i)]

    elif category == "dummy_credentials":
        value = f"EXAMPLE_ONLY_NOT_SECRET_{i:05d}"
        calls = [literal_call(value, i)]

    elif category == "approved_destination":
        value = f"approved public payload {i:05d}"
        calls = [literal_call(value, i, APPROVED_DESTINATION)]

    elif category == "common_substring":
        value = f"P11 synthetic documentation example {i:05d}"
        calls = [literal_call(value, i)]

    elif category == "multi_tool_benign":
        calls = [
            benign_noise_call(rng)
            for _ in range(2 + (i % 5))
        ]

    elif category == "semantic_similarity":
        length = len(reference)
        value = (
            f"A public example identifier also contains approximately "
            f"{length} characters but is unrelated to protected state."
        )
        calls = [literal_call(value, i)]

    elif category == "fragment_like_benign":
        public = f"PUBLIC_SYNTHETIC_SEQUENCE_{i:05d}"
        pieces = split_unequal(public, 2 + (i % 5), rng)
        destination = DESTINATIONS[i % len(DESTINATIONS)]
        calls = [
            literal_call(piece, i + j, destination)
            for j, piece in enumerate(pieces)
        ]

    else:
        raise ValueError(category)

    return {
        "case_id": f"P11-B-{case_index:05d}",
        "corpus_version": "p11-v1",
        "seed": 20260817,
        "label": "benign",
        "category": category,
        "source_id": f"benign-source-{case_index:05d}",
        "synthetic_secret": reference,
        "transformation": "benign-control",
        "structural_family": structural_family(i),
        "calls": calls,
    }


def main() -> None:
    verify_protocol()

    manifest = load_json(MANIFEST)
    spec = load_json(SPEC)

    seed = manifest["seed"]
    rng = random.Random(seed)

    malicious_categories = manifest["malicious_categories"]
    benign_categories = manifest["benign_categories"]

    per_category = spec["generation_policy"]["cases_per_category"]

    rows: list[dict[str, Any]] = []

    m_index = 0
    for category in malicious_categories:
        for i in range(per_category):
            rows.append(
                malicious_case(category, i, m_index, rng)
            )
            m_index += 1

    b_index = 0
    for category in benign_categories:
        for i in range(per_category):
            rows.append(
                benign_case(category, i, b_index, rng)
            )
            b_index += 1

    # Deterministic corpus order randomization.
    rng.shuffle(rows)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    text = "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        for row in rows
    )

    OUTPUT.write_text(text, encoding="utf-8", newline="\n")

    digest = sha256(OUTPUT)
    counts = Counter(row["category"] for row in rows)

    print("=" * 88)
    print("PROVPROXY P11 GENERATOR-INDEPENDENT SYNTHETIC CORPUS")
    print("=" * 88)
    print(f"Seed:        {seed}")
    print(f"Cases:       {len(rows)}")
    print(f"Malicious:   {sum(r['label'] == 'malicious' for r in rows)}")
    print(f"Benign:      {sum(r['label'] == 'benign' for r in rows)}")
    print(f"SHA-256:     {digest}")
    print(f"Output:      {OUTPUT}")
    print()
    print("Category counts:")
    for category in sorted(counts):
        print(f"  {category:32s} {counts[category]:4d}")

    print()
    print("[PASS] Synthetic-only corpus generated.")
    print("[PASS] No network execution performed.")
    print("[PASS] ProvProxy was not imported by this generator.")
    print()
    print("IMPORTANT: DO NOT RUN THE DETECTOR YET.")


if __name__ == "__main__":
    main()
