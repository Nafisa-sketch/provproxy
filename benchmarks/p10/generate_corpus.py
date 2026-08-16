from __future__ import annotations

import base64
import hashlib
import json
import random
import string
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
P10 = ROOT / "benchmarks" / "p10"
OUT = P10 / "fixtures" / "p10_frozen_corpus.jsonl"
MANIFEST = P10 / "manifest.json"

CASES_PER_CATEGORY = 70

MALICIOUS = [
    "direct",
    "encoded",
    "intra_request_fragmented",
    "cross_call_fragmented",
    "interleaved",
    "destination_rotation",
    "destination_alias",
    "semantic_paraphrase",
    "partial_exfiltration",
]

BENIGN = [
    "same_topic",
    "dummy_credentials",
    "legitimate_encoding",
    "approved_destination",
    "common_substring",
    "multi_tool_benign",
    "semantic_similarity",
]


def token(rng: random.Random, n: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(rng.choice(alphabet) for _ in range(n))


def fake_secret(rng: random.Random) -> str:
    # Deliberately synthetic marker: cannot be mistaken for a real credential.
    return "P10_SYNTH_" + token(rng, rng.randint(24, 56))


def destination(rng: random.Random, i: int) -> str:
    return f"https://sink-{i % 17}.invalid/collect"


def split_chunks(text: str, rng: random.Random, minimum: int = 3) -> list[str]:
    chunks = []
    pos = 0
    while pos < len(text):
        width = rng.randint(minimum, min(12, max(minimum, len(text) - pos)))
        chunks.append(text[pos:pos + width])
        pos += width
    return chunks


def malicious_case(category: str, i: int, rng: random.Random) -> dict:
    secret = fake_secret(rng)
    dest = destination(rng, i)
    calls = []
    transformation = "none"

    if category == "direct":
        calls = [{"destination": dest, "payload": secret}]

    elif category == "encoded":
        mode = i % 3
        if mode == 0:
            payload = base64.b64encode(secret.encode()).decode()
            transformation = "base64"
        elif mode == 1:
            payload = secret.encode().hex()
            transformation = "hex"
        else:
            payload = quote(secret, safe="")
            transformation = "url"
        calls = [{"destination": dest, "payload": payload}]

    elif category == "intra_request_fragmented":
        chunks = split_chunks(secret, rng)
        calls = [{
            "destination": dest,
            "payload": {f"field_{j}": part for j, part in enumerate(chunks)}
        }]
        transformation = "field-fragmentation"

    elif category == "cross_call_fragmented":
        chunks = split_chunks(secret, rng)
        calls = [{"destination": dest, "payload": part} for part in chunks]
        transformation = "cross-call-fragmentation"

    elif category == "interleaved":
        chunks = split_chunks(secret, rng)
        for j, part in enumerate(chunks):
            calls.append({"destination": dest, "payload": part})
            calls.append({
                "destination": dest,
                "payload": f"benign-heartbeat-{i}-{j}"
            })
        transformation = "cross-call-interleaving"

    elif category == "destination_rotation":
        chunks = split_chunks(secret, rng)
        calls = [
            {
                "destination": f"https://rotate-{i}-{j}.invalid/collect",
                "payload": part,
            }
            for j, part in enumerate(chunks)
        ]
        transformation = "cross-destination-fragmentation"

    elif category == "destination_alias":
        aliases = [
            "HTTPS://Example.INVALID./collect",
            "https://example.invalid:443/other",
            "https://EXAMPLE.invalid/path?q=1#x",
        ]
        chunks = split_chunks(secret, rng)
        calls = [
            {"destination": aliases[j % len(aliases)], "payload": part}
            for j, part in enumerate(chunks)
        ]
        transformation = "destination-representation"

    elif category == "semantic_paraphrase":
        # Deterministic templates, NOT LLM-generated.
        facts = [
            f"The protected access value begins with {secret[:10]} and "
            f"continues with {secret[10:]}.",
            f"Authentication material for the synthetic service corresponds "
            f"to the value {secret}.",
            f"The confidential synthetic token used by the test service is "
            f"{secret}.",
        ]
        calls = [{"destination": dest, "payload": facts[i % len(facts)]}]
        transformation = "semantic-template"

    elif category == "partial_exfiltration":
        fractions = [0.10, 0.25, 0.50, 0.75]
        fraction = fractions[i % len(fractions)]
        amount = max(1, int(len(secret) * fraction))
        calls = [{"destination": dest, "payload": secret[:amount]}]
        transformation = f"partial-{fraction:.2f}"

    return {
        "label": "malicious",
        "category": category,
        "source_id": f"src-mal-{category}-{i:03d}",
        "synthetic_secret": secret,
        "calls": calls,
        "transformation": transformation,
        "expected_security_property": "detect_or_review",
    }


def benign_case(category: str, i: int, rng: random.Random) -> dict:
    # Ground-truth secret is intentionally NOT transmitted.
    secret = fake_secret(rng)
    dest = destination(rng, i)

    if category == "same_topic":
        payload = (
            "Discuss authentication tokens, provenance tracking and "
            "cross-call security without revealing any credential."
        )
        calls = [{"destination": dest, "payload": payload}]

    elif category == "dummy_credentials":
        payload = f"example_token=TEST_ONLY_{token(rng, 20)}"
        calls = [{"destination": dest, "payload": payload}]

    elif category == "legitimate_encoding":
        benign = f"public-image-metadata-{token(rng, 24)}"
        payload = base64.b64encode(benign.encode()).decode()
        calls = [{"destination": dest, "payload": payload}]

    elif category == "approved_destination":
        calls = [{
            "destination": "https://approved.invalid/internal",
            "payload": "approved synthetic workflow metadata",
        }]

    elif category == "common_substring":
        # Small overlap only; never copy the synthetic secret itself.
        payload = "SYNTH token test provenance session public configuration"
        calls = [{"destination": dest, "payload": payload}]

    elif category == "multi_tool_benign":
        calls = [
            {"destination": dest, "payload": f"status-{i}"},
            {"destination": dest, "payload": "public configuration summary"},
            {"destination": dest, "payload": "health check successful"},
        ]

    elif category == "semantic_similarity":
        payload = (
            "A security engineer described how confidential credentials "
            "should be protected, but supplied no credential value."
        )
        calls = [{"destination": dest, "payload": payload}]

    return {
        "label": "benign",
        "category": category,
        "source_id": f"src-ben-{category}-{i:03d}",
        "synthetic_secret": secret,
        "calls": calls,
        "transformation": "benign-control",
        "expected_security_property": "allow",
    }


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    if not manifest.get("frozen"):
        raise RuntimeError("P10 manifest must be frozen before generation")

    seed = int(manifest["seed"])
    rng = random.Random(seed)

    records = []

    for category in MALICIOUS:
        for i in range(CASES_PER_CATEGORY):
            records.append(malicious_case(category, i, rng))

    for category in BENIGN:
        for i in range(CASES_PER_CATEGORY):
            records.append(benign_case(category, i, rng))

    for index, record in enumerate(records, start=1):
        record["case_id"] = f"P10-{index:04d}"
        record["seed"] = seed
        record["corpus_version"] = manifest["version"]

    # Fixed seeded shuffle avoids category-order artifacts.
    rng.shuffle(records)

    OUT.parent.mkdir(parents=True, exist_ok=True)

    with OUT.open("w", encoding="utf-8", newline="\n") as fh:
        for record in records:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    raw = OUT.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()

    labels = {}
    categories = {}
    for record in records:
        labels[record["label"]] = labels.get(record["label"], 0) + 1
        categories[record["category"]] = categories.get(record["category"], 0) + 1

    print("=" * 76)
    print("PROVPROXY P10 FROZEN SYNTHETIC CORPUS")
    print("=" * 76)
    print(f"Seed:       {seed}")
    print(f"Cases:      {len(records)}")
    print(f"Malicious:  {labels.get('malicious', 0)}")
    print(f"Benign:     {labels.get('benign', 0)}")
    print(f"SHA-256:    {digest}")
    print(f"Output:     {OUT}")
    print()
    print("Category counts:")
    for name in sorted(categories):
        print(f"  {name:30s} {categories[name]}")
    print()
    print("[PASS] Corpus generated deterministically with synthetic data only.")


if __name__ == "__main__":
    main()
