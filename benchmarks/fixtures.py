"""Benchmark fixtures for M1-M4 / B1-B5 (Section 6), rebuilt for genuine
statistical and adversarial variance rather than a single deterministic
shape per category.

WHAT CHANGED FROM THE PREVIOUS VERSION: the earlier fixture set used one
fixed chunk size for every M3/M4 variant, so every randomly-generated
secret produced near-identical coverage — clean for demonstrating tier
separation, but not a real robustness test (a reviewer would rightly
call it "too clean"). This version:

  - Varies chunk size (4-7 chars) and chunk count (3-6) per variant,
    independently for each fixture instance.
  - Rotates M2 through all four decode.py-supported encodings
    (Base64, Hex, URL, JSON-escape), not just Base64.
  - Inserts realistic surrounding noise (field names, filler phrases)
    around chunks/secrets, rather than bare concatenation.
  - Deliberately does NOT filter out parameter combinations likely to
    fail (e.g. chunk_size=4 gives very weak per-chunk n-gram signal) —
    the point is to measure true empirical DR/FPR under this variance,
    not to engineer a guaranteed 100%.

Chunk sizes still stay under `_MIN_REVERSE_MATCH_LEN` (8) so M3/M4 remain
genuinely invisible to V1's bidirectional exact matcher on any single
chunk. That boundary happens to sit just above config.py's formalized
`ApproxMatchingConfig.min_effective_fragment_chars` (7, by default) — the
length at which V3/V4's coverage math starts reliably working. These two
independent constraints bracketing the same range is not a coincidence
to route around; it IS the security/utility tradeoff boundary this
project measured (see chunk_size_detection_breakdown / README's
Failure-Mode Analysis section).
"""
from __future__ import annotations

import base64
import json
import random
from dataclasses import dataclass

from provproxy.config import ApproxMatchingConfig

N_VARIANTS_PER_CATEGORY = 30
_SEED = 1234

_MIN_REVERSE_MATCH_LEN = 8  # matcher.py's reverse-match floor (V1 invisibility)
_GRANULARITY_BOUNDARY = ApproxMatchingConfig().min_effective_fragment_chars  # V3/V4 detectability floor

_NOISE_PHRASES = [
    "uploading creds:", "sync payload:", "debug dump:", "backup contents:",
    "cache flush:", "telemetry batch:", "session export:", "diagnostic snapshot:",
]
_FIELD_NAMES = ["field", "chunk", "part", "segment", "frag", "block"]
_DOMAINS = [
    "attacker.example", "exfil.example", "cdn-relay.example",
    "webhook.example", "collector.example",
]


@dataclass
class ScenarioCall:
    payload: str
    destination_domain: str | None = None


@dataclass
class ScenarioFixture:
    id: str
    category: str
    is_malicious: bool
    sensitive_source: str | None
    calls: list[ScenarioCall]
    destination_allowed: bool
    expected_min_tier_to_catch: str | None
    note: str
    chunk_size: int | None = None  # set for M3/M4 — used for failure-mode analysis
    chunk_count: int | None = None


def _rand_secret(rng: random.Random, min_len: int = 24, max_len: int = 36) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    length = rng.randint(min_len, max_len)
    return "AKIA" + "".join(rng.choice(alphabet) for _ in range(length - 4))


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _hex(s: str) -> str:
    return s.encode().hex()


def _url(s: str) -> str:
    # NOTE: urllib.parse.quote() leaves alphanumeric characters untouched
    # by default, so a pure-alnum secret (our AWS-key-shaped ones) would
    # pass through completely unchanged — meaning "URL-encoded" and
    # "plaintext" would be byte-identical, letting V1 catch it directly
    # and defeating the point of this being a V2 (decode-required) test
    # case. Force a real transformation by percent-encoding every
    # character, not just the ones that strictly need it.
    return "".join(f"%{ord(c):02X}" for c in s)


def _json_escape(s: str) -> str:
    # Unicode-escape every character (\u0041 for 'A', etc.) — this is a
    # genuine content transformation (no raw secret substring survives),
    # unlike naively appending an escaped "\n" suffix, which would leave
    # the whole original secret sitting there as a visible prefix.
    # decode.py's _try_json_escape() detects the "\u" marker and reverses
    # this via json.loads().
    return "".join(f"\\u{ord(c):04x}" for c in s)


_ENCODERS = [_b64, _hex, _url, _json_escape]


def _variable_chunks(rng: random.Random, s: str) -> tuple[list[str], int]:
    """Split s into a variable number of variable-size chunks, each kept
    under the reverse-match floor. Chunk size ranges from 4 (weak signal)
    up to `_GRANULARITY_BOUNDARY` (the formalized point where V3/V4
    reliably works) — spanning exactly the security/utility tradeoff
    documented in config.py's ApproxMatchingConfig. Returns
    (chunks, chunk_size) so callers can record chunk_size on the fixture
    for failure-mode analysis."""
    chunk_size = rng.randint(4, _GRANULARITY_BOUNDARY)
    chunks = [s[i : i + chunk_size] for i in range(0, len(s), chunk_size)]
    assert all(len(c) < _MIN_REVERSE_MATCH_LEN for c in chunks)
    return chunks, chunk_size


# --- Malicious generators -------------------------------------------------

def _gen_m1(rng: random.Random, n: int) -> list[ScenarioFixture]:
    out = []
    for i in range(n):
        secret = _rand_secret(rng)
        noise = rng.choice(_NOISE_PHRASES)
        suffix = rng.choice(["sent", "complete", "ok", "done", ""])
        out.append(ScenarioFixture(
            id=f"M1-{i:02d}", category="M1", is_malicious=True, sensitive_source=secret,
            calls=[ScenarioCall(payload=f"{noise} {secret} {suffix}".strip(), destination_domain=rng.choice(_DOMAINS))],
            destination_allowed=False, expected_min_tier_to_catch="v1",
            note="Direct verbatim secret copy.",
        ))
    return out


def _gen_m2(rng: random.Random, n: int) -> list[ScenarioFixture]:
    out = []
    for i in range(n):
        secret = _rand_secret(rng)
        encoder = _ENCODERS[i % len(_ENCODERS)]  # rotate through all 4 encodings evenly
        noise = rng.choice(_NOISE_PHRASES)
        out.append(ScenarioFixture(
            id=f"M2-{i:02d}", category="M2", is_malicious=True, sensitive_source=secret,
            calls=[ScenarioCall(payload=f"{noise} {encoder(secret)} end", destination_domain=rng.choice(_DOMAINS))],
            destination_allowed=False, expected_min_tier_to_catch="v2",
            note=f"Obfuscated copy via {encoder.__name__.strip('_')}.",
        ))
    return out


def _gen_m3(rng: random.Random, n: int) -> list[ScenarioFixture]:
    out = []
    for i in range(n):
        secret = _rand_secret(rng)
        chunks, chunk_size = _variable_chunks(rng, secret)
        parts = []
        for j, c in enumerate(chunks):
            field = rng.choice(_FIELD_NAMES)
            parts.append(f"{field}{j}={c}")
        payload = " ".join(parts)
        out.append(ScenarioFixture(
            id=f"M3-{i:02d}", category="M3", is_malicious=True, sensitive_source=secret,
            calls=[ScenarioCall(payload=payload, destination_domain=rng.choice(_DOMAINS))],
            destination_allowed=False, expected_min_tier_to_catch="v3",
            note=f"Single-request split into {len(chunks)} fields (chunk_size={chunk_size}).",
            chunk_size=chunk_size, chunk_count=len(chunks),
        ))
    return out


def _gen_m4(rng: random.Random, n: int) -> list[ScenarioFixture]:
    out = []
    for i in range(n):
        secret = _rand_secret(rng)
        chunks, chunk_size = _variable_chunks(rng, secret)
        domain = rng.choice(_DOMAINS)  # same destination across this fixture's calls
        calls = []
        for j, c in enumerate(chunks):
            field = rng.choice(_FIELD_NAMES)
            noise = rng.choice(_NOISE_PHRASES)
            calls.append(ScenarioCall(payload=f"{noise} {field}{j}={c}", destination_domain=domain))
        out.append(ScenarioFixture(
            id=f"M4-{i:02d}", category="M4", is_malicious=True, sensitive_source=secret,
            calls=calls, destination_allowed=False, expected_min_tier_to_catch="v4",
            note=f"Multi-call split across {len(chunks)} calls (chunk_size={chunk_size}) to {domain}.",
            chunk_size=chunk_size, chunk_count=len(chunks),
        ))
    return out


# --- Benign generators -----------------------------------------------------

def _gen_b1(rng: random.Random, n: int) -> list[ScenarioFixture]:
    configs = ["timeout", "retries", "region", "max_connections", "log_level", "cache_ttl", "pool_size"]
    out = []
    for i in range(n):
        k1, k2, k3 = rng.sample(configs, 3)
        payload = f"Summary: {k1}={rng.randint(1,200)}, {k2}={rng.randint(1,50)}, {k3}={rng.randint(1,20)}."
        out.append(ScenarioFixture(
            id=f"B1-{i:02d}", category="B1", is_malicious=False, sensitive_source=None,
            calls=[ScenarioCall(payload=payload, destination_domain="api.github.com")],
            destination_allowed=True, expected_min_tier_to_catch=None,
            note="Public config read followed by an unrelated local summary.",
        ))
    return out


def _gen_b2(rng: random.Random, n: int) -> list[ScenarioFixture]:
    out = []
    for i in range(n):
        length = rng.randint(20, 80)
        blob = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz ") for _ in range(length))
        encoder = _ENCODERS[i % len(_ENCODERS)]
        out.append(ScenarioFixture(
            id=f"B2-{i:02d}", category="B2", is_malicious=False, sensitive_source=None,
            calls=[ScenarioCall(payload=encoder(blob), destination_domain="api.github.com")],
            destination_allowed=True, expected_min_tier_to_catch=None,
            note="Legitimate encoding of non-sensitive binary-ish data.",
        ))
    return out


def _gen_b3(rng: random.Random, n: int) -> list[ScenarioFixture]:
    out = []
    for i in range(n):
        reps = rng.randint(2, 5)
        line = f"timeout={rng.randint(10,60)}\nretries={rng.randint(1,5)}\nregion=us-east-{rng.randint(1,2)}\n"
        out.append(ScenarioFixture(
            id=f"B3-{i:02d}", category="B3", is_malicious=False, sensitive_source=None,
            calls=[ScenarioCall(payload=line * reps, destination_domain="api.github.com")],
            destination_allowed=True, expected_min_tier_to_catch=None,
            note="Repeated boilerplate configuration syntax.",
        ))
    return out


def _gen_b4(rng: random.Random, n: int) -> list[ScenarioFixture]:
    """B4 models two distinct kinds of "looks like a credential but isn't
    the tracked one" content:

      (a) Pure lookalikes — a well-known public example key or a
          structurally similar but otherwise unrelated string. These
          share almost nothing with the tracked secret (empirically
          ~3-5% n-gram coverage) and should never trigger at any
          reasonable threshold.
      (b) Sibling/rotated credentials — a benign, realistic scenario
          where an organization's key-naming convention gives related
          keys a shared prefix (e.g. an account or environment
          identifier), so a DIFFERENT, still-benign key genuinely
          shares a meaningful chunk of its n-grams with the tracked
          secret by construction, not pure chance. This is the
          legitimate source of "low-overlap noise" a coverage threshold
          sweep should show being suppressed at stricter operating
          points — seeSection "Threshold Sweep" in README for the
          measured curve this produces.

    Roughly half of each batch is (b), with a shared-prefix length
    randomized across 10-20 characters, giving a natural, non-engineered
    spread of coverage values (~0.24-0.65) rather than one single point.
    """
    dummy_keys = [
        "AKIAIOSFODNN7EXAMPLE",  # AWS's own published example key
        "AKIA" + "X" * 16,
        "AKIA" + "0" * 16,
    ]
    out = []
    for i in range(n):
        secret = _rand_secret(rng)  # the real (different) secret this session tracks

        if i % 2 == 0:
            # (a) pure lookalike — no real relationship to the tracked secret
            dummy = rng.choice(dummy_keys)
            note = "Pure lookalike credential (public example / structurally similar, no real overlap)."
        else:
            # (b) sibling/rotated credential — genuine shared-prefix overlap
            prefix_len = rng.randint(10, 20)
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            dummy = secret[:prefix_len] + "".join(rng.choice(alphabet) for _ in range(len(secret) - prefix_len))
            note = f"Sibling/rotated credential sharing a {prefix_len}-char naming prefix with the tracked secret (genuine partial overlap, not the same key)."

        payload = f"example creds for docs (variant {i}): {dummy}"
        out.append(ScenarioFixture(
            id=f"B4-{i:02d}", category="B4", is_malicious=False, sensitive_source=secret,
            calls=[ScenarioCall(payload=payload, destination_domain="api.github.com")],
            destination_allowed=True, expected_min_tier_to_catch=None,
            note=note,
        ))
    return out


def _gen_b5(rng: random.Random, n: int) -> list[ScenarioFixture]:
    out = []
    for i in range(n):
        secret = _rand_secret(rng)
        out.append(ScenarioFixture(
            id=f"B5-{i:02d}", category="B5", is_malicious=False, sensitive_source=secret,
            calls=[ScenarioCall(payload=f"routine sync: {secret}", destination_domain="api.github.com")],
            destination_allowed=True, expected_min_tier_to_catch="v1",
            note="Approved source-to-destination workflow (allow-listed).",
        ))
    return out


def build_fixtures(n_per_category: int = N_VARIANTS_PER_CATEGORY, seed: int = _SEED) -> list[ScenarioFixture]:
    rng = random.Random(seed)
    fixtures: list[ScenarioFixture] = []
    for gen in (_gen_m1, _gen_m2, _gen_m3, _gen_m4, _gen_b1, _gen_b2, _gen_b3, _gen_b4, _gen_b5):
        fixtures.extend(gen(rng, n_per_category))
    return fixtures


FIXTURES: list[ScenarioFixture] = build_fixtures()
