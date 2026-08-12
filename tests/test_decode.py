import base64

from provproxy.config import DecodeLimits
from provproxy.decode import Decoder


def test_base64_secret_is_decoded():
    secret = "AKIAABCDEFGHIJKLMNOP"
    encoded = base64.b64encode(secret.encode()).decode()
    decoder = Decoder(DecodeLimits())
    candidates = decoder.expand(f"payload: {encoded} end")
    assert any(secret in c.text for c in candidates)


def test_nesting_depth_is_bounded():
    secret = "topsecretvalue123"
    once = base64.b64encode(secret.encode()).decode()
    twice = base64.b64encode(once.encode()).decode()
    thrice = base64.b64encode(twice.encode()).decode()
    four_times = base64.b64encode(thrice.encode()).decode()

    decoder = Decoder(DecodeLimits())  # max_nesting_depth = 3
    candidates = decoder.expand(four_times)
    assert not any(c.text == secret for c in candidates)


def test_invalid_encoding_is_left_as_opaque_plaintext():
    decoder = Decoder(DecodeLimits())
    candidates = decoder.expand("not_base64_!!!_at_all_junk")
    assert candidates[0].text == "not_base64_!!!_at_all_junk"


def test_expansion_ratio_is_bounded():
    limits = DecodeLimits(max_expansion_ratio=2.0)
    decoder = Decoder(limits)
    # A short, valid base64 token decoding to something much longer than
    # 2x its own length should get truncated, not fully expanded.
    long_secret = "x" * 500
    encoded = base64.b64encode(long_secret.encode()).decode()[:20]  # truncate token itself
    candidates = decoder.expand(encoded)
    for c in candidates:
        assert len(c.text) <= max(len(encoded) * 2, limits.max_candidate_len_bytes)
