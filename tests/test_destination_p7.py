from __future__ import annotations

from provproxy.destination import (
    canonical_network_destination,
    primary_domain,
)


def key(url: str) -> str | None:
    return primary_domain("http_request", {"url": url})


def test_hostname_case_collapses():
    assert key("https://Example.COM/a") == key("https://example.com/b")


def test_trailing_dns_dot_collapses():
    assert key("https://example.com./a") == key("https://example.com/b")


def test_default_https_port_collapses():
    assert key("https://example.com/a") == key("https://example.com:443/b")


def test_default_http_port_collapses():
    assert key("http://example.com/a") == key("http://example.com:80/b")


def test_path_query_fragment_do_not_change_identity():
    assert key("https://example.com/a?x=1#one") == key(
        "https://example.com/b/c?x=2#two"
    )


def test_scheme_is_part_of_identity():
    assert key("http://example.com:8080/a") != key(
        "https://example.com:8080/a"
    )


def test_nondefault_port_is_part_of_identity():
    assert key("https://example.com:443/a") != key(
        "https://example.com:8443/a"
    )


def test_ipv6_equivalent_text_collapses():
    assert key("http://[::1]:8765/a") == key(
        "http://[0:0:0:0:0:0:0:1]:8765/b"
    )


def test_idn_and_punycode_collapse():
    assert key("https://bücher.example/a") == key(
        "https://xn--bcher-kva.example/b"
    )


def test_hostname_and_ip_alias_remain_distinct_without_resolution():
    assert key("http://localhost:8765/a") != key(
        "http://127.0.0.1:8765/a"
    )


def test_distinct_host_aliases_remain_distinct_without_dns_resolution():
    assert key("https://api.example.test/a") != key(
        "https://alias.example.test/a"
    )


def test_malformed_or_missing_scheme_returns_none():
    assert key("example.com/no-scheme") is None
    assert key("https://:443/bad") is None
    assert key("https://example.com:99999/bad") is None


def test_canonical_object_exposes_effective_port():
    dest = canonical_network_destination(
        "http_request", "https://Example.COM./x"
    )
    assert dest is not None
    assert dest.scheme == "https"
    assert dest.host == "example.com"
    assert dest.port == 443
    assert dest.key == "http_request|https|example.com|443"
