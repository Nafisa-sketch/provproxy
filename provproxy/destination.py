"""Destination extraction, canonicalization, and V0 allow-list checking.

P7 hardening
------------
Network destination identity is canonicalized before it is used to key V4
cross-call state. The canonical key is:

    <tool>|<scheme>|<normalized-host>|<effective-port>

Normalization is intentionally deterministic and local:
- scheme lower-cased
- DNS hostname lower-cased
- terminal DNS root dot removed
- Unicode IDN hostnames converted to ASCII IDNA/Punycode
- IPv4/IPv6 literals normalized with ``ipaddress``
- omitted HTTP/HTTPS ports expanded to 80/443
- path/query/fragment excluded from destination identity

DNS resolution, CNAME equivalence, redirect targets, and DNS rebinding are NOT
collapsed here. Those require network-adapter observability and remain explicit
threat-model boundaries.

Detection and enforcement remain conceptually separate:
- provenance detection asks whether payload content derives from tracked data;
- allow-list enforcement asks whether the destination is policy-approved.

Malformed network destinations fail closed for enforcement.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .config import PolicyFile


_FILESYSTEM_PATH_KEYS = ("path", "source", "destination")
_NETWORK_URL_KEYS = ("url",)

_FILESYSTEM_TOOLS = {
    "read_file",
    "write_file",
    "delete_file",
    "list_directory",
    "move_file",
}
_NETWORK_TOOLS = {"http_request", "fetch"}

_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}


@dataclass(frozen=True)
class CanonicalNetworkDestination:
    tool_name: str
    scheme: str
    host: str
    port: int | None

    @property
    def key(self) -> str:
        port_text = "" if self.port is None else str(self.port)
        return f"{self.tool_name}|{self.scheme}|{self.host}|{port_text}"


def _normalize_host(host: str) -> str | None:
    """Canonicalize an already-parsed hostname/IP literal.

    Returns ``None`` for empty/invalid hosts.
    """
    host = host.strip()
    if not host:
        return None

    # urlsplit().hostname removes IPv6 brackets for us.
    host = host.rstrip(".")
    if not host:
        return None

    # Normalize IP literals first.
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass

    # DNS names are case-insensitive. IDNA gives one ASCII representation for
    # Unicode and already-punycode hostnames.
    host = host.lower()
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None

    # IDNA output should still be treated case-insensitively.
    ascii_host = ascii_host.lower().rstrip(".")
    return ascii_host or None


def canonical_network_destination(
    tool_name: str,
    url: str,
) -> CanonicalNetworkDestination | None:
    """Parse one network URL into the P7 canonical endpoint identity.

    Userinfo/path/query/fragment do not participate in identity.
    Invalid ports, missing scheme, or missing host return ``None``.
    """
    if tool_name not in _NETWORK_TOOLS or not isinstance(url, str):
        return None

    try:
        parsed = urlsplit(url)
    except ValueError:
        return None

    scheme = (parsed.scheme or "").lower()
    if not scheme:
        return None

    host = _normalize_host(parsed.hostname or "")
    if host is None:
        return None

    try:
        explicit_port = parsed.port
    except ValueError:
        # e.g. malformed or out-of-range port
        return None

    port = explicit_port
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)

    return CanonicalNetworkDestination(
        tool_name=tool_name,
        scheme=scheme,
        host=host,
        port=port,
    )


def extract_destination_candidates(
    tool_name: str,
    arguments: dict,
) -> tuple[list[str], list[str]]:
    """Return ``(paths, normalized_hosts)`` referenced by a tool call.

    Hosts here are for allow/block policy matching, so they remain host-only.
    V4 state uses :func:`primary_domain`, which returns the full canonical
    endpoint key including scheme/effective-port/tool identity.
    """
    paths: list[str] = []
    domains: list[str] = []

    if tool_name in _FILESYSTEM_TOOLS:
        for key in _FILESYSTEM_PATH_KEYS:
            val = arguments.get(key)
            if isinstance(val, str):
                paths.append(val)

    if tool_name in _NETWORK_TOOLS:
        for key in _NETWORK_URL_KEYS:
            val = arguments.get(key)
            if isinstance(val, str):
                dest = canonical_network_destination(tool_name, val)
                if dest is not None:
                    domains.append(dest.host)

    return paths, domains


def _network_arguments_are_valid(tool_name: str, arguments: dict) -> bool:
    """Fail-closed validation for referenced network URLs."""
    if tool_name not in _NETWORK_TOOLS:
        return True

    found_url = False
    for key in _NETWORK_URL_KEYS:
        val = arguments.get(key)
        if isinstance(val, str):
            found_url = True
            if canonical_network_destination(tool_name, val) is None:
                return False

    # Preserve the project's historical convention: if a network tool call
    # contains no destination-bearing URL at all, there is nothing to evaluate
    # against the destination allow/block policy, so the call is vacuously
    # allowed. A PRESENT but malformed URL still returns False above.
    return True


def _matches_any(value: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(value, p) for p in patterns)


def is_sensitive_source(
    policy: PolicyFile,
    server_id: str,
    tool_name: str,
    arguments: dict,
) -> bool:
    """Return whether a filesystem read targets a blocked/sensitive path."""
    binding = policy.binding_for(server_id)
    if binding is None:
        return False

    cap = binding.tool_capabilities.get(tool_name)
    if cap is None or not cap.blocked_paths:
        return False

    paths, _domains = extract_destination_candidates(tool_name, arguments)
    return any(_matches_any(p, cap.blocked_paths) for p in paths)


def primary_domain(tool_name: str, arguments: dict) -> str | None:
    """Return the canonical V4 destination key for the first network URL.

    Historical name preserved for API compatibility with the relay/benchmarks.
    """
    if tool_name not in _NETWORK_TOOLS:
        return None

    for key in _NETWORK_URL_KEYS:
        val = arguments.get(key)
        if isinstance(val, str):
            dest = canonical_network_destination(tool_name, val)
            return dest.key if dest is not None else None

    return None


def is_destination_allowed(
    policy: PolicyFile,
    server_id: str,
    tool_name: str,
    arguments: dict,
) -> bool:
    """Apply V0 destination policy.

    Unknown server/tool, malformed network URLs, blocked destinations, or
    destinations outside a non-empty allow-list are denied.
    """
    binding = policy.binding_for(server_id)
    if binding is None:
        return False

    cap = binding.tool_capabilities.get(tool_name)
    if cap is None:
        return False

    if not _network_arguments_are_valid(tool_name, arguments):
        return False

    paths, domains = extract_destination_candidates(tool_name, arguments)

    if not paths and not domains:
        # Preserve the project's historical convention: when no destination
        # is referenced at all, there is nothing to compare against the
        # allow/block lists, so the call is vacuously allowed.
        return True

    for p in paths:
        if _matches_any(p, cap.blocked_paths):
            return False
        if cap.allowed_paths and not _matches_any(p, cap.allowed_paths):
            return False

    for d in domains:
        if _matches_any(d, cap.blocked_domains):
            return False
        if cap.allowed_domains and not _matches_any(d, cap.allowed_domains):
            return False

    return True
