"""Destination extraction + V0 allow-list checking.

This closes the B5 gap the evaluation harness surfaced: previously,
`pipeline.evaluate()` decided ALLOW/BLOCK purely from payload content,
never consulting the V0 `server_bindings` allow-list. So a provenance
match against an explicitly-approved destination still got blocked.

The fix keeps two things conceptually separate, on purpose:

  - **Detection** (`TierResult.matched`): did the payload contain content
    provenance-linked to a tracked sensitive source? This is what the
    research question (Section 2) is actually about — it should NOT be
    influenced by where the call is going, or the V1-V3 ablation results
    stop measuring what they claim to measure.
  - **Enforcement** (`TierResult.enforcement_blocked`): should this call
    actually be stopped? This is where an allow-listed destination gets
    to override a detection into a pass-through — the V0 baseline and the
    provenance tiers aren't competing signals, V0 is a downstream policy
    check on top of what provenance detects.

Fail-closed by construction: an unknown server_id, unknown tool, or a
destination that matches no allow rule at all is NOT allowed.
"""
from __future__ import annotations

import fnmatch
from typing import Any

from .config import PolicyFile, ToolCapability

_FILESYSTEM_PATH_KEYS = ("path", "source", "destination")
_NETWORK_URL_KEYS = ("url",)

_FILESYSTEM_TOOLS = {"read_file", "write_file", "delete_file", "list_directory", "move_file"}
_NETWORK_TOOLS = {"http_request", "fetch"}


def extract_destination_candidates(tool_name: str, arguments: dict) -> tuple[list[str], list[str]]:
    """Returns (paths, domains) referenced by this tool call's arguments."""
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
                host = _extract_host(val)
                if host:
                    domains.append(host)

    return paths, domains


def _extract_host(url: str) -> str | None:
    without_scheme = url.split("://", 1)[-1]
    host_and_port = without_scheme.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return host_and_port or None


def _matches_any(value: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(value, p) for p in patterns)


def is_sensitive_source(policy: PolicyFile, server_id: str, tool_name: str, arguments: dict) -> bool:
    """Is this a read of a location the policy marks as sensitive
    (`blocked_paths`)? Used to decide whether to automatically register
    the *result* of this call as a tracked fragment (see relay.py), so
    later provenance matching has something real to compare against —
    without this, nothing ever gets registered and V1-V3 can never
    actually detect anything in a live run.

    Note: this only looks at `blocked_paths`, not `blocked_domains` — the
    idea is specifically "reading from a normally-forbidden location",
    which for filesystem tools means things like `~/.ssh/*` or `.env`
    files. Network reads aren't treated as sensitive *sources* here."""
    binding = policy.binding_for(server_id)
    if binding is None:
        return False
    cap = binding.tool_capabilities.get(tool_name)
    if cap is None or not cap.blocked_paths:
        return False

    paths, _domains = extract_destination_candidates(tool_name, arguments)
    return any(_matches_any(p, cap.blocked_paths) for p in paths)


def primary_domain(tool_name: str, arguments: dict) -> str | None:
    """First domain referenced by this call, if any — used to key the V4
    cross-call window (Section 5C scopes windows per destination)."""
    _paths, domains = extract_destination_candidates(tool_name, arguments)
    return domains[0] if domains else None


def is_destination_allowed(
    policy: PolicyFile, server_id: str, tool_name: str, arguments: dict
) -> bool:
    """Fail-closed: unknown server/tool, or a referenced path/domain that
    doesn't clear the allow-list, means NOT allowed. A call that
    references no path/domain at all (nothing to check) is vacuously
    allowed — same convention used by the allow-glob matching elsewhere
    in this project."""
    binding = policy.binding_for(server_id)
    if binding is None:
        return False

    cap = binding.tool_capabilities.get(tool_name)
    if cap is None:
        return False

    paths, domains = extract_destination_candidates(tool_name, arguments)

    if not paths and not domains:
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
