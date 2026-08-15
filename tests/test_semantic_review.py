from __future__ import annotations

import pytest

from provproxy.semantic import SemanticBackendUnavailable, SemanticMatch


def test_semantic_match_dataclass():
    m = SemanticMatch(source_id="s1", score=0.75)
    assert m.source_id == "s1"
    assert m.score == 0.75


def test_optional_backend_error_is_explicit(monkeypatch):
    # Import-time availability is intentionally optional. This test only
    # verifies the public exception type exists and is usable by callers.
    err = SemanticBackendUnavailable("backend unavailable")
    assert "backend" in str(err)
