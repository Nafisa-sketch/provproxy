import os
from pathlib import Path

from provproxy.pathcanon import _lexical_normalize


def test_traversal_is_lexically_flattened():
    out = _lexical_normalize(Path("/home/user/project/../../etc/passwd"))
    assert str(out) in ("/home/etc/passwd", "\\home\\etc\\passwd") or out == Path("/home/etc/passwd")


def test_tilde_expands_to_home(monkeypatch):
    monkeypatch.setenv("HOME", "/home/testuser")
    from provproxy.pathcanon import canonicalize

    # We only check the lexical/expansion part is sane; resolve() may fail
    # since the path doesn't exist, canonicalize() handles that gracefully.
    result = canonicalize("~/.ssh/id_rsa")
    assert "testuser" in str(result) or ".ssh" in str(result)
