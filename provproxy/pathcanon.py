"""Path Canonicalizer — resolves `~`, `..` traversals, and symlink escape
vectors so V0's stateless baseline policy reasons about real targets, not
attacker-chosen spellings of them.
"""
from __future__ import annotations

import os
from pathlib import Path


def canonicalize(raw: str) -> Path:
    expanded = Path(raw).expanduser()
    lexical = _lexical_normalize(expanded)
    try:
        return lexical.resolve(strict=True)
    except (FileNotFoundError, OSError):
        return _canonicalize_nonexistent(lexical)


def _canonicalize_nonexistent(p: Path) -> Path:
    existing = p
    tail: list[str] = []
    while not existing.exists():
        tail.append(existing.name)
        parent = existing.parent
        if parent == existing:
            break
        existing = parent

    resolved = existing.resolve() if existing.exists() else existing
    for component in reversed(tail):
        resolved = resolved / component
    return resolved


def _lexical_normalize(p: Path) -> Path:
    """Resolve `.` and `..` without touching the filesystem, so traversal
    attempts against nonexistent paths still normalize correctly."""
    stack: list[str] = []
    for part in p.parts:
        if part == os.sep or (len(part) == 2 and part[1] == ":"):
            # Drive letter or root — always keep.
            stack.append(part)
        elif part == "..":
            if stack and stack[-1] not in ("..", os.sep) and not stack[-1].endswith(":"):
                stack.pop()
            else:
                stack.append(part)
        elif part == ".":
            continue
        else:
            stack.append(part)
    return Path(*stack) if stack else Path(".")
