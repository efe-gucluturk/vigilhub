"""Sanitization of untrusted strings coming from scanner reports."""

from __future__ import annotations

import unicodedata
from typing import Any

# Cc: control chars (incl. ESC, NUL). Cf: format chars, which covers bidi overrides
# (U+202A-E, U+2066-9, U+200E/F) and zero-width characters. Cs/Co/Cn: surrogates,
# private-use and unassigned code points have no legitimate place in a report.
_DROP = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
_TO_SPACE = frozenset({"Zl", "Zp"})

_MAX_DEPTH = 6
_MAX_ITEMS = 64


def sanitize_text(value: object, max_len: int = 2000) -> str:
    """Return a single-line string with control/bidi characters removed.

    Newlines and tabs become spaces so one field can never forge extra log lines.
    """
    out: list[str] = []
    for ch in str(value):
        if ch in "\n\r\t":
            out.append(" ")
            continue
        cat = unicodedata.category(ch)
        if cat in _TO_SPACE:
            out.append(" ")
        elif cat not in _DROP:
            out.append(ch)
    return "".join(out).strip()[:max_len]


def sanitize_json(value: Any, *, max_len: int = 1000, _depth: int = 0) -> Any:
    """Recursively sanitize strings in a JSON-like structure, bounding depth and size."""
    if isinstance(value, str):
        return sanitize_text(value, max_len)
    if isinstance(value, bool) or value is None or isinstance(value, int | float):
        return value
    if _depth >= _MAX_DEPTH:
        return None
    if isinstance(value, dict):
        return {
            sanitize_text(k, 64): sanitize_json(v, max_len=max_len, _depth=_depth + 1)
            for k, v in list(value.items())[:_MAX_ITEMS]
        }
    if isinstance(value, list | tuple):
        return [sanitize_json(v, max_len=max_len, _depth=_depth + 1) for v in value[:_MAX_ITEMS]]
    return sanitize_text(value, max_len)
