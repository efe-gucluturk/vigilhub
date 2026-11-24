"""Static guard: the dashboard must render untrusted scanner text as plain React text nodes."""

from __future__ import annotations

import re
from pathlib import Path

FRONTEND = Path(__file__).parent.parent / "frontend"
BANNED = re.compile(
    r"dangerouslySetInnerHTML|\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write"
    r"|\beval\(|new Function\(|localStorage"
)


def _sources() -> list[Path]:
    return [
        p
        for d in ("app", "components", "lib")
        for p in (FRONTEND / d).rglob("*")
        if p.suffix in {".ts", ".tsx"}
    ]


def test_frontend_sources_exist():
    assert len(_sources()) >= 15


def test_no_raw_html_or_eval_sinks():
    offenders = [
        f"{p.relative_to(FRONTEND)}: {m.group(0)}"
        for p in _sources()
        for m in BANNED.finditer(p.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_api_key_is_never_hardcoded_or_put_in_a_url():
    for p in _sources():
        text = p.read_text(encoding="utf-8")
        assert not re.search(r"[?&]api_?key=", text, re.I), p.name
    ws_url = (FRONTEND / "lib" / "api.ts").read_text(encoding="utf-8")
    assert "/api/v1/ws`" in ws_url  # the stream URL carries no query string
