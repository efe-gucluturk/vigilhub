from __future__ import annotations

import pytest

from vigilhub.correlation.normalize import normalize_target, scope_label
from vigilhub.sanitize import sanitize_json, sanitize_text


def test_sanitize_strips_control_and_bidi():
    dirty = "ok\x00\x1b[31m\u202eevil\u2066x\u200b\r\nline2\u2028end"
    clean = sanitize_text(dirty)
    assert clean == "ok[31mevilx  line2 end"
    assert all(ord(c) >= 32 for c in clean)


def test_sanitize_truncates_and_json_recurses():
    assert len(sanitize_text("a" * 5000, 100)) == 100
    nested = {"k\x00": ["a\u202eb", {"n": 1}], "d": {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}}
    out = sanitize_json(nested)
    assert out["k"] == ["ab", {"n": 1}]


@pytest.mark.parametrize(
    ("raw", "hint", "expected"),
    [
        ("Staging.AcmeCorp.Example.", None, "domain:staging.acmecorp.example"),
        ("https://User@WWW.Example.com:8443/path?q=1", None, "domain:www.example.com"),
        ("203.0.113.10", None, "ip:203.0.113.10"),
        ("203.0.113.10:22", None, "ip:203.0.113.10"),
        ("[2001:DB8::1]:443", None, "ip:2001:db8::1"),
        ("web01", "host", "host:web01"),
        ("C:\\src\\AcmeCorp-Web", "repo", "repo:acmecorp-web"),
        ("https://github.com/Org/Repo.git", "repo", "repo:repo"),
        ("git@github.com:org/My_Repo.git", "repo", "repo:my_repo"),
        ("acmecorp-web", None, "repo:acmecorp-web"),
        ("ev\x00il.example.com\u202e", None, "domain:evil.example.com"),
    ],
)
def test_normalize_valid(raw, hint, expected):
    assert normalize_target(raw, hint).key == expected


@pytest.mark.parametrize(
    "raw", ["", "   ", "\x00\x01", "<script>alert(1)</script>", "a b.com", "-bad-.com", "x" * 600]
)
def test_normalize_rejects(raw):
    with pytest.raises(ValueError, match=r"invalid|empty"):
        normalize_target(raw, "host")


def test_scope_label():
    assert scope_label("staging.acmecorp.example") == "acmecorp"
    assert scope_label("shop.example.co.uk") == "example"
    assert scope_label("localhost") is None
