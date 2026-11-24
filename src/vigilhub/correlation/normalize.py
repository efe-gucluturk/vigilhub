"""Canonicalization of targets (domains, IPs, hosts, repositories) into asset keys."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal, NamedTuple
from urllib.parse import urlsplit

from vigilhub.models import AssetKind
from vigilhub.sanitize import sanitize_text

Hint = Literal["host", "repo"] | None

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_REPO = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")
_MAX_TARGET = 512
# Second-level labels that form part of a public suffix (example.co.uk -> label "example").
_SLD_SUFFIXES = frozenset({"co", "com", "org", "net", "gov", "ac", "edu"})


class Target(NamedTuple):
    kind: AssetKind
    name: str

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.name}"


def split_key(key: str) -> tuple[AssetKind, str]:
    kind, _, name = key.partition(":")
    return AssetKind(kind), name


def _host_candidate(text: str) -> str:
    if "://" in text:
        text = urlsplit(text).hostname or ""
    else:
        text = re.split(r"[/?#\\]", text, maxsplit=1)[0]
        text = text.rsplit("@", 1)[-1]
        if text.startswith("["):
            text = text[1:].split("]", 1)[0]
        elif text.count(":") == 1:
            text = text.split(":", 1)[0]
    return text.rstrip(".")


def _as_domain(text: str) -> str | None:
    try:
        ascii_name = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not ascii_name or len(ascii_name) > 253 or "." not in ascii_name:
        return None
    labels = ascii_name.split(".")
    if not all(_LABEL.match(lbl) for lbl in labels) or labels[-1].isdigit():
        return None
    return ascii_name


def _as_repo(text: str) -> str | None:
    parts = [p for p in re.split(r"[/\\:]", text) if p]
    if not parts:
        return None
    name = parts[-1].removesuffix(".git")
    return name if _REPO.match(name) else None


def normalize_target(raw: object, hint: Hint = None) -> Target:
    """Canonicalize ``raw`` or raise ``ValueError``.

    ``hint="repo"`` forces repository parsing (last path component, lowercase, no ``.git``).
    ``hint="host"`` accepts IP, FQDN or a bare single-label hostname.
    With no hint: IP, then domain, then repository.
    """
    text = sanitize_text(raw, _MAX_TARGET).lower()
    if not text:
        raise ValueError("empty target")

    if hint == "repo":
        repo = _as_repo(text)
        if repo is None:
            raise ValueError("invalid repository name")
        return Target(AssetKind.REPO, repo)

    try:
        host = _host_candidate(text)
    except ValueError as exc:  # urlsplit rejects malformed netlocs
        raise ValueError("invalid target") from exc

    try:
        return Target(AssetKind.IP, str(ipaddress.ip_address(host)))
    except ValueError:
        pass
    domain = _as_domain(host)
    if domain:
        return Target(AssetKind.DOMAIN, domain)
    if hint == "host" and _LABEL.match(host):
        return Target(AssetKind.HOST, host)
    if hint is None:
        repo = _as_repo(text)
        if repo:
            return Target(AssetKind.REPO, repo)
    raise ValueError("invalid target")


def scope_label(domain: str) -> str | None:
    """Project-scope label of a domain: ``staging.acme.example`` -> ``acme``."""
    labels = domain.split(".")
    if len(labels) < 2:
        return None
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD_SUFFIXES:
        return labels[-3]
    return labels[-2]
