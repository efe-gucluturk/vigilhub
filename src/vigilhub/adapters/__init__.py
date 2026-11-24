"""Ingestion adapters, one per sibling tool."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from vigilhub.adapters import gitvigil_adapter, reconvigil_adapter, vigilsiem_adapter
from vigilhub.adapters.base import AdapterError, ParseResult
from vigilhub.models import Source

_ADAPTERS: dict[Source, Callable[..., ParseResult]] = {
    Source.VIGILSIEM: vigilsiem_adapter.parse,
    Source.GITVIGIL: gitvigil_adapter.parse,
    Source.RECONVIGIL: reconvigil_adapter.parse,
}


def parse_report(source: Source, data: Any, *, target: str | None = None) -> ParseResult:
    return _ADAPTERS[source](data, target=target)


__all__ = ["AdapterError", "ParseResult", "parse_report"]
