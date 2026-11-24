"""Business operations shared by the API and the CLI."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

from vigilhub import db
from vigilhub.adapters import AdapterError, parse_report
from vigilhub.correlation import build_assets, correlate
from vigilhub.models import Source


@dataclass
class IngestSummary:
    source: str
    accepted: int
    skipped: int
    warnings: list[str] = field(default_factory=list)


@dataclass
class CorrelationSummary:
    assets: int
    findings: int
    incidents: int
    by_severity: dict[str, int]


def rescore_assets(conn: sqlite3.Connection) -> int:
    assets = build_assets(db.all_findings(conn))
    db.replace_assets(conn, assets)
    return len(assets)


def ingest(
    conn: sqlite3.Connection, source: Source, data: Any, *, target: str | None = None
) -> IngestSummary:
    """Parse a report with the matching adapter, store it, and refresh asset risk scores."""
    parsed = parse_report(source, data, target=target)  # raises AdapterError
    db.save_findings(conn, parsed.findings)
    rescore_assets(conn)
    return IngestSummary(source.value, len(parsed.findings), parsed.skipped, parsed.warnings)


def run_correlation(conn: sqlite3.Connection) -> CorrelationSummary:
    findings = db.all_findings(conn)
    db.replace_assets(conn, build_assets(findings))
    incidents = correlate(findings)
    db.replace_incidents(conn, incidents)
    by_sev: dict[str, int] = {}
    for i in incidents:
        by_sev[i.severity.value] = by_sev.get(i.severity.value, 0) + 1
    return CorrelationSummary(
        assets=db.counts(conn)["assets"],
        findings=len(findings),
        incidents=len(incidents),
        by_severity=by_sev,
    )


def seed_demo(conn: sqlite3.Connection) -> tuple[list[IngestSummary], CorrelationSummary]:
    from vigilhub.demo import demo_reports  # local import: demo data is only needed here

    summaries = [ingest(conn, source, payload) for source, payload in demo_reports()]
    return summaries, run_correlation(conn)


__all__ = [
    "AdapterError",
    "CorrelationSummary",
    "IngestSummary",
    "ingest",
    "rescore_assets",
    "run_correlation",
    "seed_demo",
]
