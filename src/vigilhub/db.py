"""SQLite store. Every statement is static SQL with bound ``?`` parameters."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from vigilhub.config import MAX_API_KEY_LENGTH
from vigilhub.models import Asset, Finding, Incident, Severity, Source

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    finding_count INTEGER NOT NULL DEFAULT 0,
    sources TEXT NOT NULL DEFAULT '[]',
    severity_counts TEXT NOT NULL DEFAULT '{}',
    aliases TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    severity_rank INTEGER NOT NULL,
    category TEXT NOT NULL,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    aliases TEXT NOT NULL DEFAULT '[]',
    location TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '{}',
    observed_at TEXT,
    ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    severity_rank INTEGER NOT NULL,
    score INTEGER NOT NULL,
    summary TEXT NOT NULL,
    asset_ids TEXT NOT NULL,
    finding_ids TEXT NOT NULL,
    sources TEXT NOT NULL,
    steps TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
"""

_REQUIRED_TABLES = {"assets", "findings", "incidents", "api_keys"}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def connect(path: Path | str) -> sqlite3.Connection:
    # check_same_thread=False: FastAPI may run a request's dependency and handler on
    # different worker threads, but one connection is never used concurrently.
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    with conn:
        conn.executescript(SCHEMA)


def has_schema(conn: sqlite3.Connection) -> bool:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return {r["name"] for r in rows} >= _REQUIRED_TABLES


# --- API keys -------------------------------------------------------------------------------


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_api_key(conn: sqlite3.Connection, name: str) -> str:
    raw = secrets.token_urlsafe(32)
    with conn:
        conn.execute(
            "INSERT INTO api_keys (name, key_hash, created_at) VALUES (?, ?, ?)",
            (name, hash_key(raw), _now()),
        )
    return raw


def verify_api_key(conn: sqlite3.Connection, presented: str | None) -> bool:
    """Constant-time check against every active hash (no early exit on a match)."""
    if not presented or len(presented) > MAX_API_KEY_LENGTH:
        return False
    digest = hash_key(presented)
    ok = False
    for row in conn.execute("SELECT key_hash FROM api_keys WHERE revoked = 0"):
        ok |= hmac.compare_digest(row["key_hash"], digest)
    return ok


def ensure_api_key(conn: sqlite3.Connection, key_file: Path) -> bool:
    """Make sure ``key_file`` holds a key registered in the DB. Returns True if one was created.

    The raw key only ever lives in the key file; the DB keeps its SHA-256.
    """
    if key_file.exists():
        existing = key_file.read_text(encoding="utf-8").strip()
        if existing and verify_api_key(conn, existing):
            return False
        if existing and len(existing) <= MAX_API_KEY_LENGTH:
            with conn:  # key file from an earlier DB: register its hash
                conn.execute(
                    "INSERT OR IGNORE INTO api_keys (name, key_hash, created_at) VALUES (?, ?, ?)",
                    ("local", hash_key(existing), _now()),
                )
            return False
    raw = create_api_key(conn, "local")
    # Only reached when the file is missing/empty; 0o600 is honoured on POSIX.
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(raw + "\n")
    with contextlib.suppress(OSError):
        key_file.chmod(0o600)
    return True


# --- findings / assets / incidents ----------------------------------------------------------


def save_findings(conn: sqlite3.Connection, findings: list[Finding]) -> None:
    now = _now()
    with conn:
        for f in findings:
            kind, _, name = f.asset.partition(":")
            conn.execute(
                "INSERT OR IGNORE INTO assets (id, kind, name, updated_at) VALUES (?, ?, ?, ?)",
                (f.asset, kind, name, now),
            )
            conn.execute(
                """INSERT INTO findings (id, source, rule_id, title, severity, severity_rank,
                       category, asset_id, aliases, location, description, evidence,
                       observed_at, ingested_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       title = excluded.title, severity = excluded.severity,
                       severity_rank = excluded.severity_rank, category = excluded.category,
                       aliases = excluded.aliases, location = excluded.location,
                       description = excluded.description, evidence = excluded.evidence,
                       observed_at = excluded.observed_at""",
                (
                    f.id,
                    f.source.value,
                    f.rule_id,
                    f.title,
                    f.severity.value,
                    f.severity.rank,
                    f.category,
                    f.asset,
                    json.dumps(f.aliases),
                    f.location,
                    f.description,
                    json.dumps(f.evidence),
                    f.observed_at,
                    now,
                ),
            )


def _finding_from_row(row: sqlite3.Row) -> Finding:
    return Finding(
        id=row["id"],
        source=row["source"],
        rule_id=row["rule_id"],
        title=row["title"],
        severity=row["severity"],
        category=row["category"],
        asset=row["asset_id"],
        aliases=json.loads(row["aliases"]),
        location=row["location"],
        description=row["description"],
        evidence=json.loads(row["evidence"]),
        observed_at=row["observed_at"],
    )


def query_findings(
    conn: sqlite3.Connection,
    *,
    source: str | None = None,
    severity: str | None = None,
    asset_ids: list[str] | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Finding]:
    # Static SQL: optional filters are `? IS NULL OR col = ?`, the asset list is bound as JSON.
    rows = conn.execute(
        """SELECT * FROM findings
           WHERE (? IS NULL OR source = ?)
             AND (? IS NULL OR severity = ?)
             AND (? IS NULL OR asset_id IN (SELECT value FROM json_each(?)))
           ORDER BY severity_rank DESC, id LIMIT ? OFFSET ?""",
        (
            source,
            source,
            severity,
            severity,
            None if asset_ids is None else 1,
            json.dumps(asset_ids or []),
            limit,
            offset,
        ),
    ).fetchall()
    return [_finding_from_row(r) for r in rows]


def all_findings(conn: sqlite3.Connection) -> list[Finding]:
    rows = conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
    return [_finding_from_row(r) for r in rows]


def replace_assets(conn: sqlite3.Connection, assets: list[Asset]) -> None:
    now = _now()
    with conn:
        for a in assets:
            conn.execute(
                """UPDATE assets SET risk_score = ?, finding_count = ?, sources = ?,
                       severity_counts = ?, aliases = ?, updated_at = ? WHERE id = ?""",
                (
                    a.risk_score,
                    a.finding_count,
                    json.dumps([s.value for s in a.sources]),
                    json.dumps(a.severity_counts),
                    json.dumps(a.aliases),
                    now,
                    a.id,
                ),
            )


def _asset_from_row(row: sqlite3.Row) -> Asset:
    return Asset(
        id=row["id"],
        kind=row["kind"],
        name=row["name"],
        risk_score=row["risk_score"],
        finding_count=row["finding_count"],
        sources=json.loads(row["sources"]),
        severity_counts=json.loads(row["severity_counts"]),
        aliases=json.loads(row["aliases"]),
    )


def list_assets(conn: sqlite3.Connection, limit: int = 100, offset: int = 0) -> list[Asset]:
    rows = conn.execute(
        "SELECT * FROM assets ORDER BY risk_score DESC, id LIMIT ? OFFSET ?", (limit, offset)
    ).fetchall()
    return [_asset_from_row(r) for r in rows]


def get_asset(conn: sqlite3.Connection, asset_id: str) -> Asset | None:
    row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    return _asset_from_row(row) if row else None


def replace_incidents(conn: sqlite3.Connection, incidents: list[Incident]) -> None:
    """Incidents are derived data: recompute-and-swap inside one transaction."""
    now = _now()
    with conn:
        conn.execute("DELETE FROM incidents")
        for i in incidents:
            conn.execute(
                """INSERT INTO incidents (id, rule_id, title, severity, severity_rank, score,
                       summary, asset_ids, finding_ids, sources, steps, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    i.id,
                    i.rule_id,
                    i.title,
                    i.severity.value,
                    i.severity.rank,
                    i.score,
                    i.summary,
                    json.dumps(i.asset_ids),
                    json.dumps(i.finding_ids),
                    json.dumps([s.value for s in i.sources]),
                    json.dumps([s.model_dump(mode="json") for s in i.steps]),
                    now,
                ),
            )


def list_incidents(conn: sqlite3.Connection, limit: int = 100, offset: int = 0) -> list[Incident]:
    rows = conn.execute(
        "SELECT * FROM incidents ORDER BY severity_rank DESC, score DESC, id LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    return [
        Incident(
            id=r["id"],
            rule_id=r["rule_id"],
            title=r["title"],
            severity=r["severity"],
            score=r["score"],
            summary=r["summary"],
            asset_ids=json.loads(r["asset_ids"]),
            finding_ids=json.loads(r["finding_ids"]),
            sources=json.loads(r["sources"]),
            steps=json.loads(r["steps"]),
        )
        for r in rows
    ]


def incident_ids_for_asset(conn: sqlite3.Connection, asset_id: str) -> list[str]:
    rows = conn.execute("SELECT id, asset_ids FROM incidents ORDER BY id").fetchall()
    return [r["id"] for r in rows if asset_id in json.loads(r["asset_ids"])]


_COUNT_SQL = {
    "assets": "SELECT COUNT(*) FROM assets",
    "findings": "SELECT COUNT(*) FROM findings",
    "incidents": "SELECT COUNT(*) FROM incidents",
    "api_keys": "SELECT COUNT(*) FROM api_keys WHERE revoked = 0",
}


def counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {name: conn.execute(sql).fetchone()[0] for name, sql in _COUNT_SQL.items()}


def _group_counts(rows: list[sqlite3.Row]) -> dict[str, int]:
    return {r["k"]: r["n"] for r in rows}


def stats(conn: sqlite3.Connection) -> dict[str, dict[str, int] | int]:
    """Aggregate counts for the dashboard. Every severity/source key is present (0 if none)."""
    c = counts(conn)
    by_sev = _group_counts(
        conn.execute(
            "SELECT severity AS k, COUNT(*) AS n FROM findings GROUP BY severity"
        ).fetchall()
    )
    by_src = _group_counts(
        conn.execute("SELECT source AS k, COUNT(*) AS n FROM findings GROUP BY source").fetchall()
    )
    inc_sev = _group_counts(
        conn.execute(
            "SELECT severity AS k, COUNT(*) AS n FROM incidents GROUP BY severity"
        ).fetchall()
    )
    levels = [s.value for s in Severity]
    return {
        "total_assets": c["assets"],
        "total_findings": c["findings"],
        "total_incidents": c["incidents"],
        "findings_by_severity": {k: by_sev.get(k, 0) for k in levels},
        "findings_by_source": {s.value: by_src.get(s.value, 0) for s in Source},
        "incidents_by_severity": {k: inc_sev.get(k, 0) for k in levels},
    }
