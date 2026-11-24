"""VigilHub command line interface."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from vigilhub import __version__, db, service
from vigilhub.adapters import AdapterError
from vigilhub.config import MAX_BODY_BYTES, db_path, key_file_path
from vigilhub.models import Source
from vigilhub.sanitize import sanitize_text

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Security command center: ingest, normalize and correlate Vigil-tool findings.",
)

DbOption = Annotated[
    Path | None, typer.Option("--db", envvar="VIGILHUB_DB", help="SQLite database path.")
]
out = Console(markup=False, highlight=False)
err = Console(stderr=True, markup=False, highlight=False)


def _fail(message: str, code: int = 2) -> typer.Exit:
    err.print(Text(f"error: {sanitize_text(message, 300)}"))
    return typer.Exit(code)


def _open(database: Path | None) -> sqlite3.Connection:
    path = db_path(database)
    if not path.exists():
        raise _fail(f"database {path} not found; run `vigilhub init-db` first")
    conn = db.connect(path)
    if not db.has_schema(conn):
        conn.close()
        raise _fail(f"database {path} is not initialised; run `vigilhub init-db`")
    return conn


def _read_limited(path: Path) -> bytes:
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_BODY_BYTES + 1)
    except OSError as exc:
        raise _fail(f"cannot read {path}: {exc.strerror}") from exc
    if len(data) > MAX_BODY_BYTES:
        raise _fail(f"{path} exceeds the {MAX_BODY_BYTES} byte ingestion limit")
    return data


@app.command("init-db")
def init_db(
    database: DbOption = None,
    key_file: Annotated[Path | None, typer.Option("--key-file", envvar="VIGILHUB_KEY_FILE")] = None,
) -> None:
    """Create the database and, if needed, a local API key file."""
    path = db_path(database)
    conn = db.connect(path)
    try:
        db.init_schema(conn)
        keyfile = key_file_path(key_file)
        created = db.ensure_api_key(conn, keyfile)
    finally:
        conn.close()
    out.print(Text(f"database ready: {path}"))
    if created:
        out.print(Text(f"API key written to {keyfile} (send as X-API-Key; keep it out of git)"))
    else:
        out.print(Text(f"API key already present in {keyfile}"))


@app.command()
def ingest(
    source: Annotated[Source, typer.Argument(help="vigilsiem | gitvigil | reconvigil")],
    file: Annotated[Path, typer.Argument(help="Report file (JSON or SARIF).")],
    target: Annotated[
        str | None, typer.Option(help="Override/provide the target (e.g. repo name for SARIF).")
    ] = None,
    database: DbOption = None,
) -> None:
    """Parse a tool report and store its findings."""
    raw = _read_limited(file)
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise _fail("file is not valid JSON") from exc
    conn = _open(database)
    try:
        summary = service.ingest(conn, source, data, target=target)
    except AdapterError as exc:
        raise _fail(str(exc)) from exc
    finally:
        conn.close()
    out.print(
        Text(f"{summary.source}: {summary.accepted} findings stored, {summary.skipped} skipped")
    )
    for warning in summary.warnings:
        err.print(Text(f"warning: {warning}"))


@app.command()
def correlate(database: DbOption = None) -> None:
    """Re-run asset scoring and cross-tool correlation over all stored findings."""
    conn = _open(database)
    try:
        result = service.run_correlation(conn)
    finally:
        conn.close()
    sev = ", ".join(f"{k}={v}" for k, v in sorted(result.by_severity.items())) or "none"
    out.print(
        Text(
            f"{result.findings} findings, {result.assets} assets, "
            f"{result.incidents} incidents ({sev})"
        )
    )


@app.command("seed-demo")
def seed_demo(database: DbOption = None) -> None:
    """Load realistic sample reports from all three tools, then correlate."""
    conn = _open(database)
    try:
        summaries, result = service.seed_demo(conn)
    finally:
        conn.close()
    for s in summaries:
        out.print(Text(f"{s.source}: {s.accepted} findings"))
    out.print(Text(f"correlated: {result.incidents} incidents across {result.assets} assets"))


@app.command()
def status(database: DbOption = None) -> None:
    """Show database counts, top assets and incidents."""
    conn = _open(database)
    try:
        counts = db.counts(conn)
        assets = db.list_assets(conn, limit=5)
        incidents = db.list_incidents(conn, limit=5)
    finally:
        conn.close()
    out.print(Text(f"VigilHub {__version__}  " + "  ".join(f"{k}={v}" for k, v in counts.items())))
    if incidents:
        table = Table(title="Incidents")
        for col in ("Severity", "Score", "Rule", "Title"):
            table.add_column(col)
        for i in incidents:
            table.add_row(
                Text(i.severity.value), Text(str(i.score)), Text(i.rule_id), Text(i.title)
            )
        out.print(table)
    if assets:
        table = Table(title="Top assets by risk")
        for col in ("Risk", "Asset", "Findings", "Tools"):
            table.add_column(col)
        for a in assets:
            table.add_row(
                Text(str(a.risk_score)),
                Text(a.id),
                Text(str(a.finding_count)),
                Text(",".join(s.value for s in a.sources)),
            )
        out.print(table)


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address (default loopback only).")] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535)] = 8000,
    database: DbOption = None,
) -> None:
    """Run the API server."""
    import uvicorn

    from vigilhub.api import create_app

    conn = _open(database)  # fail early if init-db hasn't been run
    conn.close()
    uvicorn.run(create_app(database), host=host, port=port, log_level="info")
