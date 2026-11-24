"""FastAPI dependencies: per-request DB connection and API-key authentication."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request

from vigilhub import db


def get_conn(request: Request) -> Iterator[sqlite3.Connection]:
    conn = db.connect(request.app.state.db_path)
    try:
        yield conn
    finally:
        conn.close()


Conn = Annotated[sqlite3.Connection, Depends(get_conn)]


def require_api_key(
    conn: Conn,
    x_api_key: Annotated[str | None, Header(max_length=256)] = None,
) -> None:
    if not db.verify_api_key(conn, x_api_key):
        # Same response for missing and wrong keys: no oracle for which one it was.
        raise HTTPException(status_code=401, detail="invalid or missing API key")
