from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vigilhub import db
from vigilhub.api import create_app


@pytest.fixture
def db_file(tmp_path: Path) -> Path:
    return tmp_path / "hub.db"


@pytest.fixture
def conn(db_file: Path) -> Iterator[sqlite3.Connection]:
    c = db.connect(db_file)
    db.init_schema(c)
    yield c
    c.close()


@pytest.fixture
def api_key(conn: sqlite3.Connection, tmp_path: Path) -> str:
    key_file = tmp_path / ".vigilhub_key"
    db.ensure_api_key(conn, key_file)
    return key_file.read_text(encoding="utf-8").strip()


@pytest.fixture
def client(db_file: Path, conn: sqlite3.Connection, api_key: str) -> TestClient:
    return TestClient(create_app(db_file), headers={"X-API-Key": api_key})


@pytest.fixture
def anon(db_file: Path, conn: sqlite3.Connection) -> TestClient:
    return TestClient(create_app(db_file))
