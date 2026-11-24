from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from vigilhub import db


def test_wal_mode_and_foreign_keys(db_file: Path, conn: sqlite3.Connection):
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert db.has_schema(conn)


def test_api_key_stored_only_as_sha256(conn: sqlite3.Connection, tmp_path: Path):
    key_file = tmp_path / "k"
    assert db.ensure_api_key(conn, key_file) is True
    raw = key_file.read_text(encoding="utf-8").strip()
    (stored,) = [r["key_hash"] for r in conn.execute("SELECT key_hash FROM api_keys")]
    assert stored == hashlib.sha256(raw.encode()).hexdigest()
    assert raw not in "\n".join(conn.iterdump())
    assert len(raw) >= 40  # 256 bits of urlsafe entropy


def test_ensure_api_key_is_idempotent_and_rebinds_existing_file(
    conn: sqlite3.Connection, tmp_path: Path
):
    key_file = tmp_path / "k"
    db.ensure_api_key(conn, key_file)
    assert db.ensure_api_key(conn, key_file) is False
    assert conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0] == 1
    other = db.connect(tmp_path / "fresh.db")  # key file from an older DB gets re-registered
    db.init_schema(other)
    assert db.ensure_api_key(other, key_file) is False
    assert db.verify_api_key(other, key_file.read_text(encoding="utf-8").strip())
    other.close()


def test_verify_api_key(conn: sqlite3.Connection):
    raw = db.create_api_key(conn, "t")
    assert db.verify_api_key(conn, raw)
    assert not db.verify_api_key(conn, raw + "x")
    assert not db.verify_api_key(conn, None)
    assert not db.verify_api_key(conn, "")
    assert not db.verify_api_key(conn, "é" * 10)  # non-ASCII must not raise


def test_verify_uses_compare_digest(conn: sqlite3.Connection, monkeypatch):
    calls = []
    real = db.hmac.compare_digest
    monkeypatch.setattr(db.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    db.create_api_key(conn, "a")
    raw = db.create_api_key(conn, "b")
    assert db.verify_api_key(conn, raw)
    assert len(calls) == 2  # every active hash is compared; no early exit
