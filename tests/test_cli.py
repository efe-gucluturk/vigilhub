from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vigilhub import db
from vigilhub.cli import app
from vigilhub.config import MAX_BODY_BYTES
from vigilhub.demo import _gitvigil_report, _gitvigil_sarif, _recon_report, _siem_alerts

runner = CliRunner()


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("VIGILHUB_DB", str(tmp_path / "cli.db"))
    monkeypatch.setenv("VIGILHUB_KEY_FILE", str(tmp_path / ".vigilhub_key"))
    return tmp_path


def _write(tmp: Path, name: str, doc) -> Path:
    path = tmp / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_init_db_creates_db_and_key(env: Path):
    res = runner.invoke(app, ["init-db"])
    assert res.exit_code == 0, res.output
    assert (env / "cli.db").exists()
    key = (env / ".vigilhub_key").read_text(encoding="utf-8").strip()
    assert key
    assert key not in res.output  # the key is never echoed
    again = runner.invoke(app, ["init-db"])
    assert again.exit_code == 0
    assert (env / ".vigilhub_key").read_text(encoding="utf-8").strip() == key


def test_commands_require_init(env: Path):
    for cmd in (["status"], ["correlate"], ["seed-demo"]):
        res = runner.invoke(app, cmd)
        assert res.exit_code == 2
        assert "init-db" in res.output


def test_ingest_each_source_then_correlate_and_status(env: Path):
    runner.invoke(app, ["init-db"])
    files = {
        "reconvigil": _write(env, "r.json", _recon_report()),
        "gitvigil": _write(env, "g.json", _gitvigil_report()),
        "vigilsiem": _write(env, "s.json", _siem_alerts()),
    }
    for source, path in files.items():
        res = runner.invoke(app, ["ingest", source, str(path)])
        assert res.exit_code == 0, res.output
        assert "findings stored" in res.output
    sarif = _write(env, "g.sarif", _gitvigil_sarif())
    assert runner.invoke(app, ["ingest", "gitvigil", str(sarif)]).exit_code == 0

    res = runner.invoke(app, ["correlate"])
    assert res.exit_code == 0
    assert "1 incidents" in res.output
    assert "critical=1" in res.output

    res = runner.invoke(app, ["status"])
    assert res.exit_code == 0
    assert "KC-001" in res.output
    assert "staging.acmecorp.example" in res.output


def test_seed_demo(env: Path):
    runner.invoke(app, ["init-db"])
    res = runner.invoke(app, ["seed-demo"])
    assert res.exit_code == 0, res.output
    for source in ("vigilsiem", "gitvigil", "reconvigil"):
        assert source in res.output
    assert "1 incidents" in res.output


def test_ingest_rejects_bad_inputs(env: Path):
    runner.invoke(app, ["init-db"])
    bad_json = env / "bad.json"
    bad_json.write_text("{nope", encoding="utf-8")
    assert runner.invoke(app, ["ingest", "vigilsiem", str(bad_json)]).exit_code == 2
    assert runner.invoke(app, ["ingest", "vigilsiem", str(env / "missing.json")]).exit_code == 2
    wrong = _write(env, "w.json", {"hello": "world"})
    assert runner.invoke(app, ["ingest", "reconvigil", str(wrong)]).exit_code == 2
    assert runner.invoke(app, ["ingest", "nessus", str(wrong)]).exit_code != 0


def test_ingest_enforces_2mb_limit(env: Path):
    runner.invoke(app, ["init-db"])
    big = env / "big.json"
    big.write_text("[" + " " * MAX_BODY_BYTES + "]", encoding="utf-8")
    res = runner.invoke(app, ["ingest", "vigilsiem", str(big)])
    assert res.exit_code == 2
    assert "limit" in res.output


def test_rich_markup_in_findings_is_not_interpreted(env: Path):
    runner.invoke(app, ["init-db"])
    doc = _recon_report()
    doc["scan"]["findings"][0]["title"] = "[bold red]pwned[/bold red] [link=http://x]y[/link]"
    runner.invoke(app, ["ingest", "reconvigil", str(_write(env, "m.json", doc))])
    runner.invoke(app, ["seed-demo"])  # adds incidents/assets to the status view
    res = runner.invoke(app, ["status"])
    assert res.exit_code == 0


def test_serve_refuses_without_db(env: Path):
    res = runner.invoke(app, ["serve"])
    assert res.exit_code == 2


def test_serve_starts_uvicorn_on_loopback(env: Path, monkeypatch):
    runner.invoke(app, ["init-db"])
    seen = {}
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda application, **kw: seen.update(kw))
    res = runner.invoke(app, ["serve", "--port", "9123"])
    assert res.exit_code == 0, res.output
    assert seen["host"] == "127.0.0.1"
    assert seen["port"] == 9123


def test_key_file_is_gitignored():
    ignore = (Path(__file__).parent.parent / ".gitignore").read_text(encoding="utf-8")
    assert ".vigilhub_key" in ignore.splitlines()
    assert "*.db" in ignore.splitlines()


def test_cli_db_state_matches_api_store(env: Path):
    runner.invoke(app, ["init-db"])
    runner.invoke(app, ["seed-demo"])
    conn = db.connect(env / "cli.db")
    assert db.counts(conn)["incidents"] == 1
    conn.close()
