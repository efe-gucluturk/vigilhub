from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from vigilhub.config import MAX_BODY_BYTES
from vigilhub.demo import _gitvigil_report, _gitvigil_sarif, _recon_report, _siem_alerts

PROTECTED = [
    ("GET", "/api/v1/assets"),
    ("GET", "/api/v1/assets/ip:203.0.113.10"),
    ("GET", "/api/v1/findings"),
    ("GET", "/api/v1/incidents"),
    ("POST", "/api/v1/correlate"),
    ("POST", "/api/v1/incidents/" + "0" * 32 + "/analyze"),
    ("POST", "/api/v1/demo/seed"),
    ("POST", "/api/v1/ingest/vigilsiem"),
]


def test_health_is_open_and_has_security_headers(anon: TestClient):
    r = anon.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["referrer-policy"] == "no-referrer"


def test_docs_endpoints_disabled(anon: TestClient):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert anon.get(path).status_code == 404


@pytest.mark.parametrize(("method", "path"), PROTECTED)
def test_missing_key_rejected(anon: TestClient, method: str, path: str):
    r = anon.request(method, path, content=b"[]")
    assert r.status_code == 401
    assert r.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize(
    "bad_key", ["wrong", "", " ", "A" * 255, "x' OR '1'='1", "../../etc/passwd"]
)
def test_invalid_key_rejected(anon: TestClient, bad_key: str):
    r = anon.get("/api/v1/assets", headers={"X-API-Key": bad_key})
    assert r.status_code == 401


def test_overlong_key_rejected(anon: TestClient):
    r = anon.get("/api/v1/assets", headers={"X-API-Key": "A" * 5000})
    assert r.status_code in (401, 422)


def test_valid_key_accepted_and_revoked_key_rejected(client: TestClient, conn):
    assert client.get("/api/v1/assets").status_code == 200
    with conn:
        conn.execute("UPDATE api_keys SET revoked = 1")
    assert client.get("/api/v1/assets").status_code == 401


def test_oversized_declared_body_rejected(client: TestClient):
    body = b"[" + b"0," * (MAX_BODY_BYTES // 2 + 10) + b"0]"
    assert len(body) > MAX_BODY_BYTES
    r = client.post("/api/v1/ingest/vigilsiem", content=body)
    assert r.status_code == 413
    assert r.headers["x-content-type-options"] == "nosniff"


def test_oversized_chunked_body_rejected(client: TestClient):
    def chunks():
        for _ in range(MAX_BODY_BYTES // 65536 + 2):
            yield b"0" * 65536  # no Content-Length: forces the streaming guard

    r = client.post("/api/v1/ingest/vigilsiem", content=chunks())
    assert r.status_code == 413


def test_body_at_limit_is_not_a_size_error(client: TestClient):
    padding = " " * (MAX_BODY_BYTES - 2)
    r = client.post("/api/v1/ingest/vigilsiem", content="[" + padding + "]")
    assert r.status_code == 200  # exactly at the limit is accepted; an empty export is valid
    assert r.json()["accepted"] == 0


@pytest.mark.parametrize("payload", [b"{not json", b"", b"\xff\xfe\x00", b"[" * 50_000])
def test_malformed_json_rejected(client: TestClient, payload: bytes):
    r = client.post("/api/v1/ingest/vigilsiem", content=payload)
    assert r.status_code == 400
    assert r.json()["detail"] == "malformed JSON"


def test_wrong_shape_rejected_with_422(client: TestClient):
    for source in ("vigilsiem", "gitvigil", "reconvigil"):
        r = client.post(f"/api/v1/ingest/{source}", json={"hello": "world"})
        assert r.status_code == 422, source


def test_unknown_source_rejected(client: TestClient):
    assert client.post("/api/v1/ingest/nessus", json=[]).status_code == 422


def test_ingest_all_three_sources_and_idempotency(client: TestClient):
    payloads = {
        "reconvigil": _recon_report(),
        "gitvigil": _gitvigil_report(),
        "vigilsiem": _siem_alerts(),
    }
    for source, payload in payloads.items():
        r = client.post(f"/api/v1/ingest/{source}", json=payload)
        assert r.status_code == 200, r.text
        assert r.json()["source"] == source
    total = len(client.get("/api/v1/findings", params={"limit": 500}).json())
    again = client.post("/api/v1/ingest/gitvigil", json=payloads["gitvigil"])
    assert again.status_code == 200
    assert len(client.get("/api/v1/findings", params={"limit": 500}).json()) == total


def test_sarif_ingest_with_target_override(client: TestClient):
    sarif = _gitvigil_sarif()
    del sarif["runs"][0]["versionControlProvenance"]
    assert client.post("/api/v1/ingest/gitvigil", json=sarif).status_code == 422
    r = client.post("/api/v1/ingest/gitvigil", params={"target": "org/site"}, json=sarif)
    assert r.status_code == 200
    assert client.get("/api/v1/assets/repo:site").status_code == 200


def test_seed_correlate_and_query_flow(client: TestClient):
    seeded = client.post("/api/v1/demo/seed")
    assert seeded.status_code == 200
    body = seeded.json()
    assert body["correlation"]["incidents"] == 1
    assert {i["source"] for i in body["ingested"]} == {"vigilsiem", "gitvigil", "reconvigil"}

    (incident,) = client.get("/api/v1/incidents").json()
    assert incident["severity"] == "critical"
    assert incident["rule_id"] == "KC-001"
    assert len(incident["steps"]) >= 4

    assert client.post("/api/v1/correlate").json()["incidents"] == 1

    assets = client.get("/api/v1/assets").json()
    assert assets == sorted(assets, key=lambda a: (-a["risk_score"], a["id"]))
    detail = client.get("/api/v1/assets/domain:staging.acmecorp.example").json()
    assert detail["asset"]["risk_score"] > 0
    assert incident["id"] in detail["incident_ids"] or "ip:203.0.113.10" in incident["asset_ids"]
    assert detail["findings"]

    assert client.get("/api/v1/assets/domain:nope.example").status_code == 404


def test_finding_filters(client: TestClient):
    client.post("/api/v1/demo/seed")
    by_src = client.get("/api/v1/findings", params={"source": "gitvigil"}).json()
    assert by_src
    assert {f["source"] for f in by_src} == {"gitvigil"}
    crit = client.get("/api/v1/findings", params={"severity": "critical"}).json()
    assert [f["rule_id"] for f in crit] == ["aws-access-key-id"]
    by_asset = client.get("/api/v1/findings", params={"asset": "Staging.AcmeCorp.Example"}).json()
    assert {f["rule_id"] for f in by_asset} == {"exposed-dotenv", "exposed-swagger-json"}
    by_repo = client.get("/api/v1/findings", params={"asset": "acmecorp-web"}).json()
    assert {f["source"] for f in by_repo} == {"gitvigil"}
    both = client.get("/api/v1/findings", params={"source": "reconvigil", "severity": "high"})
    assert [f["rule_id"] for f in both.json()] == ["exposed-dotenv"]
    assert client.get("/api/v1/findings", params={"severity": "bogus"}).status_code == 422
    assert client.get("/api/v1/findings", params={"limit": 0}).status_code == 422
    assert client.get("/api/v1/findings", params={"limit": 501}).status_code == 422


@pytest.mark.parametrize(
    "evil", ["' OR 1=1 --", "x'; DROP TABLE findings; --", '" UNION SELECT * FROM api_keys --']
)
def test_sql_injection_attempts_are_inert(client: TestClient, conn, evil: str):
    client.post("/api/v1/demo/seed")
    for params in ({"asset": evil}, {"source": evil}, {"severity": evil}):
        r = client.get("/api/v1/findings", params=params)
        assert r.status_code in (200, 422)
        if r.status_code == 200:
            assert r.json() == []
    assert client.get(f"/api/v1/assets/{evil}").status_code == 404
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] > 0


def test_xss_and_control_chars_in_ingested_findings(client: TestClient, conn):
    xss = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    doc = _recon_report()
    doc["scan"]["findings"] = [
        {
            "rule_id": "exposed-dotenv\x00",
            "title": f"{xss}\x1b[31m‮RTL⁦​",
            "severity": "HIGH",
            "cwe": "CWE-79",
            "asset": "staging.acmecorp.example",
            "location": "https://staging.acmecorp.example/\r\nSet-Cookie: pwn=1",
            "description": f"line1\nline2 {xss}",
            "remediation": "x",
            "evidence": f"\x07bell {xss}",
            "category": "exposure",
        }
    ]
    r = client.post("/api/v1/ingest/reconvigil", json=doc)
    assert r.status_code == 200

    r = client.get("/api/v1/findings")
    assert r.headers["content-type"].startswith("application/json")
    assert r.headers["x-content-type-options"] == "nosniff"
    (f,) = r.json()
    for field in ("rule_id", "title", "location", "description"):
        assert not any(ord(c) < 32 for c in f[field]), field
    assert "‮" not in f["title"]
    assert "⁦" not in f["title"]
    assert "​" not in f["title"]
    assert "\r" not in f["location"]
    assert "\x07" not in json.dumps(f)
    # the markup itself is kept as inert JSON text (UIs must escape on output)
    assert "<script>" in f["title"]
    stored = conn.execute("SELECT title, evidence FROM findings").fetchone()
    assert "\x1b" not in stored["title"]
    assert "\x07" not in stored["evidence"]


def test_hostile_targets_are_rejected_not_stored(client: TestClient, conn):
    doc = _recon_report()
    for finding in doc["scan"]["findings"]:
        finding["asset"] = "<script>alert(1)</script>"
    assert client.post("/api/v1/ingest/reconvigil", json=doc).status_code == 422
    assert conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0

    alerts = _siem_alerts()
    alerts[0]["events"][0]["destination_ip"] = "1.2.3.4; DROP TABLE assets"
    r = client.post("/api/v1/ingest/vigilsiem", json=alerts)
    assert r.status_code == 200  # the other alerts are fine; the hostile target was dropped
    assert "DROP" not in " ".join(row["id"] for row in conn.execute("SELECT id FROM assets"))


def test_gitvigil_raw_secret_not_persisted(client: TestClient, conn):
    doc = _gitvigil_report()
    doc["findings"][0]["secret"] = "AKIAIOSFODNN7REALKEY"
    assert client.post("/api/v1/ingest/gitvigil", json=doc).status_code == 200
    dump = "\n".join(conn.iterdump())
    assert "AKIAIOSFODNN7REALKEY" not in dump


def test_rate_limit_returns_429() -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from vigilhub.api.middleware import RateLimitMiddleware

    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, limit=2, window=60.0)

    @app.get("/api/x")
    def x() -> dict[str, int]:
        return {"ok": 1}

    client = TestClient(app)
    assert [client.get("/api/x").status_code for _ in range(3)] == [200, 200, 429]
