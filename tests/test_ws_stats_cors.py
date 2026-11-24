from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from vigilhub.api import create_app, ws
from vigilhub.demo import _gitvigil_report

WS = "/api/v1/ws"


@pytest.fixture
def live(db_file: Path, conn, api_key: str) -> Iterator[TestClient]:
    # Entering the context keeps one event loop alive for HTTP and WebSocket traffic alike.
    # No default headers: the test client would also send them on the WebSocket handshake,
    # silently authenticating sockets that are meant to be anonymous.
    with TestClient(create_app(db_file)) as c:
        c.key = api_key  # type: ignore[attr-defined]
        yield c


def hpost(c: TestClient, path: str, **kw):
    return c.post(path, headers={"X-API-Key": c.key}, **kw)  # type: ignore[attr-defined]


def _expect_close(client: TestClient, *, headers=None, frame=None, url: str = WS) -> int:
    with (
        pytest.raises(WebSocketDisconnect) as exc,
        client.websocket_connect(url, headers=headers or {}) as sock,
    ):
        if frame is not None:
            sock.send_text(frame if isinstance(frame, str) else json.dumps(frame))
        sock.receive_text()
    return exc.value.code


def _auth(sock, key: str) -> None:
    sock.send_json({"type": "auth", "api_key": key})
    assert sock.receive_json() == {"type": "auth_ok"}


# ---- authentication ----


def test_ws_no_auth_frame_times_out_with_1008(live: TestClient, monkeypatch):
    monkeypatch.setattr(ws, "AUTH_TIMEOUT", 0.2)
    assert _expect_close(live, headers=None) == 1008


@pytest.mark.parametrize(
    "frame",
    [
        {"type": "auth", "api_key": "wrong"},
        {"type": "auth", "api_key": ""},
        {"type": "auth", "api_key": None},
        {"type": "auth", "api_key": "A" * 1000},
        {"type": "auth"},
        {"type": "hello", "api_key": "x"},
        "not json",
        "[]",
        "x" * 5000,
    ],
)
def test_ws_bad_auth_frame_rejected_1008(live: TestClient, frame):
    assert _expect_close(live, frame=frame) == 1008


def test_ws_wrong_header_key_rejected_1008(live: TestClient):
    assert _expect_close(live, headers={"X-API-Key": "nope"}) == 1008


def test_ws_key_in_query_string_is_not_accepted(live: TestClient, api_key: str):
    # Even a *valid* key in the URL must not authenticate the socket.
    assert _expect_close(live, url=f"{WS}?api_key={api_key}") == 1008


def test_ws_revoked_key_rejected(live: TestClient, conn, api_key: str):
    with conn:
        conn.execute("UPDATE api_keys SET revoked = 1")
    assert _expect_close(live, frame={"type": "auth", "api_key": api_key}) == 1008


def test_ws_foreign_origin_rejected_even_with_valid_key(live: TestClient, api_key: str):
    code = _expect_close(live, headers={"Origin": "https://evil.example", "X-API-Key": api_key})
    assert code == 1008


def test_ws_header_auth_and_frame_auth_both_work(live: TestClient, api_key: str):
    with live.websocket_connect(WS, headers={"X-API-Key": api_key}) as sock:
        assert sock.receive_json() == {"type": "auth_ok"}
    with live.websocket_connect(WS, headers={"Origin": "http://localhost:3000"}) as sock:
        _auth(sock, api_key)
        sock.send_json({"type": "ping"})
        assert sock.receive_json() == {"type": "pong"}


# ---- broadcasts ----


def test_demo_seed_broadcasts_to_authenticated_client(live: TestClient, api_key: str):
    with live.websocket_connect(WS) as sock:
        _auth(sock, api_key)
        assert hpost(live, "/api/v1/demo/seed").status_code == 200
        event = sock.receive_json()
    assert event["type"] == "demo_seeded"
    assert event["ts"]
    data = event["data"]
    assert data["correlation"]["incidents"] == 1
    assert {i["source"] for i in data["ingested"]} == {"vigilsiem", "gitvigil", "reconvigil"}


def test_ingest_and_correlate_broadcast(live: TestClient, api_key: str):
    with live.websocket_connect(WS) as sock:
        _auth(sock, api_key)
        r = hpost(live, "/api/v1/ingest/gitvigil", json=_gitvigil_report())
        assert r.status_code == 200
        ev = sock.receive_json()
        assert ev["type"] == "ingest_completed"
        assert ev["data"] == {"source": "gitvigil", "accepted": 2, "skipped": 0}

        assert hpost(live, "/api/v1/correlate").status_code == 200
        ev = sock.receive_json()
        assert ev["type"] == "correlation_updated"
        assert ev["data"]["findings"] == 2
        assert ev["data"]["incidents"] == 0


def test_failed_ingest_does_not_broadcast(live: TestClient, api_key: str):
    with live.websocket_connect(WS) as sock:
        _auth(sock, api_key)
        assert hpost(live, "/api/v1/ingest/vigilsiem", content=b"{bad").status_code == 400
        assert hpost(live, "/api/v1/ingest/vigilsiem", json={"x": 1}).status_code == 422
        assert hpost(live, "/api/v1/correlate").status_code == 200
        assert sock.receive_json()["type"] == "correlation_updated"  # first event is this one


def test_all_clients_receive_and_dead_clients_are_dropped(live: TestClient, api_key: str):
    manager = live.app.state.ws_manager
    with live.websocket_connect(WS) as a, live.websocket_connect(WS) as b:
        _auth(a, api_key)
        _auth(b, api_key)
        assert manager.count == 2
        hpost(live, "/api/v1/correlate")
        assert a.receive_json()["type"] == b.receive_json()["type"] == "correlation_updated"
    hpost(live, "/api/v1/correlate")  # both gone: must not raise
    assert manager.count == 0


def test_unauthenticated_socket_never_receives_events(live: TestClient, monkeypatch):
    monkeypatch.setattr(ws, "AUTH_TIMEOUT", 0.3)
    manager = live.app.state.ws_manager
    with pytest.raises(WebSocketDisconnect), live.websocket_connect(WS) as sock:
        hpost(live, "/api/v1/correlate")
        assert manager.count == 0
        sock.receive_text()


def test_broadcast_threadsafe_from_worker_thread(live: TestClient, api_key: str):
    manager = live.app.state.ws_manager
    with live.websocket_connect(WS) as sock:
        _auth(sock, api_key)
        t = threading.Thread(target=manager.broadcast_threadsafe, args=("demo_seeded", {"n": 1}))
        t.start()
        t.join()
        ev = sock.receive_json()
    assert ev["type"] == "demo_seeded"
    assert ev["data"] == {"n": 1}


def test_client_cap(live: TestClient, api_key: str, monkeypatch):
    monkeypatch.setattr(ws, "MAX_CLIENTS", 1)
    with live.websocket_connect(WS) as first:
        _auth(first, api_key)
        assert _expect_close(live, frame={"type": "auth", "api_key": api_key}) == 1013


# ---- /stats ----


def test_stats_requires_key(anon: TestClient):
    assert anon.get("/api/v1/stats").status_code == 401
    assert anon.get("/api/v1/stats", headers={"X-API-Key": "bad"}).status_code == 401


def test_stats_empty_has_all_keys_zeroed(client: TestClient):
    body = client.get("/api/v1/stats").json()
    assert body["total_assets"] == body["total_findings"] == body["total_incidents"] == 0
    assert body["findings_by_severity"] == dict.fromkeys(
        ["info", "low", "medium", "high", "critical"], 0
    )
    assert body["findings_by_source"] == dict.fromkeys(["vigilsiem", "gitvigil", "reconvigil"], 0)
    assert body["incidents_by_severity"]["critical"] == 0


def test_stats_counts_are_accurate_after_seed(client: TestClient, conn):
    client.post("/api/v1/demo/seed")
    body = client.get("/api/v1/stats").json()
    assert body["total_assets"] == 7
    assert body["total_findings"] == 10
    assert body["total_incidents"] == 1
    assert body["findings_by_source"] == {"vigilsiem": 3, "gitvigil": 3, "reconvigil": 4}
    assert body["findings_by_severity"] == {
        "info": 0, "low": 1, "medium": 5, "high": 3, "critical": 1,
    }  # fmt: skip
    assert body["incidents_by_severity"] == {
        "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 1,
    }  # fmt: skip
    # cross-check against the database directly, not just the fixed numbers above
    rows = conn.execute("SELECT severity, COUNT(*) n FROM findings GROUP BY severity").fetchall()
    for row in rows:
        assert body["findings_by_severity"][row["severity"]] == row["n"]
    assert sum(body["findings_by_severity"].values()) == body["total_findings"]
    assert sum(body["findings_by_source"].values()) == body["total_findings"]


# ---- CORS ----


@pytest.mark.parametrize("origin", ["http://localhost:3000", "http://127.0.0.1:3000"])
def test_cors_allows_dashboard_origins(anon: TestClient, origin: str):
    pre = anon.options(
        "/api/v1/stats",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-api-key",
        },
    )
    assert pre.status_code == 200
    assert pre.headers["access-control-allow-origin"] == origin
    assert "x-api-key" in pre.headers["access-control-allow-headers"].lower()
    resp = anon.get("/health", headers={"Origin": origin})
    assert resp.headers["access-control-allow-origin"] == origin
    assert "access-control-allow-credentials" not in resp.headers
    # errors carry CORS headers too, so the dashboard can read a 401 instead of a network error
    denied = anon.get("/api/v1/stats", headers={"Origin": origin})
    assert denied.status_code == 401
    assert denied.headers["access-control-allow-origin"] == origin


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "http://localhost:3001",
        "http://localhost",
        "null",
        "http://localhost.evil.example:3000",
    ],
)
def test_cors_rejects_other_origins(anon: TestClient, origin: str):
    pre = anon.options(
        "/api/v1/stats",
        headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
    )
    assert pre.status_code == 400
    assert "access-control-allow-origin" not in pre.headers
    resp = anon.get("/health", headers={"Origin": origin})
    assert "access-control-allow-origin" not in resp.headers
