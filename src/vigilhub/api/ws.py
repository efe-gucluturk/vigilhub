"""Real-time event stream: ``WS /api/v1/ws``.

Authentication never uses the URL (query strings end up in access logs). A client either
sends ``X-API-Key`` on the handshake (non-browser clients) or, as browsers cannot set
WebSocket headers, a first text frame ``{"type": "auth", "api_key": "..."}`` within
``AUTH_TIMEOUT`` seconds. Anything else closes the socket with code 1008.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from vigilhub import db
from vigilhub.config import ALLOWED_ORIGINS, MAX_API_KEY_LENGTH

AUTH_TIMEOUT = 5.0
SEND_TIMEOUT = 2.0
MAX_CLIENTS = 100
MAX_CLIENT_FRAME = 1024  # clients only ever send tiny auth/ping frames

CLOSE_POLICY = 1008
CLOSE_TRY_LATER = 1013

router = APIRouter(prefix="/api/v1")


@dataclass(eq=False)
class _Client:
    ws: WebSocket
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)  # one writer at a time per socket


class ConnectionManager:
    """Tracks authenticated sockets and fans events out to them.

    Mutation of the client set is guarded by an ``asyncio.Lock``. Code running in worker
    threads must use :meth:`broadcast_threadsafe`, which hands the work to the event loop.
    """

    def __init__(self) -> None:
        self._clients: set[_Client] = set()
        self._lock = asyncio.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def count(self) -> int:
        return len(self._clients)

    async def add(self, ws: WebSocket) -> _Client | None:
        async with self._lock:
            if len(self._clients) >= MAX_CLIENTS:
                return None
            self._loop = asyncio.get_running_loop()
            client = _Client(ws)
            self._clients.add(client)
            return client

    async def remove(self, client: _Client) -> None:
        async with self._lock:
            self._clients.discard(client)

    async def _send(self, client: _Client, payload: str) -> bool:
        try:
            async with client.lock:
                await asyncio.wait_for(client.ws.send_text(payload), SEND_TIMEOUT)
        except Exception:
            return False
        return True

    async def send_to(self, client: _Client, message: dict[str, Any]) -> bool:
        return await self._send(client, json.dumps(message))

    async def broadcast(self, event_type: str, data: dict[str, Any]) -> int:
        """Send ``{"type", "ts", "data"}`` to every client; returns how many received it."""
        payload = json.dumps(
            {
                "type": event_type,
                "ts": datetime.now(UTC).isoformat(timespec="seconds"),
                "data": data,
            }
        )
        async with self._lock:
            clients = list(self._clients)
        results = await asyncio.gather(*(self._send(c, payload) for c in clients))
        dead = [c for c, ok in zip(clients, results, strict=True) if not ok]
        if dead:
            async with self._lock:
                self._clients.difference_update(dead)
        return len(clients) - len(dead)

    def broadcast_threadsafe(self, event_type: str, data: dict[str, Any]) -> None:
        """Schedule a broadcast from a non-event-loop thread (no-op if no client ever joined)."""
        loop = self._loop
        if loop is not None and loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast(event_type, data), loop)


def get_manager(request: Request) -> ConnectionManager:
    return request.app.state.ws_manager


async def _key_valid(ws: WebSocket, key: object) -> bool:
    if not isinstance(key, str) or not key or len(key) > MAX_API_KEY_LENGTH:
        return False

    def check() -> bool:
        conn = db.connect(ws.app.state.db_path)
        try:
            return db.verify_api_key(conn, key)
        finally:
            conn.close()

    return await run_in_threadpool(check)


async def _authenticate(ws: WebSocket) -> bool:
    header_key = ws.headers.get("x-api-key")
    if header_key is not None:
        return await _key_valid(ws, header_key)
    try:
        raw = await asyncio.wait_for(ws.receive_text(), AUTH_TIMEOUT)
        if len(raw) > MAX_CLIENT_FRAME:
            return False
        frame = json.loads(raw)
    except (TimeoutError, ValueError, WebSocketDisconnect, RuntimeError):
        return False
    return (
        isinstance(frame, dict)
        and frame.get("type") == "auth"
        and await _key_valid(ws, frame.get("api_key"))
    )


@router.websocket("/ws")
async def event_stream(ws: WebSocket) -> None:
    origin = ws.headers.get("origin")
    await ws.accept()  # accept first so the client can read the close code
    if origin is not None and origin not in ALLOWED_ORIGINS:
        await ws.close(code=CLOSE_POLICY, reason="origin not allowed")
        return
    if not await _authenticate(ws):
        await ws.close(code=CLOSE_POLICY, reason="authentication required")
        return

    manager: ConnectionManager = ws.app.state.ws_manager
    client = await manager.add(ws)
    if client is None:
        await ws.close(code=CLOSE_TRY_LATER, reason="too many clients")
        return
    try:
        await ws.send_text(json.dumps({"type": "auth_ok"}))
        while True:
            raw = await ws.receive_text()
            if len(raw) > MAX_CLIENT_FRAME:
                await ws.close(code=CLOSE_POLICY, reason="frame too large")
                return
            with contextlib.suppress(ValueError):
                frame = json.loads(raw)
                if isinstance(frame, dict) and frame.get("type") == "ping":
                    await manager.send_to(client, {"type": "pong"})
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await manager.remove(client)
