"""Pure-ASGI middleware: request size guard and security headers."""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SECURITY_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    b"referrer-policy": b"no-referrer",
    b"content-security-policy": b"default-src 'none'; frame-ancestors 'none'",
    b"cache-control": b"no-store",
    b"permissions-policy": b"geolocation=(), microphone=(), camera=()",
    b"cross-origin-resource-policy": b"same-origin",
}


class PayloadTooLargeError(Exception):
    pass


class SecurityMiddleware:
    """Rejects bodies over ``max_body`` (declared or streamed) and adds security headers."""

    def __init__(self, app: ASGIApp, max_body: int) -> None:
        self.app = app
        self.max_body = max_body

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = [
                    (k, v) for k, v in message.get("headers", []) if k not in SECURITY_HEADERS
                ]
                headers.extend(SECURITY_HEADERS.items())
                message = {**message, "headers": headers}
            await send(message)

        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_body
            except ValueError:
                too_big = True  # unparseable length: refuse rather than guess
            if too_big:
                await self._reject(scope, receive, send_with_headers)
                return

        seen = 0

        async def counting_receive() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_body:
                    raise PayloadTooLargeError
            return message

        try:
            await self.app(scope, counting_receive, send_with_headers)
        except PayloadTooLargeError:
            if started:
                raise
            await self._reject(scope, receive, send_with_headers)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            {"detail": f"payload exceeds {self.max_body} bytes"},
            status_code=413,
            headers={"Connection": "close"},
        )
        await response(scope, receive, send)
