"""FastAPI application factory."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from vigilhub import __version__
from vigilhub.api.middleware import RateLimitMiddleware, SecurityMiddleware
from vigilhub.api.routes import router
from vigilhub.api.ws import ConnectionManager
from vigilhub.api.ws import router as ws_router
from vigilhub.config import (
    ALLOWED_ORIGINS,
    MAX_BODY_BYTES,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    db_path,
)


def create_app(database: Path | str | None = None) -> FastAPI:
    # No interactive docs / openapi.json: smaller unauthenticated surface.
    app = FastAPI(
        title="VigilHub",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.db_path = str(db_path(database))
    app.state.ws_manager = ConnectionManager()
    app.add_middleware(SecurityMiddleware, max_body=MAX_BODY_BYTES)
    app.add_middleware(
        RateLimitMiddleware, limit=RATE_LIMIT_REQUESTS, window=RATE_LIMIT_WINDOW_SECONDS
    )
    # Added last = outermost, so preflights are answered before auth and every response
    # (including 401/413) carries CORS headers. Only the local dashboard origins are allowed.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(ALLOWED_ORIGINS),
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Content-Type"],
        allow_credentials=False,
        max_age=600,
    )
    app.include_router(router)
    app.include_router(ws_router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app
