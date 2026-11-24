"""FastAPI application factory."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from vigilhub import __version__
from vigilhub.api.middleware import SecurityMiddleware
from vigilhub.api.routes import router
from vigilhub.config import MAX_BODY_BYTES, db_path


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
    app.add_middleware(SecurityMiddleware, max_body=MAX_BODY_BYTES)
    app.include_router(router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app
