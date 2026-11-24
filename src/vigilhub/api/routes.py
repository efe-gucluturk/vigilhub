"""Authenticated /api/v1 routes."""

from __future__ import annotations

import contextlib
import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from vigilhub import db, service
from vigilhub.adapters import AdapterError
from vigilhub.api.deps import Conn, require_api_key
from vigilhub.correlation.normalize import normalize_target
from vigilhub.models import Asset, Finding, Incident, Severity, Source
from vigilhub.sanitize import sanitize_text

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])

Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]


class IngestOut(BaseModel):
    source: str
    accepted: int
    skipped: int
    warnings: list[str]


class CorrelateOut(BaseModel):
    assets: int
    findings: int
    incidents: int
    by_severity: dict[str, int]


class AssetDetail(BaseModel):
    asset: Asset
    findings: list[Finding]
    incident_ids: list[str]


class SeedOut(BaseModel):
    ingested: list[IngestOut]
    correlation: CorrelateOut


@router.post("/ingest/{source}", response_model=IngestOut)
async def ingest(
    source: Source,
    request: Request,
    conn: Conn,
    target: Annotated[str | None, Query(max_length=512)] = None,
) -> IngestOut:
    body = await request.body()  # size already bounded by SecurityMiddleware
    try:
        data = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise HTTPException(status_code=400, detail="malformed JSON") from exc
    try:
        summary = await run_in_threadpool(service.ingest, conn, source, data, target=target)
    except AdapterError as exc:
        raise HTTPException(status_code=422, detail=sanitize_text(exc, 300)) from exc
    return IngestOut(**vars(summary))


@router.get("/assets", response_model=list[Asset])
def list_assets(conn: Conn, limit: Limit = 100, offset: Offset = 0) -> list[Asset]:
    return db.list_assets(conn, limit, offset)


@router.get("/assets/{asset_id:path}", response_model=AssetDetail)
def get_asset(asset_id: str, conn: Conn) -> AssetDetail:
    asset = db.get_asset(conn, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found")
    return AssetDetail(
        asset=asset,
        findings=db.query_findings(conn, asset_ids=[asset.id], limit=500),
        incident_ids=db.incident_ids_for_asset(conn, asset.id),
    )


@router.get("/findings", response_model=list[Finding])
def list_findings(
    conn: Conn,
    source: Source | None = None,
    severity: Severity | None = None,
    asset: Annotated[str | None, Query(max_length=512)] = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> list[Finding]:
    asset_ids = None
    if asset:
        # Accept "staging.example.com" as well as the canonical "domain:staging.example.com";
        # a bare name may be a domain, host, ip or repo, so match all candidate kinds.
        asset_ids = [asset]
        for hint in ("host", "repo"):
            with contextlib.suppress(ValueError):
                asset_ids.append(normalize_target(asset, hint).key)
    return db.query_findings(
        conn,
        source=source.value if source else None,
        severity=severity.value if severity else None,
        asset_ids=asset_ids,
        limit=limit,
        offset=offset,
    )


@router.get("/incidents", response_model=list[Incident])
def list_incidents(conn: Conn, limit: Limit = 100, offset: Offset = 0) -> list[Incident]:
    return db.list_incidents(conn, limit, offset)


@router.post("/correlate", response_model=CorrelateOut)
def correlate(conn: Conn) -> CorrelateOut:
    return CorrelateOut(**vars(service.run_correlation(conn)))


@router.post("/demo/seed", response_model=SeedOut)
def seed_demo(conn: Conn) -> SeedOut:
    summaries, correlation = service.seed_demo(conn)
    return SeedOut(
        ingested=[IngestOut(**vars(s)) for s in summaries],
        correlation=CorrelateOut(**vars(correlation)),
    )
