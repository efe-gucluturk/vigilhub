"""VigilSIEM adapter.

VigilSIEM exposes alerts through ``GET /alerts`` (``AlertOut``/``AlertDetail``: lowercase
severities, nested ``events`` with ``destination_ip``). Accepted documents:

* a JSON list of alert objects,
* ``{"alerts": [...]}`` (a wrapped export),
* a single alert object,
* a list of raw security events (``event_category`` present, no ``rule_id``).

An alert's asset is the *victim*: an explicit ``host``, else the first event ``meta.host`` /
``destination_ip``. Only if none exists does the attacker ``source_ip`` stand in, tagged
``attacker-source`` in the evidence.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vigilhub.adapters.base import AdapterError, ParseResult, dedupe, finding_id
from vigilhub.correlation.normalize import normalize_target
from vigilhub.models import Finding, Source, parse_severity

_HOST_META_KEYS = ("host", "hostname", "dest_host", "server")
_MAX_EVENTS_SAMPLED = 3


class _Event(BaseModel):
    model_config = ConfigDict(extra="ignore")

    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    category: str | None = None
    event_category: str | None = None
    action: str | None = None
    status: str | None = None
    raw_log: str | None = None
    timestamp: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class _Alert(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int | str | None = None
    rule_id: str
    rule_name: str | None = None
    severity: str
    status: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    mitre_technique_name: str | None = None
    source_ip: str | None = None
    username: str | None = None
    summary: str | None = None
    created_at: str | None = None
    host: str | None = None
    events: list[_Event] = Field(default_factory=list)


def _extract_items(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("alerts"), list):
            return data["alerts"]
        if "rule_id" in data:
            return [data]
    raise AdapterError("not a VigilSIEM alert export (expected list or {'alerts': [...]})")


def _targets(alert: _Alert) -> tuple[list[str], str]:
    """Candidate asset keys (victim side first) and the role of the primary one."""
    candidates: list[str] = []
    if alert.host:
        candidates.append(alert.host)
    for ev in alert.events:
        meta = {**ev.metadata, **ev.meta}
        candidates.extend(str(meta[k]) for k in _HOST_META_KEYS if meta.get(k))
        if ev.destination_ip:
            candidates.append(ev.destination_ip)
    keys: list[str] = []
    for cand in candidates:
        try:
            keys.append(normalize_target(cand, "host").key)
        except ValueError:
            continue
    if keys:
        return dedupe(keys), "victim"
    if alert.source_ip:
        try:
            return [normalize_target(alert.source_ip, "host").key], "attacker-source"
        except ValueError:
            pass
    return [], ""


def _alert_to_finding(alert: _Alert) -> Finding:
    keys, role = _targets(alert)
    if not keys:
        raise ValueError("alert has no usable target")
    severity = parse_severity(alert.severity)
    events = [e for e in alert.events if e.action or e.raw_log]
    sample = [
        {
            "action": e.action,
            "status": e.status,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "raw_log": (e.raw_log or "")[:200],
        }
        for e in events[:_MAX_EVENTS_SAMPLED]
    ]
    evidence = {
        "alert_id": alert.id,
        "role": role,
        "mitre_tactic": alert.mitre_tactic,
        "mitre_technique": alert.mitre_technique,
        "mitre_technique_name": alert.mitre_technique_name,
        "source_ip": alert.source_ip,
        "username": alert.username,
        "event_count": len(alert.events),
        "sample_events": sample,
    }
    title = alert.rule_name or alert.rule_id
    return Finding(
        id=finding_id(Source.VIGILSIEM, alert.rule_id, keys[0], alert.id, alert.source_ip),
        source=Source.VIGILSIEM,
        rule_id=alert.rule_id,
        title=title,
        severity=severity,
        category="alert",
        asset=keys[0],
        aliases=keys[1:],
        description=alert.summary or "",
        evidence={k: v for k, v in evidence.items() if v not in (None, "", [])},
        observed_at=alert.created_at,
    )


def _event_to_alert(raw: dict[str, Any]) -> _Alert:
    """Wrap a bare security event so it flows through the alert path (info/low only)."""
    if not ({"event_category", "category", "action"} & raw.keys()):
        raise ValueError("neither an alert nor an event")
    ev = _Event.model_validate(raw)
    failed = (ev.status or "").lower() in {"failure", "failed", "denied", "error"}
    action = ev.action or "event"
    return _Alert(
        rule_id=f"event:{action}:{ev.status or 'unknown'}",
        rule_name=f"{action} ({ev.status or 'unknown'})",
        severity="low" if failed else "info",
        source_ip=ev.source_ip,
        username=ev.username,
        summary=ev.raw_log,
        created_at=ev.timestamp,
        events=[ev],
    )


def parse(data: Any, *, target: str | None = None) -> ParseResult:
    result = ParseResult()
    for i, item in enumerate(_extract_items(data)):
        if not isinstance(item, dict):
            result.warn(f"item {i}: not an object")
            continue
        if item.get("status") == "false_positive":
            continue  # analyst already dismissed it; not a finding
        try:
            alert = _Alert.model_validate(item) if "rule_id" in item else _event_to_alert(item)
            result.add(_alert_to_finding(alert))
        except (ValidationError, ValueError) as exc:
            if isinstance(exc, AdapterError):
                raise
            result.warn(f"item {i}: {type(exc).__name__}")
    return result.finish()
