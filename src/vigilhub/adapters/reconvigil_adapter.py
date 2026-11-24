"""ReconVigil adapter: the JSON report (``{"tool", "scan": {assets, findings}, "drift"}``).

A bare ``ScanResult`` (``{"target", "assets", "findings"}``) is accepted too. Each finding's
host gets the IPs ReconVigil resolved for it as aliases, which is what lets a SIEM alert on
``203.0.113.10`` be tied back to ``staging.example.com``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vigilhub.adapters.base import AdapterError, ParseResult, dedupe, finding_id
from vigilhub.correlation.normalize import normalize_target
from vigilhub.models import Finding, Source, parse_severity


class _RVAsset(BaseModel):
    model_config = ConfigDict(extra="ignore")

    host: str
    ips: list[str] = Field(default_factory=list)
    cnames: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)


class _RVFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    rule_id: str
    title: str
    severity: str
    cwe: str | None = None
    asset: str
    location: str = ""
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    category: str = "general"


def parse(data: Any, *, target: str | None = None) -> ParseResult:
    if not isinstance(data, dict):
        raise AdapterError("ReconVigil report must be a JSON object")
    tool = data.get("tool")
    if isinstance(tool, dict) and tool.get("name") not in (None, "reconvigil"):
        raise AdapterError("report was not produced by reconvigil")
    scan = data.get("scan", data)
    if not isinstance(scan, dict) or not isinstance(scan.get("findings"), list):
        raise AdapterError("not a ReconVigil report (missing scan.findings)")

    ips_by_host: dict[str, list[str]] = {}
    for raw in scan.get("assets") or []:
        try:
            a = _RVAsset.model_validate(raw)
            host = normalize_target(a.host, "host").key
            keys = []
            for ip in a.ips:
                try:
                    keys.append(normalize_target(ip, "host").key)
                except ValueError:
                    continue
            ips_by_host[host] = dedupe(keys)
        except (ValidationError, ValueError):
            continue  # a bad asset row only costs us aliases

    result = ParseResult()
    for i, raw in enumerate(scan["findings"]):
        try:
            f = _RVFinding.model_validate(raw)
            asset = normalize_target(f.asset, "host").key
            result.add(
                Finding(
                    id=finding_id(Source.RECONVIGIL, f.rule_id, asset, f.location),
                    source=Source.RECONVIGIL,
                    rule_id=f.rule_id,
                    title=f.title,
                    severity=parse_severity(f.severity),
                    category=f.category.lower(),
                    asset=asset,
                    aliases=[k for k in ips_by_host.get(asset, []) if k != asset],
                    location=f.location,
                    description=f.description,
                    evidence={
                        "cwe": f.cwe,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                        "scan_target": scan.get("target"),
                    },
                    observed_at=scan.get("finished_at")
                    if isinstance(scan.get("finished_at"), str)
                    else None,
                )
            )
        except (ValidationError, ValueError, TypeError) as exc:
            result.warn(f"finding {i}: {type(exc).__name__}")
    return result.finish()
