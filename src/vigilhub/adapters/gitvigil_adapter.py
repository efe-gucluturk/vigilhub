"""GitVigil adapter: native ``gitvigil scan --format json`` output and SARIF v2.1.0.

GitVigil's JSON is its ``ScanResult`` (``repository`` + ``findings[]``). Each finding is a
``secret`` or ``iac`` hit. The optional raw ``secret`` value (``--reveal-secrets``) is
deliberately *not* modelled below, so it is dropped and never stored.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from vigilhub.adapters.base import AdapterError, ParseResult, finding_id
from vigilhub.correlation.normalize import normalize_target
from vigilhub.models import Finding, Severity, Source, parse_severity


class _GVFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")  # never declare `secret`

    rule_id: str
    title: str
    category: str
    severity: str
    cwe: str | None = None
    path: str
    line: int | None = None
    commit: str | None = None
    blob_sha: str | None = None
    source: str | None = None
    redacted_match: str | None = None
    fingerprint: str | None = None
    remediation: str | None = None
    entropy: float | None = None
    author: str | None = None
    message: str | None = None


def _repo_key(name: object, override: str | None) -> str:
    return normalize_target(override or name, "repo").key


def _parse_json(doc: dict[str, Any], target: str | None) -> ParseResult:
    repo = doc.get("repository")
    if not isinstance(doc.get("findings"), list) or not (repo or target):
        raise AdapterError("not a GitVigil JSON report (need 'repository' and 'findings')")
    try:
        asset = _repo_key(repo, target)
    except ValueError as exc:
        raise AdapterError("invalid repository name") from exc

    result = ParseResult()
    for i, raw in enumerate(doc["findings"]):
        try:
            f = _GVFinding.model_validate(raw)
            category = f.category.lower()
            if category not in {"secret", "iac"}:
                raise ValueError("unknown category")
            location = f"{f.path}:{f.line}" if f.line else f.path
            result.add(
                Finding(
                    id=finding_id(
                        Source.GITVIGIL,
                        asset,
                        f.fingerprint or (f.rule_id, f.path, f.line, f.commit),
                    ),
                    source=Source.GITVIGIL,
                    rule_id=f.rule_id,
                    title=f.title,
                    severity=parse_severity(f.severity),
                    category=category,
                    asset=asset,
                    location=location,
                    description=f"{f.title} at {location}",
                    evidence={
                        "cwe": f.cwe,
                        "commit": f.commit,
                        "blob_sha": f.blob_sha,
                        "scan_source": f.source,
                        "redacted_match": f.redacted_match,
                        "remediation": f.remediation,
                        "entropy": f.entropy,
                        "author": f.author,
                        "commit_message": f.message,
                    },
                )
            )
        except (ValidationError, ValueError, TypeError) as exc:
            result.warn(f"finding {i}: {type(exc).__name__}")
    return result.finish()


# --- SARIF v2.1.0 -------------------------------------------------------------------------


def _sarif_severity(rule: dict[str, Any], result: dict[str, Any]) -> Severity:
    props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
    score = props.get("security-severity")
    try:
        cvss = float(score)
    except (TypeError, ValueError):
        cvss = None
    if cvss is not None:
        if cvss >= 9.0:
            return Severity.CRITICAL
        if cvss >= 7.0:
            return Severity.HIGH
        if cvss >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW if cvss > 0 else Severity.INFO
    default_level = (rule.get("defaultConfiguration") or {}).get("level")
    level = result.get("level") or default_level or "warning"
    return Severity.INFO if level == "none" else parse_severity(level)


def _sarif_category(rule_id: str, rule: dict[str, Any]) -> str:
    props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
    tags = {str(t).lower() for t in props.get("tags", []) if isinstance(t, str)}
    if "iac" in tags or "infrastructure-as-code" in tags:
        return "iac"
    if "secret" in tags or "secrets" in tags:
        return "secret"
    return "iac" if rule_id.upper().startswith("GV-") else "secret"


def _sarif_repo(run: dict[str, Any], target: str | None) -> str:
    if target:
        return _repo_key(target, None)
    props = run.get("properties") if isinstance(run.get("properties"), dict) else {}
    candidates: list[Any] = [props.get("repository")]
    for prov in run.get("versionControlProvenance") or []:
        if isinstance(prov, dict):
            candidates.append(prov.get("repositoryUri"))
    base = (run.get("originalUriBaseIds") or {}).get("%SRCROOT%")
    if isinstance(base, dict):
        candidates.append(base.get("uri"))
    for cand in candidates:
        if cand:
            try:
                return _repo_key(cand, None)
            except ValueError:
                continue
    raise AdapterError("SARIF run has no repository; pass a target override")


def _parse_sarif(doc: dict[str, Any], target: str | None) -> ParseResult:
    if str(doc.get("version", "")) != "2.1.0" or not isinstance(doc.get("runs"), list):
        raise AdapterError("only SARIF v2.1.0 is supported")
    out = ParseResult()
    for run in doc["runs"]:
        if not isinstance(run, dict):
            out.warn("run is not an object")
            continue
        asset = _sarif_repo(run, target)
        driver = ((run.get("tool") or {}).get("driver")) or {}
        rules = {r["id"]: r for r in driver.get("rules") or [] if isinstance(r, dict) and "id" in r}
        for i, res in enumerate(run.get("results") or []):
            try:
                rule_id = str(res["ruleId"])
                rule = rules.get(rule_id, {})
                loc = ((res.get("locations") or [{}])[0]).get("physicalLocation") or {}
                uri = (loc.get("artifactLocation") or {}).get("uri") or ""
                line = (loc.get("region") or {}).get("startLine")
                location = f"{uri}:{line}" if uri and line else uri
                text = (res.get("message") or {}).get("text") or ""
                title = (rule.get("shortDescription") or {}).get("text") or text or rule_id
                fp = next(iter((res.get("partialFingerprints") or {}).values()), None)
                out.add(
                    Finding(
                        id=finding_id(Source.GITVIGIL, asset, fp or (rule_id, location)),
                        source=Source.GITVIGIL,
                        rule_id=rule_id,
                        title=title,
                        severity=_sarif_severity(rule, res),
                        category=_sarif_category(rule_id, rule),
                        asset=asset,
                        location=location,
                        description=text,
                        evidence={"format": "sarif", "tool": driver.get("name")},
                    )
                )
            except (ValidationError, ValueError, TypeError, KeyError, AttributeError) as exc:
                out.warn(f"result {i}: {type(exc).__name__}")
    return out.finish()


def parse(data: Any, *, target: str | None = None) -> ParseResult:
    if not isinstance(data, dict):
        raise AdapterError("GitVigil report must be a JSON object")
    if "runs" in data:
        return _parse_sarif(data, target)
    return _parse_json(data, target)
