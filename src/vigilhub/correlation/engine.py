"""Deterministic asset scoring and cross-tool incident correlation.

Pure functions: findings in, assets/incidents out. No I/O, clocks or randomness, so the
same findings always produce the same incident ids and scores.

Linking model (union-find over asset keys):
  * a finding links its primary asset to every alias (e.g. a ReconVigil host and the IPs it
    resolves to, which is how a VigilSIEM alert on an IP joins a domain);
  * a repository links to every domain whose project label (``staging.acme.example`` ->
    ``acme``) equals a token of the repo name (``acme-web`` -> ``acme``, ``web``).
Each connected component is a *scope*; incidents are evaluated per scope.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable

from vigilhub.correlation.normalize import scope_label, split_key
from vigilhub.models import (
    Asset,
    AssetKind,
    Finding,
    Incident,
    IncidentStep,
    Severity,
    Source,
)

SEVERITY_WEIGHT = {
    Severity.INFO: 1,
    Severity.LOW: 3,
    Severity.MEDIUM: 10,
    Severity.HIGH: 25,
    Severity.CRITICAL: 40,
}
_OVERLAP_BONUS = 0.25  # +25% per additional tool seen in the same scope
_TOP_FINDINGS = 10  # an asset's score counts its ten heaviest findings
_MIN_TOKEN = 3
_STEPS_PER_STAGE = 5

# Kill-chain stages, in the order an attack unfolds.
EXPOSURE = "exposure"
CREDENTIAL_LEAK = "credential_leak"
IAC_MISCONFIG = "iac_misconfig"
ACTIVE_ATTACK = "active_attack"
STAGE_ORDER = (EXPOSURE, CREDENTIAL_LEAK, IAC_MISCONFIG, ACTIVE_ATTACK)
_STAGE_LABEL = {
    EXPOSURE: "Exposed attack surface",
    CREDENTIAL_LEAK: "Leaked credential in source",
    IAC_MISCONFIG: "Infrastructure misconfiguration",
    ACTIVE_ATTACK: "Active attack observed",
}
_NON_PROD = frozenset({"staging", "stage", "stg", "dev", "test", "uat", "qa", "preprod", "sandbox"})


def classify(f: Finding) -> str | None:
    """Map a finding to a kill-chain stage, or None if it only contributes to risk score."""
    if f.source is Source.RECONVIGIL:
        exposed = f.category in {"exposure", "takeover"} or f.rule_id.startswith("exposed-")
        return EXPOSURE if exposed and f.severity.rank >= Severity.LOW.rank else None
    if f.source is Source.GITVIGIL:
        if f.category == "secret":
            return CREDENTIAL_LEAK
        return IAC_MISCONFIG if f.category == "iac" else None
    if f.source is Source.VIGILSIEM:
        return ACTIVE_ATTACK if f.severity.rank >= Severity.MEDIUM.rank else None
    return None


def _is_brute_force(f: Finding) -> bool:
    text = f"{f.title} {f.evidence.get('mitre_technique', '')}".lower()
    return any(w in text for w in ("brute", "spray", "stuffing", "t1110"))


# --- union-find -----------------------------------------------------------------------------


class _Components:
    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def find(self, key: str) -> str:
        self._parent.setdefault(key, key)
        root = key
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[key] != root:  # path compression
            self._parent[key], key = root, self._parent[key]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Lexicographically smaller root wins so results never depend on input order.
            lo, hi = sorted((ra, rb))
            self._parent[hi] = lo


def build_components(findings: Iterable[Finding]) -> _Components:
    comps = _Components()
    domains_by_label: dict[str, list[str]] = defaultdict(list)
    repos: list[str] = []
    for f in findings:
        for alias in f.aliases:
            comps.union(f.asset, alias)
        comps.find(f.asset)
        for key in (f.asset, *f.aliases):
            kind, name = split_key(key)
            if kind is AssetKind.DOMAIN and (label := scope_label(name)):
                domains_by_label[label].append(key)
            elif kind is AssetKind.REPO:
                repos.append(key)
    for repo in set(repos):
        for token in re.split(r"[-_.]", split_key(repo)[1]):
            if len(token) >= _MIN_TOKEN:
                for domain in domains_by_label.get(token, []):
                    comps.union(repo, domain)
    return comps


# --- asset scoring --------------------------------------------------------------------------


def build_assets(findings: list[Finding]) -> list[Asset]:
    """One ``Asset`` per finding target with a 0-100 composite risk score.

    score = min(100, round(sum of the top-10 severity weights * (1 + 0.25 * (tools - 1)))),
    where ``tools`` counts distinct sources across the asset's whole correlation scope.
    """
    comps = build_components(findings)
    scope_sources: dict[str, set[Source]] = defaultdict(set)
    by_asset: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_asset[f.asset].append(f)
        scope_sources[comps.find(f.asset)].add(f.source)

    assets = []
    for key in sorted(by_asset):
        group = by_asset[key]
        weights = sorted((SEVERITY_WEIGHT[f.severity] for f in group), reverse=True)
        raw = sum(weights[:_TOP_FINDINGS])
        tools = len(scope_sources[comps.find(key)])
        score = min(100, round(raw * (1 + _OVERLAP_BONUS * (tools - 1))))
        kind, name = split_key(key)
        counts: dict[str, int] = defaultdict(int)
        for f in group:
            counts[f.severity.value] += 1
        assets.append(
            Asset(
                id=key,
                kind=kind,
                name=name,
                risk_score=score,
                finding_count=len(group),
                sources=sorted({f.source for f in group}),
                severity_counts=dict(sorted(counts.items())),
                aliases=sorted({a for f in group for a in f.aliases}),
            )
        )
    return assets


# --- incident rules -------------------------------------------------------------------------


class _Rule:
    def __init__(self, rule_id: str, title: str, needs: frozenset[str], base: Severity) -> None:
        self.rule_id, self.title, self.needs, self.base = rule_id, title, needs, base


# Ordered most-specific first; the first rule whose stages are all present wins.
RULES = (
    _Rule(
        "KC-001",
        "Kill chain: exposed asset, leaked credential and active attack",
        frozenset({EXPOSURE, CREDENTIAL_LEAK, ACTIVE_ATTACK}),
        Severity.CRITICAL,
    ),
    _Rule(
        "KC-002",
        "Kill chain: exposed asset, IaC misconfiguration and active attack",
        frozenset({EXPOSURE, IAC_MISCONFIG, ACTIVE_ATTACK}),
        Severity.HIGH,
    ),
    _Rule(
        "XT-001",
        "Leaked credential on a scope under active attack",
        frozenset({CREDENTIAL_LEAK, ACTIVE_ATTACK}),
        Severity.HIGH,
    ),
    _Rule(
        "XT-002",
        "Exposed asset with a leaked credential in its source",
        frozenset({EXPOSURE, CREDENTIAL_LEAK}),
        Severity.HIGH,
    ),
    _Rule(
        "XT-003",
        "Exposed asset under active attack",
        frozenset({EXPOSURE, ACTIVE_ATTACK}),
        Severity.HIGH,
    ),
    _Rule(
        "XT-004",
        "Infrastructure misconfiguration on a scope under active attack",
        frozenset({IAC_MISCONFIG, ACTIVE_ATTACK}),
        Severity.MEDIUM,
    ),
)
_SEVERITY_FLOOR = {Severity.CRITICAL: 85, Severity.HIGH: 65, Severity.MEDIUM: 40}


def _incident_for_scope(members: list[tuple[str, Finding]]) -> Incident | None:
    by_stage: dict[str, list[Finding]] = defaultdict(list)
    for stage, f in members:
        by_stage[stage].append(f)
    rule = next((r for r in RULES if r.needs <= by_stage.keys()), None)
    if rule is None:
        return None

    stage_findings = [f for fs in by_stage.values() for f in fs]
    top = max(f.severity.rank for f in stage_findings)
    severity = rule.base
    if top == Severity.CRITICAL.rank and severity.rank >= Severity.HIGH.rank:
        severity = Severity.CRITICAL
    elif severity is Severity.MEDIUM and top >= Severity.HIGH.rank:
        severity = Severity.HIGH
    if rule.rule_id == "KC-002" and top == Severity.CRITICAL.rank:
        severity = Severity.CRITICAL

    steps: list[IncidentStep] = []
    for stage in STAGE_ORDER:
        ranked = sorted(by_stage.get(stage, []), key=lambda f: (-f.severity.rank, f.id))
        for f in ranked[:_STEPS_PER_STAGE]:
            detail = _STAGE_LABEL[stage]
            if stage == EXPOSURE and _non_prod(f.asset):
                detail += " (non-production host)"
            if stage == ACTIVE_ATTACK and _is_brute_force(f):
                detail += " (brute force / credential guessing)"
            steps.append(
                IncidentStep(
                    order=len(steps) + 1,
                    stage=stage,
                    source=f.source,
                    finding_id=f.id,
                    rule_id=f.rule_id,
                    title=f.title,
                    severity=f.severity,
                    asset=f.asset,
                    detail=detail,
                )
            )

    finding_ids = sorted({f.id for f in stage_findings})
    asset_ids = sorted({f.asset for f in stage_findings})
    sources = sorted({f.source for f in stage_findings})
    score = min(100, _SEVERITY_FLOOR[severity] + min(15, 3 * len(finding_ids)))
    stages_seen = [s for s in STAGE_ORDER if s in by_stage]
    return Incident(
        id=hashlib.sha256(f"{rule.rule_id}|{'|'.join(asset_ids)}".encode()).hexdigest()[:32],
        rule_id=rule.rule_id,
        title=rule.title,
        severity=severity,
        score=score,
        summary=(
            f"{len(finding_ids)} findings from {len(sources)} tools across "
            f"{len(asset_ids)} assets: " + " -> ".join(_STAGE_LABEL[s] for s in stages_seen)
        ),
        asset_ids=asset_ids,
        finding_ids=finding_ids,
        sources=sources,
        steps=steps,
    )


def _non_prod(asset_key: str) -> bool:
    kind, name = split_key(asset_key)
    return kind is AssetKind.DOMAIN and bool(_NON_PROD & set(re.split(r"[.-]", name)))


def correlate(findings: list[Finding]) -> list[Incident]:
    """Link findings across tools into incidents; ordered most severe first."""
    comps = build_components(findings)
    scopes: dict[str, list[tuple[str, Finding]]] = defaultdict(list)
    for f in findings:
        if (stage := classify(f)) is not None:
            scopes[comps.find(f.asset)].append((stage, f))
    incidents = [inc for scope in scopes.values() if (inc := _incident_for_scope(scope))]
    return sorted(incidents, key=lambda i: (-i.severity.rank, -i.score, i.id))
