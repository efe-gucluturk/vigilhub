from __future__ import annotations

from vigilhub.adapters import parse_report
from vigilhub.adapters.base import finding_id
from vigilhub.correlation import build_assets, correlate
from vigilhub.correlation.engine import STAGE_ORDER
from vigilhub.demo import STAGING_IP, demo_reports
from vigilhub.models import Finding, Severity, Source


def _all() -> list[Finding]:
    out: list[Finding] = []
    for src, payload in demo_reports():
        out.extend(parse_report(src, payload).findings)
    return out


def _f(source: Source, asset: str, sev: Severity, cat: str, rule: str = "r") -> Finding:
    return Finding(
        id=finding_id(source, asset, sev, cat, rule),
        source=source,
        rule_id=rule,
        title=rule,
        severity=sev,
        category=cat,
        asset=asset,
    )


def test_demo_produces_one_critical_kill_chain():
    incidents = correlate(_all())
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.rule_id == "KC-001"
    assert inc.severity is Severity.CRITICAL
    assert set(inc.sources) == set(Source)
    assert {s.stage for s in inc.steps} == set(STAGE_ORDER)
    assert [s.order for s in inc.steps] == list(range(1, len(inc.steps) + 1))
    stages = [s.stage for s in inc.steps]
    assert stages == sorted(stages, key=STAGE_ORDER.index)  # attack order
    assert any("non-production" in s.detail for s in inc.steps)
    assert any("brute force" in s.detail for s in inc.steps)
    assert f"ip:{STAGING_IP}" in inc.asset_ids


def test_unrelated_noise_not_correlated():
    (inc,) = correlate(_all())
    assert "domain:legacy.othercorp.example" not in inc.asset_ids
    assert "ip:192.0.2.50" not in inc.asset_ids  # sudo alert on another host
    assert "repo:notes-site" not in inc.asset_ids


def test_single_tool_never_makes_an_incident():
    siem_only = parse_report(*demo_reports()[3]).findings
    assert correlate(siem_only) == []


def test_ip_alias_is_what_joins_siem_to_recon():
    findings = [f for f in _all() if f.asset != "repo:acmecorp-web"]
    assert [i.rule_id for i in correlate(findings)] == ["XT-003"]  # exposure + attack
    no_alias = [f.model_copy(update={"aliases": []}) for f in findings]
    assert correlate(no_alias) == []


def test_repo_links_by_project_label():
    f = [
        _f(Source.RECONVIGIL, "domain:shop.acme.example", Severity.HIGH, "exposure", "exposed-x"),
        _f(Source.GITVIGIL, "repo:acme-api", Severity.HIGH, "secret"),
    ]
    assert [i.rule_id for i in correlate(f)] == ["XT-002"]
    f[1] = f[1].model_copy(update={"asset": "repo:other-api"})
    assert correlate(f) == []


def test_rule_selection_and_escalation():
    d, r = "domain:a.acme.example", "repo:acme"
    chain = [
        _f(Source.RECONVIGIL, d, Severity.MEDIUM, "exposure", "exposed-a"),
        _f(Source.GITVIGIL, r, Severity.HIGH, "iac", "GV-1"),
        _f(Source.VIGILSIEM, d, Severity.MEDIUM, "alert", "VSR"),
    ]
    inc = correlate(chain)[0]
    assert (inc.rule_id, inc.severity) == ("KC-002", Severity.HIGH)
    chain[1] = _f(Source.GITVIGIL, r, Severity.CRITICAL, "iac", "GV-2")
    assert correlate(chain)[0].severity is Severity.CRITICAL
    weak = [
        _f(Source.GITVIGIL, r, Severity.LOW, "iac"),
        _f(Source.VIGILSIEM, "domain:b.acme.example", Severity.MEDIUM, "alert"),
    ]
    inc = correlate(weak)[0]
    assert (inc.rule_id, inc.severity) == ("XT-004", Severity.MEDIUM)


def test_deterministic_regardless_of_order():
    findings = _all()
    a = correlate(findings)
    b = correlate(list(reversed(findings)))
    assert [i.model_dump() for i in a] == [i.model_dump() for i in b]
    assets_a = [x.model_dump() for x in build_assets(findings)]
    assets_b = [x.model_dump() for x in build_assets(list(reversed(findings)))]
    assert assets_a == assets_b


def test_info_findings_do_not_trigger_stages():
    f = [
        _f(Source.RECONVIGIL, "domain:a.acme.example", Severity.INFO, "exposure", "exposed-info"),
        _f(Source.VIGILSIEM, "domain:a.acme.example", Severity.LOW, "alert"),
    ]
    assert correlate(f) == []


def test_asset_risk_scores_bounded_and_overlap_raises_score():
    assets = {a.id: a for a in build_assets(_all())}
    assert all(0 <= a.risk_score <= 100 for a in assets.values())
    staging = assets["domain:staging.acmecorp.example"]
    isolated = assets["domain:legacy.othercorp.example"]
    assert staging.risk_score > isolated.risk_score
    # 3 tools share the scope => x1.5 on (high 25 + medium 10)
    assert staging.risk_score == round((25 + 10) * 1.5)
    assert isolated.risk_score == 10  # one medium, one tool
    solo = build_assets([_f(Source.RECONVIGIL, "domain:a.b.example", Severity.HIGH, "exposure")])
    assert solo[0].risk_score == 25


def test_score_caps_at_100():
    many = [_f(Source.GITVIGIL, "repo:x1", Severity.CRITICAL, "secret", f"r{i}") for i in range(10)]
    assert build_assets(many)[0].risk_score == 100
