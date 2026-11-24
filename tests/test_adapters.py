from __future__ import annotations

import copy

import pytest

from vigilhub.adapters import AdapterError, parse_report
from vigilhub.demo import (
    ATTACKER_IP,
    STAGING_IP,
    _gitvigil_report,
    _gitvigil_sarif,
    _recon_report,
    _siem_alerts,
)
from vigilhub.models import Severity, Source

# ---- VigilSIEM ----


def test_siem_alert_list_targets_victim_not_attacker():
    res = parse_report(Source.VIGILSIEM, _siem_alerts())
    assert len(res.findings) == 3
    brute = next(f for f in res.findings if f.rule_id == "VSR-1001")
    assert brute.source is Source.VIGILSIEM
    assert brute.asset == f"ip:{STAGING_IP}"
    assert brute.severity is Severity.HIGH
    assert brute.evidence["source_ip"] == ATTACKER_IP
    assert brute.evidence["mitre_technique"] == "T1110"
    assert brute.evidence["event_count"] == 5


def test_siem_wrapped_and_single_and_idempotent_ids():
    alerts = _siem_alerts()
    a = parse_report(Source.VIGILSIEM, {"alerts": alerts})
    b = parse_report(Source.VIGILSIEM, alerts[0])
    assert len(b.findings) == 1
    assert b.findings[0].id in {f.id for f in a.findings}


def test_siem_host_meta_and_attacker_fallback():
    alert = {
        "rule_id": "VSR-2004",
        "rule_name": "Scanner",
        "severity": "low",
        "source_ip": "198.51.100.9",
        "events": [{"action": "get", "meta": {"host": "web01"}}],
    }
    assert parse_report(Source.VIGILSIEM, [alert]).findings[0].asset == "host:web01"
    alert["events"] = []
    f = parse_report(Source.VIGILSIEM, [alert]).findings[0]
    assert f.asset == "ip:198.51.100.9"
    assert f.evidence["role"] == "attacker-source"


def test_siem_false_positive_skipped_and_raw_events():
    fp = {**_siem_alerts()[0], "status": "false_positive"}
    res = parse_report(Source.VIGILSIEM, [fp, _siem_alerts()[1]])
    assert [f.rule_id for f in res.findings] == ["VSR-2001"]
    ev = {
        "event_category": "authentication",
        "action": "ssh_login",
        "status": "failure",
        "source_ip": "198.51.100.1",
        "destination_ip": "203.0.113.5",
        "raw_log": "x",
    }
    f = parse_report(Source.VIGILSIEM, [ev]).findings[0]
    assert f.severity is Severity.LOW
    assert f.asset == "ip:203.0.113.5"


@pytest.mark.parametrize("bad", ["text", 5, {"foo": 1}, {"alerts": "x"}])
def test_siem_rejects_garbage(bad):
    with pytest.raises(AdapterError):
        parse_report(Source.VIGILSIEM, bad)


def test_siem_all_items_invalid_raises():
    with pytest.raises(AdapterError, match="no valid records"):
        parse_report(Source.VIGILSIEM, [{"rule_id": "X", "severity": "bogus"}])


# ---- GitVigil ----


def test_gitvigil_json():
    res = parse_report(Source.GITVIGIL, _gitvigil_report())
    assert {f.source for f in res.findings} == {Source.GITVIGIL}
    secret = next(f for f in res.findings if f.category == "secret")
    assert secret.asset == "repo:acmecorp-web"
    assert secret.severity is Severity.CRITICAL
    assert secret.location == "config/prod.env:12"
    assert next(f for f in res.findings if f.category == "iac").rule_id == "GV-TF-001"


def test_gitvigil_never_stores_raw_secret():
    doc = copy.deepcopy(_gitvigil_report())
    doc["findings"][0]["secret"] = "AKIAIOSFODNN7REALKEY"
    res = parse_report(Source.GITVIGIL, doc)
    assert "AKIAIOSFODNN7REALKEY" not in repr([f.model_dump() for f in res.findings])


def test_gitvigil_sarif():
    res = parse_report(Source.GITVIGIL, _gitvigil_sarif())
    (f,) = res.findings
    assert f.asset == "repo:notes-site"
    assert f.category == "iac"
    assert f.severity is Severity.MEDIUM  # security-severity 5.0
    assert f.location == "Dockerfile:1"


def test_gitvigil_sarif_target_override_and_errors():
    sarif = _gitvigil_sarif()
    del sarif["runs"][0]["versionControlProvenance"]
    with pytest.raises(AdapterError, match="repository"):
        parse_report(Source.GITVIGIL, sarif)
    found = parse_report(Source.GITVIGIL, sarif, target="Team/My-Repo").findings[0]
    assert found.asset == "repo:my-repo"
    sarif["version"] = "2.0.0"
    with pytest.raises(AdapterError, match=r"2\.1\.0"):
        parse_report(Source.GITVIGIL, sarif)


def test_gitvigil_sarif_level_fallback():
    sarif = _gitvigil_sarif()
    sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"] = {"tags": ["secret"]}
    sarif["runs"][0]["results"][0]["level"] = "error"
    f = parse_report(Source.GITVIGIL, sarif).findings[0]
    assert (f.severity, f.category) == (Severity.HIGH, "secret")


@pytest.mark.parametrize("bad", [[], {"repository": "x"}, {"findings": []}, "s"])
def test_gitvigil_rejects_garbage(bad):
    with pytest.raises(AdapterError):
        parse_report(Source.GITVIGIL, bad)


# ---- ReconVigil ----


def test_reconvigil_json_with_ip_aliases():
    res = parse_report(Source.RECONVIGIL, _recon_report())
    assert len(res.findings) == 4
    env = next(f for f in res.findings if f.rule_id == "exposed-dotenv")
    assert env.asset == "domain:staging.acmecorp.example"
    assert env.aliases == [f"ip:{STAGING_IP}"]
    assert env.severity is Severity.HIGH
    assert env.category == "exposure"


def test_reconvigil_bare_scan_and_wrong_tool():
    scan = _recon_report()["scan"]
    assert len(parse_report(Source.RECONVIGIL, scan).findings) == 4
    with pytest.raises(AdapterError, match="reconvigil"):
        parse_report(Source.RECONVIGIL, {"tool": {"name": "other"}, "scan": scan})
    with pytest.raises(AdapterError, match="missing"):
        parse_report(Source.RECONVIGIL, {"scan": {}})


def test_reconvigil_skips_bad_rows_but_keeps_good():
    doc = _recon_report()
    doc["scan"]["findings"].append(
        {"rule_id": "x", "title": "t", "severity": "nope", "asset": "a.com"}
    )
    res = parse_report(Source.RECONVIGIL, doc)
    assert len(res.findings) == 4
    assert res.skipped == 1


def test_finding_fields_are_sanitized_by_model():
    doc = _recon_report()
    doc["scan"]["findings"][0]["title"] = "Bad\x00‮<script>alert(1)</script>\nnewline"
    f = parse_report(Source.RECONVIGIL, doc).findings[0]
    assert f.title == "Bad<script>alert(1)</script> newline"
