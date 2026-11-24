"""Realistic sample reports in each sibling tool's native format.

Hosts/IPs use reserved documentation ranges (RFC 5737) and the ``.example`` TLD (RFC 2606).
The staging host is exposed (ReconVigil), its repo leaked a cloud key and ships an open
security group (GitVigil), and its IP is being brute-forced (VigilSIEM): a full kill chain.
Everything else is deliberately unrelated noise that must NOT be correlated.
"""

from __future__ import annotations

from typing import Any

from vigilhub.models import Source

STAGING_IP = "203.0.113.10"
ATTACKER_IP = "198.51.100.23"


def _recon_report() -> dict[str, Any]:
    def finding(rule_id, title, sev, cwe, asset, loc, desc, cat, evidence=""):
        return {
            "rule_id": rule_id,
            "title": title,
            "severity": sev,
            "cwe": cwe,
            "asset": asset,
            "location": loc,
            "description": desc,
            "remediation": "Remove the exposure and rotate anything it revealed.",
            "evidence": evidence,
            "category": cat,
        }

    staging = "staging.acmecorp.example"
    return {
        "tool": {"name": "reconvigil", "version": "0.1.0"},
        "generated_at": "2026-11-20T09:15:00+00:00",
        "scan_id": 1,
        "summary": {"target": "acmecorp.example", "assets": 3, "findings": 4, "severities": {}},
        "scan": {
            "target": "acmecorp.example",
            "started_at": "2026-11-20T09:10:00+00:00",
            "finished_at": "2026-11-20T09:15:00+00:00",
            "assets": [
                {"host": staging, "ips": [STAGING_IP], "endpoints": [f"https://{staging}"]},
                {"host": "www.acmecorp.example", "ips": ["203.0.113.20"], "endpoints": []},
                {"host": "legacy.othercorp.example", "ips": ["203.0.113.99"], "endpoints": []},
            ],
            "findings": [
                finding(
                    "exposed-dotenv",
                    "Exposed .env file",
                    "HIGH",
                    "CWE-538",
                    staging,
                    f"https://{staging}/.env",
                    "A .env file is publicly readable.",
                    "exposure",
                    "HTTP 200, 412 bytes",
                ),
                finding(
                    "exposed-swagger-json",
                    "Exposed Swagger API definition",
                    "MEDIUM",
                    "CWE-200",
                    staging,
                    f"https://{staging}/swagger.json",
                    "API schema is reachable without authentication.",
                    "exposure",
                ),
                finding(
                    "tls-expiring-soon",
                    "TLS certificate expires in 12 days",
                    "LOW",
                    "CWE-298",
                    "www.acmecorp.example",
                    "https://www.acmecorp.example:443",
                    "Certificate is close to expiry.",
                    "tls",
                ),
                finding(
                    "exposed-actuator-health",
                    "Exposed actuator endpoint",
                    "MEDIUM",
                    "CWE-200",
                    "legacy.othercorp.example",
                    "https://legacy.othercorp.example/actuator/health",
                    "Spring actuator is reachable.",
                    "exposure",
                ),
            ],
            "warnings": [],
        },
        "drift": None,
    }


def _gitvigil_report() -> dict[str, Any]:
    return {
        "repository": "acmecorp-web",
        "findings": [
            {
                "rule_id": "aws-access-key-id",
                "title": "AWS access key ID",
                "category": "secret",
                "severity": "CRITICAL",
                "cwe": "CWE-798",
                "path": "config/prod.env",
                "line": 12,
                "commit": "9f2c1ab7d3e84c05b6a1f0e2d4c8b7a69e5d3c21",
                "blob_sha": "a" * 40,
                "source": "history",
                "redacted_match": "AKIA************MPLE",
                "fingerprint": "fp-acmecorp-web-aws-prod-env",
                "remediation": "Revoke the key and purge it from history.",
                "entropy": 3.9,
            },
            {
                "rule_id": "GV-TF-001",
                "title": "Security group open to 0.0.0.0/0 on SSH",
                "category": "iac",
                "severity": "HIGH",
                "cwe": "CWE-284",
                "path": "infra/main.tf",
                "line": 41,
                "commit": None,
                "blob_sha": "b" * 40,
                "source": "staged",
                "redacted_match": 'cidr_blocks = ["0.0.0.0/0"]',
                "fingerprint": "fp-acmecorp-web-tf-open-ssh",
                "remediation": "Restrict ingress to a bastion CIDR.",
            },
        ],
        "warnings": [],
        "stats": {"commits": 214, "blobs_scanned": 1180},
    }


def _gitvigil_sarif() -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GitVigil",
                        "rules": [
                            {
                                "id": "GV-DKR-001",
                                "shortDescription": {"text": "Container runs as root"},
                                "defaultConfiguration": {"level": "warning"},
                                "properties": {"tags": ["iac"], "security-severity": "5.0"},
                            }
                        ],
                    }
                },
                "versionControlProvenance": [
                    {"repositoryUri": "https://example.com/team/notes-site.git"}
                ],
                "results": [
                    {
                        "ruleId": "GV-DKR-001",
                        "level": "warning",
                        "message": {"text": "Dockerfile has no USER instruction."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "Dockerfile"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                        "partialFingerprints": {"primaryLocationLineHash": "notes-site-dkr-1"},
                    }
                ],
            }
        ],
    }


def _siem_alerts() -> list[dict[str, Any]]:
    def event(action, status, raw):
        return {
            "source_ip": ATTACKER_IP,
            "destination_ip": STAGING_IP,
            "username": "admin",
            "category": "authentication",
            "action": action,
            "status": status,
            "raw_log": raw,
            "meta": {},
        }

    logs = [
        event("ssh_login", "failure", f"sshd[311]: Failed password for admin from {ATTACKER_IP}")
        for _ in range(5)
    ]
    return [
        {
            "id": 101,
            "rule_id": "VSR-1001",
            "rule_name": "SSH Brute Force",
            "severity": "high",
            "status": "open",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110",
            "mitre_technique_name": "Brute Force",
            "source_ip": ATTACKER_IP,
            "username": "admin",
            "summary": f"5 failed SSH logins from {ATTACKER_IP} within 60 seconds",
            "created_at": "2026-11-21T02:14:09+00:00",
            "events": logs,
        },
        {
            "id": 102,
            "rule_id": "VSR-2001",
            "rule_name": "SQL Injection Probe",
            "severity": "medium",
            "status": "open",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1190",
            "mitre_technique_name": "Exploit Public-Facing Application",
            "source_ip": ATTACKER_IP,
            "username": None,
            "summary": "UNION SELECT probe against /api/items",
            "created_at": "2026-11-21T02:20:41+00:00",
            "events": [
                {
                    "source_ip": ATTACKER_IP,
                    "destination_ip": STAGING_IP,
                    "category": "web",
                    "action": "http_request",
                    "status": "200",
                    "raw_log": "GET /api/items?id=1%20UNION%20SELECT%20NULL HTTP/1.1",
                    "meta": {},
                }
            ],
        },
        {
            "id": 103,
            "rule_id": "VSR-1003",
            "rule_name": "Failed sudo Followed by Root Session",
            "severity": "medium",
            "status": "open",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1548",
            "mitre_technique_name": "Abuse Elevation Control Mechanism",
            "source_ip": None,
            "username": "deploy",
            "summary": "Failed sudo then root session for user deploy",
            "created_at": "2026-11-21T08:02:00+00:00",
            "events": [
                {
                    "destination_ip": "192.0.2.50",
                    "category": "privilege",
                    "action": "sudo",
                    "status": "failure",
                    "raw_log": "sudo: deploy : 3 incorrect password attempts",
                    "meta": {},
                }
            ],
        },
    ]


def demo_reports() -> list[tuple[Source, Any]]:
    """(source, payload) pairs in native tool formats, ready for the adapters."""
    return [
        (Source.RECONVIGIL, _recon_report()),
        (Source.GITVIGIL, _gitvigil_report()),
        (Source.GITVIGIL, _gitvigil_sarif()),
        (Source.VIGILSIEM, _siem_alerts()),
    ]
