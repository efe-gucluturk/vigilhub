"""Shared adapter plumbing."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from vigilhub.config import MAX_FINDINGS_PER_REPORT
from vigilhub.models import Finding
from vigilhub.sanitize import sanitize_text

_MAX_WARNINGS = 20


class AdapterError(ValueError):
    """The document is not a recognizable report for this adapter."""


@dataclass
class ParseResult:
    findings: list[Finding] = field(default_factory=list)
    skipped: int = 0
    warnings: list[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        self.skipped += 1
        if len(self.warnings) < _MAX_WARNINGS:
            self.warnings.append(sanitize_text(message, 200))

    def add(self, finding: Finding) -> None:
        if len(self.findings) >= MAX_FINDINGS_PER_REPORT:
            raise AdapterError(f"report exceeds {MAX_FINDINGS_PER_REPORT} findings")
        self.findings.append(finding)

    def finish(self) -> ParseResult:
        if self.skipped and not self.findings:
            raise AdapterError("no valid records in report")
        # Same report ingested twice (or duplicate rows) collapse to one finding.
        unique = {f.id: f for f in self.findings}
        self.findings = list(unique.values())
        return self


def finding_id(*parts: object) -> str:
    """Deterministic 128-bit id so re-ingesting the same report is idempotent."""
    joined = "\x1f".join(str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest()[:32]


def dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))
