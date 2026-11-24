"""Normalized domain models. Everything VigilHub emits is strict and sanitized."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vigilhub.sanitize import sanitize_json, sanitize_text


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def parse_severity(value: object) -> Severity:
    """Case-insensitive severity parsing shared by all three tools' vocabularies."""
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        aliases = {"informational": "info", "warning": "medium", "error": "high", "note": "low"}
        try:
            return Severity(aliases.get(text, text))
        except ValueError:
            pass
    raise ValueError("unknown severity")


class Source(StrEnum):
    VIGILSIEM = "vigilsiem"
    GITVIGIL = "gitvigil"
    RECONVIGIL = "reconvigil"


class AssetKind(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    HOST = "host"
    REPO = "repo"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


AssetKey = Annotated[str, Field(min_length=3, max_length=300, pattern=r"^[a-z]+:[^\s]+$")]


class Finding(StrictModel):
    """One normalized finding. String fields are sanitized on construction."""

    id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    source: Source
    rule_id: Annotated[str, Field(min_length=1, max_length=128)]
    title: Annotated[str, Field(min_length=1, max_length=300)]
    severity: Severity
    category: Annotated[str, Field(min_length=1, max_length=64)] = "general"
    asset: AssetKey
    aliases: list[AssetKey] = Field(default_factory=list, max_length=32)
    location: Annotated[str, Field(max_length=500)] = ""
    description: Annotated[str, Field(max_length=2000)] = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    observed_at: Annotated[str, Field(max_length=64)] | None = None

    @field_validator("rule_id", "title", "category", "location", "description", "observed_at")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return None if value is None else sanitize_text(value)

    @field_validator("evidence")
    @classmethod
    def _clean_evidence(cls, value: dict[str, Any]) -> dict[str, Any]:
        return sanitize_json(value)


class Asset(StrictModel):
    id: AssetKey
    kind: AssetKind
    name: str
    risk_score: Annotated[int, Field(ge=0, le=100)] = 0
    finding_count: int = 0
    sources: list[Source] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    aliases: list[AssetKey] = Field(default_factory=list)


class IncidentStep(StrictModel):
    order: int
    stage: str
    source: Source
    finding_id: str
    rule_id: str
    title: str
    severity: Severity
    asset: str
    detail: str = ""


class Incident(StrictModel):
    id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    rule_id: str
    title: str
    severity: Severity
    score: Annotated[int, Field(ge=0, le=100)]
    summary: str
    asset_ids: list[str]
    finding_ids: list[str]
    sources: list[Source]
    steps: list[IncidentStep]
