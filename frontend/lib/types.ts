// Mirrors src/vigilhub/models.py and src/vigilhub/api/routes.py (Phase 1/2 API contract).

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Source = "vigilsiem" | "gitvigil" | "reconvigil";
export type AssetKind = "domain" | "ip" | "host" | "repo";
export type Stage = "exposure" | "credential_leak" | "iac_misconfig" | "active_attack";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const SOURCES: Source[] = ["vigilsiem", "gitvigil", "reconvigil"];

export const SOURCE_LABEL: Record<Source, string> = {
  vigilsiem: "VigilSIEM",
  gitvigil: "GitVigil",
  reconvigil: "ReconVigil",
};

export interface Finding {
  id: string;
  source: Source;
  rule_id: string;
  title: string;
  severity: Severity;
  category: string;
  asset: string;
  aliases: string[];
  location: string;
  description: string;
  evidence: Record<string, unknown>;
  observed_at: string | null;
}

export interface Asset {
  id: string;
  kind: AssetKind;
  name: string;
  risk_score: number;
  finding_count: number;
  sources: Source[];
  severity_counts: Record<string, number>;
  aliases: string[];
}

export interface AssetDetail {
  asset: Asset;
  findings: Finding[];
  incident_ids: string[];
}

export interface IncidentStep {
  order: number;
  stage: Stage;
  source: Source;
  finding_id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  asset: string;
  detail: string;
}

export interface Incident {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  score: number;
  summary: string;
  asset_ids: string[];
  finding_ids: string[];
  sources: Source[];
  steps: IncidentStep[];
}

export interface Stats {
  total_assets: number;
  total_findings: number;
  total_incidents: number;
  findings_by_severity: Record<Severity, number>;
  findings_by_source: Record<Source, number>;
  incidents_by_severity: Record<Severity, number>;
}

export interface IngestResult {
  source: string;
  accepted: number;
  skipped: number;
  warnings: string[];
}

export interface CorrelateResult {
  assets: number;
  findings: number;
  incidents: number;
  by_severity: Record<string, number>;
}

export interface SeedResult {
  ingested: IngestResult[];
  correlation: CorrelateResult;
}

export type HubEvent =
  | { type: "ingest_completed"; ts: string; data: { source: string; accepted: number; skipped: number } }
  | { type: "correlation_updated"; ts: string; data: CorrelateResult }
  | { type: "demo_seeded"; ts: string; data: SeedResult };

export type LiveStatus = "live" | "connecting" | "offline";
