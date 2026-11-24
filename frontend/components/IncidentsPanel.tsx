"use client";

import { ChevronDown, ChevronRight, Link2, Loader2, Siren, Sparkles } from "lucide-react";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { Incident, IncidentAnalysis, Stage } from "@/lib/types";
import { Chip, Empty, Panel, SeverityBadge, SourceBadge } from "./ui";

const STAGE_LABEL: Record<Stage, string> = {
  exposure: "Exposure",
  credential_leak: "Credential leak",
  iac_misconfig: "IaC misconfiguration",
  active_attack: "Active attack",
};

// All analysis text (including model output) is rendered as plain React text nodes.
function AnalysisView({ analysis }: { analysis: IncidentAnalysis }) {
  return (
    <div className="space-y-3 rounded-md border border-ink-600 bg-ink-900/60 p-3">
      <span
        className={`inline-block rounded border px-2 py-0.5 text-[11px] font-semibold ${
          analysis.fallback_used
            ? "border-amber-500/40 text-amber-300"
            : "border-emerald-500/40 text-emerald-300"
        }`}
      >
        {analysis.fallback_used ? "Offline Rule Triage" : `Ollama (${analysis.model})`}
      </span>
      <div>
        <h4 className="text-xs uppercase tracking-wider text-slate-400">Summary</h4>
        <p className="mt-1 text-sm text-slate-100">{analysis.summary}</p>
      </div>
      <div>
        <h4 className="text-xs uppercase tracking-wider text-slate-400">Attack chain</h4>
        <p className="mt-1 text-sm text-slate-100">{analysis.attack_chain}</p>
      </div>
      <div>
        <h4 className="text-xs uppercase tracking-wider text-slate-400">Remediation steps</h4>
        <ol className="mt-1 list-decimal space-y-1 pl-5 text-sm text-slate-100">
          {analysis.remediation_steps.map((step, i) => (
            <li key={i}>{step}</li>
          ))}
        </ol>
      </div>
    </div>
  );
}

function AnalyzeSection({
  incidentId,
  apiKey,
  onAuthError,
}: {
  incidentId: string;
  apiKey: string;
  onAuthError: () => void;
}) {
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState<IncidentAnalysis | null>(null);
  const [error, setError] = useState("");

  async function run() {
    setLoading(true);
    setError("");
    try {
      setAnalysis(await api.analyze(apiKey, incidentId));
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) onAuthError();
      setError(e instanceof Error ? e.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-2">
      <button
        type="button"
        onClick={() => void run()}
        disabled={loading}
        className="inline-flex items-center gap-1.5 rounded-md border border-blue-500/50 bg-blue-500/10 px-3 py-1.5 text-xs font-semibold text-blue-200 hover:bg-blue-500/20 disabled:opacity-60"
      >
        {loading ? <Loader2 size={13} className="animate-spin" /> : <Sparkles size={13} />}
        {loading ? "Analyzing…" : analysis ? "Re-analyze" : "Analyze Incident"}
      </button>
      {error && (
        <p role="alert" className="text-xs text-red-300">
          {error}
        </p>
      )}
      {analysis && <AnalysisView analysis={analysis} />}
    </div>
  );
}

function IncidentCard({
  incident,
  open,
  onToggle,
  apiKey,
  onAuthError,
}: {
  incident: Incident;
  open: boolean;
  onToggle: () => void;
  apiKey: string;
  onAuthError: () => void;
}) {
  const panelId = `incident-${incident.id}`;
  return (
    <li className="rounded-lg border border-ink-600 bg-ink-800/60">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={panelId}
        className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-ink-700/40"
      >
        <span className="mt-1 text-slate-500">{open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</span>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={incident.severity} />
            <span className="font-mono text-xs font-semibold text-blue-300">{incident.rule_id}</span>
            <span className="font-mono text-xs text-slate-500">score {incident.score}</span>
          </span>
          <span className="mt-1 block text-sm font-medium text-white">{incident.title}</span>
          <span className="mt-0.5 block text-xs text-slate-400">{incident.summary}</span>
          <span className="mt-2 flex flex-wrap items-center gap-1.5">
            {incident.sources.map((s) => (
              <SourceBadge key={s} source={s} />
            ))}
          </span>
        </span>
      </button>

      {open && (
        <div id={panelId} className="space-y-4 border-t border-ink-600 px-4 py-4">
          <AnalyzeSection incidentId={incident.id} apiKey={apiKey} onAuthError={onAuthError} />

          <div>
            <h3 className="mb-1.5 flex items-center gap-1.5 text-xs uppercase tracking-wider text-slate-400">
              <Link2 size={12} /> Linked assets &amp; aliases
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {incident.asset_ids.map((a) => (
                <Chip key={a}>{a}</Chip>
              ))}
            </div>
          </div>

          <div>
            <h3 className="mb-2 text-xs uppercase tracking-wider text-slate-400">Kill-chain evidence</h3>
            <ol className="relative space-y-3 border-l border-ink-600 pl-5">
              {incident.steps.map((step) => (
                <li key={`${step.order}-${step.finding_id}`} className="relative">
                  <span className="absolute -left-[27px] top-0.5 flex h-4 w-4 items-center justify-center rounded-full border border-ink-600 bg-ink-900 font-mono text-[10px] text-slate-300">
                    {step.order}
                  </span>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-300">
                      {STAGE_LABEL[step.stage] ?? step.stage}
                    </span>
                    <SourceBadge source={step.source} />
                    <SeverityBadge severity={step.severity} />
                    <span className="font-mono text-[11px] text-slate-500">{step.rule_id}</span>
                  </div>
                  <p className="mt-1 text-sm text-slate-100">{step.title}</p>
                  <p className="mt-0.5 text-xs text-slate-400">
                    <span className="font-mono">{step.asset}</span>
                    {step.detail ? ` · ${step.detail}` : ""}
                  </p>
                </li>
              ))}
            </ol>
          </div>
        </div>
      )}
    </li>
  );
}

export function IncidentsPanel({
  incidents,
  apiKey,
  onAuthError,
}: {
  incidents: Incident[];
  apiKey: string;
  onAuthError: () => void;
}) {
  const [openId, setOpenId] = useState<string | null>(null);
  // first incident is the most severe (the API sorts by severity then score); open it by default
  const effective = openId ?? incidents[0]?.id ?? null;
  return (
    <Panel title="Correlated Incidents" icon={<Siren size={15} />}>
      {incidents.length === 0 ? (
        <Empty>No cross-tool incidents yet. Seed demo data or ingest reports from two or more tools, then run correlation.</Empty>
      ) : (
        <ul className="space-y-3 p-4">
          {incidents.map((i) => (
            <IncidentCard
              key={i.id}
              incident={i}
              apiKey={apiKey}
              onAuthError={onAuthError}
              open={effective === i.id}
              onToggle={() => setOpenId(effective === i.id ? "" : i.id)}
            />
          ))}
        </ul>
      )}
    </Panel>
  );
}
