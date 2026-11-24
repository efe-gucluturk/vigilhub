"use client";

import { ListFilter } from "lucide-react";
import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import { SEVERITIES, SOURCES, SOURCE_LABEL, type Finding, type Severity, type Source } from "@/lib/types";
import { FindingList } from "./FindingList";
import { Empty, Panel, field } from "./ui";

export function FindingsExplorer({
  apiKey,
  tick,
  onAuthError,
}: {
  apiKey: string;
  tick: number;
  onAuthError: () => void;
}) {
  const [source, setSource] = useState<Source | "">("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [error, setError] = useState("");

  // Refetches on filter change and whenever the hub reports new data (tick).
  useEffect(() => {
    let cancelled = false;
    api
      .findings(apiKey, { source, severity })
      .then((rows) => {
        if (!cancelled) {
          setFindings(rows);
          setError("");
        }
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        if (e instanceof ApiError && e.status === 401) onAuthError();
        else setError(e instanceof Error ? e.message : "Could not load findings");
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, source, severity, tick, onAuthError]);

  return (
    <Panel
      title="Findings Explorer"
      icon={<ListFilter size={15} />}
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <label className="sr-only" htmlFor="f-source">
            Source
          </label>
          <select
            id="f-source"
            value={source}
            onChange={(e) => setSource(e.target.value as Source | "")}
            className={`${field} w-auto py-1`}
          >
            <option value="">All tools</option>
            {SOURCES.map((s) => (
              <option key={s} value={s}>
                {SOURCE_LABEL[s]}
              </option>
            ))}
          </select>
          <label className="sr-only" htmlFor="f-sev">
            Severity
          </label>
          <select
            id="f-sev"
            value={severity}
            onChange={(e) => setSeverity(e.target.value as Severity | "")}
            className={`${field} w-auto py-1`}
          >
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <span className="font-mono text-xs text-slate-500">{findings ? `${findings.length} shown` : ""}</span>
        </div>
      }
    >
      {error && (
        <p role="alert" className="px-4 py-3 text-sm text-red-300">
          {error}
        </p>
      )}
      {findings === null ? (
        <Empty>Loading…</Empty>
      ) : findings.length === 0 ? (
        <Empty>No findings match these filters.</Empty>
      ) : (
        <FindingList findings={findings} />
      )}
    </Panel>
  );
}
