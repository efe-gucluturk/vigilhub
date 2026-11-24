"use client";

import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";
import type { Finding } from "@/lib/types";
import { Chip, SeverityBadge, SourceBadge } from "./ui";

/**
 * Every string below comes from untrusted scanner output. It is only ever rendered as a
 * React text node (JSX children), which React escapes. Raw-HTML injection APIs are banned
 * (enforced by tests/test_frontend_guard.py).
 */
function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const evidenceKeys = Object.keys(finding.evidence);
  return (
    <li className="border-b border-ink-600 last:border-b-0">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-start gap-2 px-4 py-2.5 text-left hover:bg-ink-800/70"
      >
        <span className="mt-1 text-slate-500">{open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</span>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <SourceBadge source={finding.source} />
            <span className="font-mono text-[11px] text-slate-500">{finding.rule_id}</span>
          </span>
          <span className="mt-1 block break-words text-sm text-slate-100">{finding.title}</span>
          <span className="block truncate font-mono text-xs text-slate-500">
            {finding.asset}
            {finding.location ? ` · ${finding.location}` : ""}
          </span>
        </span>
      </button>
      {open && (
        <div className="space-y-3 bg-ink-950/60 px-4 py-3 text-sm">
          {finding.description && <p className="break-words text-slate-300">{finding.description}</p>}
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
            <dt className="text-slate-500">Category</dt>
            <dd className="text-slate-300">{finding.category}</dd>
            <dt className="text-slate-500">Finding ID</dt>
            <dd className="break-all font-mono text-slate-400">{finding.id}</dd>
            {finding.observed_at && (
              <>
                <dt className="text-slate-500">Observed</dt>
                <dd className="text-slate-300">{finding.observed_at}</dd>
              </>
            )}
            {finding.aliases.length > 0 && (
              <>
                <dt className="text-slate-500">Aliases</dt>
                <dd className="flex flex-wrap gap-1">
                  {finding.aliases.map((a) => (
                    <Chip key={a}>{a}</Chip>
                  ))}
                </dd>
              </>
            )}
          </dl>
          {evidenceKeys.length > 0 && (
            <div>
              <div className="mb-1 text-xs uppercase tracking-wider text-slate-500">Evidence</div>
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded border border-ink-600 bg-ink-950 p-2 font-mono text-xs text-slate-300">
                {JSON.stringify(finding.evidence, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </li>
  );
}

export function FindingList({ findings }: { findings: Finding[] }) {
  return (
    <ul>
      {findings.map((f) => (
        <FindingRow key={f.id} finding={f} />
      ))}
    </ul>
  );
}
