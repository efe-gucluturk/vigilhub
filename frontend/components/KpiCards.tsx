"use client";

import { Boxes, Siren, TriangleAlert, Layers } from "lucide-react";
import type { ReactNode } from "react";
import { SOURCES, SOURCE_LABEL, type Stats } from "@/lib/types";

function Card({ label, value, hint, icon }: { label: string; value: ReactNode; hint?: ReactNode; icon: ReactNode }) {
  return (
    <div className="rounded-lg border border-ink-600 bg-ink-900 p-4">
      <div className="flex items-center justify-between text-xs uppercase tracking-wider text-slate-400">
        {label}
        <span className="text-slate-500">{icon}</span>
      </div>
      <div className="mt-2 font-mono text-3xl font-semibold tabular-nums text-white">{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export function KpiCards({ stats }: { stats: Stats | null }) {
  const crit = stats?.findings_by_severity.critical ?? 0;
  const high = stats?.findings_by_severity.high ?? 0;
  const activeIncidents = stats?.total_incidents ?? 0;
  const covered = stats ? SOURCES.filter((s) => stats.findings_by_source[s] > 0).length : 0;

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <Card
        label="Total Assets"
        value={stats?.total_assets ?? "–"}
        hint={`${stats?.total_findings ?? 0} findings tracked`}
        icon={<Boxes size={16} />}
      />
      <Card
        label="Active Incidents"
        value={stats ? activeIncidents : "–"}
        hint={
          stats ? `${stats.incidents_by_severity.critical} critical · ${stats.incidents_by_severity.high} high` : undefined
        }
        icon={<Siren size={16} />}
      />
      <Card
        label="Critical / High Findings"
        value={
          stats ? (
            <>
              <span className="text-red-400">{crit}</span>
              <span className="text-slate-600"> / </span>
              <span className="text-orange-400">{high}</span>
            </>
          ) : (
            "–"
          )
        }
        hint="critical / high"
        icon={<TriangleAlert size={16} />}
      />
      <Card
        label="Tool Coverage"
        value={stats ? `${covered}/${SOURCES.length}` : "–"}
        icon={<Layers size={16} />}
        hint={
          <ul className="mt-1 space-y-0.5">
            {SOURCES.map((s) => {
              const n = stats?.findings_by_source[s] ?? 0;
              return (
                <li key={s} className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5">
                    <span className={`h-1.5 w-1.5 rounded-full ${n > 0 ? "bg-emerald-400" : "bg-slate-600"}`} />
                    {SOURCE_LABEL[s]}
                  </span>
                  <span className="font-mono tabular-nums">{n}</span>
                </li>
              );
            })}
          </ul>
        }
      />
    </div>
  );
}
