"use client";

import { FileUp, GitMerge, LogOut, Radar, Sprout } from "lucide-react";
import type { LiveStatus } from "@/lib/types";
import { btn } from "./ui";

const STATUS_STYLE: Record<LiveStatus, { dot: string; text: string; label: string }> = {
  live: { dot: "bg-emerald-400 pulse-dot", text: "text-emerald-300", label: "LIVE" },
  connecting: { dot: "bg-yellow-400 pulse-dot", text: "text-yellow-300", label: "CONNECTING" },
  offline: { dot: "bg-red-500", text: "text-red-300", label: "OFFLINE" },
};

export function Header({
  status,
  busy,
  onSeed,
  onCorrelate,
  onIngest,
  onSignOut,
}: {
  status: LiveStatus;
  busy: "seed" | "correlate" | null;
  onSeed: () => void;
  onCorrelate: () => void;
  onIngest: () => void;
  onSignOut: () => void;
}) {
  const s = STATUS_STYLE[status];
  return (
    <header className="sticky top-0 z-30 border-b border-ink-600 bg-ink-950/90 backdrop-blur">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3">
        <div className="flex items-center gap-3">
          <Radar className="text-blue-400" size={22} />
          <h1 className="text-base font-semibold tracking-wide text-white">
            VigilHub <span className="font-normal text-slate-500">/ SOC Command Center</span>
          </h1>
          <span
            role="status"
            aria-label={`Event stream ${s.label}`}
            className={`flex items-center gap-1.5 rounded-full border border-ink-600 bg-ink-900 px-2.5 py-1 text-[11px] font-semibold tracking-wider ${s.text}`}
          >
            <span className={`h-2 w-2 rounded-full ${s.dot}`} />
            {s.label}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" className={btn} onClick={onSeed} disabled={busy !== null}>
            <Sprout size={15} />
            {busy === "seed" ? "Seeding…" : "Seed Demo Data"}
          </button>
          <button type="button" className={btn} onClick={onCorrelate} disabled={busy !== null}>
            <GitMerge size={15} />
            {busy === "correlate" ? "Correlating…" : "Run Correlation"}
          </button>
          <button type="button" className={btn} onClick={onIngest}>
            <FileUp size={15} />
            Ingest Report
          </button>
          <button type="button" className={btn} onClick={onSignOut} aria-label="Sign out">
            <LogOut size={15} />
          </button>
        </div>
      </div>
    </header>
  );
}
