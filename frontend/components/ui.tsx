"use client";

import { X } from "lucide-react";
import { useEffect, useRef, type ReactNode } from "react";
import { SOURCE_LABEL, type Severity, type Source } from "@/lib/types";

// Class names are written out in full so Tailwind can see them at build time.
const SEV_STYLE: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-300 ring-red-500/40",
  high: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  medium: "bg-yellow-500/15 text-yellow-300 ring-yellow-500/40",
  low: "bg-sky-500/15 text-sky-300 ring-sky-500/40",
  info: "bg-slate-500/15 text-slate-300 ring-slate-500/40",
};

export const SEV_BAR: Record<Severity, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-sky-400",
  info: "bg-slate-400",
};

const SOURCE_STYLE: Record<Source, string> = {
  vigilsiem: "bg-violet-500/15 text-violet-300 ring-violet-500/40",
  gitvigil: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40",
  reconvigil: "bg-cyan-500/15 text-cyan-300 ring-cyan-500/40",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset ${SEV_STYLE[severity]}`}
    >
      {severity}
    </span>
  );
}

export function SourceBadge({ source }: { source: Source }) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset ${SOURCE_STYLE[source]}`}
    >
      {SOURCE_LABEL[source]}
    </span>
  );
}

export function Chip({ children }: { children: ReactNode }) {
  return (
    <span className="inline-block max-w-full truncate rounded bg-ink-700 px-1.5 py-0.5 font-mono text-[11px] text-slate-300">
      {children}
    </span>
  );
}

export function riskSeverity(score: number): Severity {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  if (score > 0) return "low";
  return "info";
}

export function RiskBar({ score }: { score: number }) {
  const pct = Math.max(0, Math.min(100, score));
  return (
    <div
      className="flex items-center gap-2"
      role="meter"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={pct}
      aria-label="Risk score"
    >
      <div className="h-2 w-24 overflow-hidden rounded-full bg-ink-600">
        <div className={`h-full ${SEV_BAR[riskSeverity(pct)]}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="w-8 text-right font-mono text-xs tabular-nums text-slate-200">{pct}</span>
    </div>
  );
}

export function Panel({
  title,
  icon,
  actions,
  children,
}: {
  title: string;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-ink-600 bg-ink-900">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-ink-600 px-4 py-3">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-300">
          {icon}
          {title}
        </h2>
        {actions}
      </header>
      {children}
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="px-4 py-8 text-center text-sm text-slate-500">{children}</p>;
}

function useEscape(onClose: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
}

/** Accessible overlay used for both the centered modal and the side drawer. */
export function Overlay({
  title,
  onClose,
  side,
  closable = true,
  children,
}: {
  title: string;
  onClose: () => void;
  side?: boolean;
  closable?: boolean;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEscape(closable ? onClose : () => undefined);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    return () => previous?.focus?.();
  }, []);
  return (
    <div
      className={`fixed inset-0 z-40 flex bg-black/70 backdrop-blur-sm ${side ? "justify-end" : "items-center justify-center p-4"}`}
      onMouseDown={(e) => closable && e.target === e.currentTarget && onClose()}
    >
      <div
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`flex flex-col border border-ink-600 bg-ink-900 shadow-2xl outline-none ${
          side
            ? "h-full w-full max-w-2xl border-y-0 border-r-0"
            : "max-h-[90vh] w-full max-w-xl rounded-lg"
        }`}
      >
        <header className="flex items-center justify-between border-b border-ink-600 px-4 py-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-200">{title}</h2>
          {closable && (
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              className="rounded p-1 text-slate-400 hover:bg-ink-700 hover:text-white"
            >
              <X size={16} />
            </button>
          )}
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
      </div>
    </div>
  );
}

export const btn =
  "inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm font-medium text-slate-200 transition-colors hover:bg-ink-700 disabled:cursor-not-allowed disabled:opacity-50";
export const btnPrimary =
  "inline-flex items-center gap-1.5 rounded-md border border-blue-500/60 bg-blue-600 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50";
export const field =
  "w-full rounded-md border border-ink-600 bg-ink-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600";
