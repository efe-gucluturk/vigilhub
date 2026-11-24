"use client";

import { CheckCircle2, CircleAlert } from "lucide-react";
import type { Toast } from "@/lib/useHub";

export function Toasts({ toasts }: { toasts: Toast[] }) {
  return (
    <div aria-live="polite" className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`flex items-start gap-2 rounded-md border px-3 py-2 text-sm shadow-lg ${
            t.kind === "ok"
              ? "border-emerald-500/40 bg-ink-900 text-emerald-200"
              : "border-red-500/40 bg-ink-900 text-red-200"
          }`}
        >
          {t.kind === "ok" ? <CheckCircle2 size={16} className="mt-0.5 shrink-0" /> : <CircleAlert size={16} className="mt-0.5 shrink-0" />}
          <span className="break-words">{t.text}</span>
        </div>
      ))}
    </div>
  );
}
