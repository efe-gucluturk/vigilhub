"use client";

import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { Asset, AssetDetail } from "@/lib/types";
import { FindingList } from "./FindingList";
import { Chip, Empty, Overlay, RiskBar, SourceBadge } from "./ui";

export function AssetDrawer({
  apiKey,
  asset,
  tick,
  onClose,
  onAuthError,
}: {
  apiKey: string;
  asset: Asset;
  tick: number;
  onClose: () => void;
  onAuthError: () => void;
}) {
  const [detail, setDetail] = useState<AssetDetail | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    api
      .asset(apiKey, asset.id)
      .then((d) => !cancelled && setDetail(d))
      .catch((e: unknown) => {
        if (cancelled) return;
        if (e instanceof ApiError && e.status === 401) onAuthError();
        else setError(e instanceof Error ? e.message : "Could not load asset");
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, asset.id, tick, onAuthError]);

  const current = detail?.asset ?? asset;

  return (
    <Overlay title="Asset detail" onClose={onClose} side>
      <div className="space-y-4 border-b border-ink-600 px-4 py-4">
        <div>
          <div className="break-all font-mono text-base text-white">{current.name}</div>
          <div className="mt-0.5 text-xs text-slate-500">
            {current.kind} · <span className="font-mono">{current.id}</span>
          </div>
        </div>
        <RiskBar score={current.risk_score} />
        <div className="flex flex-wrap gap-1.5">
          {current.sources.map((s) => (
            <SourceBadge key={s} source={s} />
          ))}
          {current.aliases.map((a) => (
            <Chip key={a}>{a}</Chip>
          ))}
        </div>
        {detail && detail.incident_ids.length > 0 && (
          <p className="text-xs text-orange-300">Part of {detail.incident_ids.length} correlated incident(s).</p>
        )}
      </div>
      {error && (
        <p role="alert" className="px-4 py-3 text-sm text-red-300">
          {error}
        </p>
      )}
      {!detail && !error ? (
        <Empty>Loading…</Empty>
      ) : detail && detail.findings.length === 0 ? (
        <Empty>No findings for this asset.</Empty>
      ) : detail ? (
        <FindingList findings={detail.findings} />
      ) : null}
    </Overlay>
  );
}
