"use client";

import { ArrowDown, ArrowUp, Boxes } from "lucide-react";
import { useMemo, useState } from "react";
import type { Asset } from "@/lib/types";
import { Chip, Empty, Panel, RiskBar, SourceBadge } from "./ui";

type SortKey = "risk_score" | "name" | "kind" | "finding_count";

const COLUMNS: { key: SortKey; label: string }[] = [
  { key: "risk_score", label: "Risk" },
  { key: "name", label: "Asset" },
  { key: "kind", label: "Kind" },
  { key: "finding_count", label: "Findings" },
];

export function AssetsTable({
  assets,
  onSelect,
}: {
  assets: Asset[];
  onSelect: (asset: Asset) => void;
}) {
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({ key: "risk_score", dir: "desc" });

  const sorted = useMemo(() => {
    const sign = sort.dir === "asc" ? 1 : -1;
    return [...assets].sort((a, b) => {
      const av = a[sort.key];
      const bv = b[sort.key];
      const cmp = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv));
      return cmp * sign || a.id.localeCompare(b.id);
    });
  }, [assets, sort]);

  function toggle(key: SortKey) {
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: key === "name" || key === "kind" ? "asc" : "desc" }));
  }

  return (
    <Panel title="Asset Risk Inventory" icon={<Boxes size={15} />}>
      {assets.length === 0 ? (
        <Empty>No assets yet.</Empty>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[40rem] text-left text-sm">
            <thead className="text-xs uppercase tracking-wider text-slate-500">
              <tr className="border-b border-ink-600">
                {COLUMNS.map((c) => (
                  <th
                    key={c.key}
                    scope="col"
                    aria-sort={sort.key === c.key ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}
                    className="px-4 py-2 font-medium"
                  >
                    <button type="button" onClick={() => toggle(c.key)} className="inline-flex items-center gap-1 uppercase tracking-wider hover:text-white">
                      {c.label}
                      {sort.key === c.key && (sort.dir === "asc" ? <ArrowUp size={12} /> : <ArrowDown size={12} />)}
                    </button>
                  </th>
                ))}
                <th scope="col" className="px-4 py-2 font-medium">
                  Aliases
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  Tools
                </th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((a) => (
                <tr key={a.id} className="border-b border-ink-600 last:border-b-0 hover:bg-ink-800/70">
                  <td className="px-4 py-2">
                    <RiskBar score={a.risk_score} />
                  </td>
                  <td className="max-w-[16rem] px-4 py-2">
                    <button
                      type="button"
                      onClick={() => onSelect(a)}
                      className="block max-w-full truncate text-left font-mono text-xs text-blue-300 hover:underline"
                    >
                      {a.name}
                    </button>
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-400">{a.kind}</td>
                  <td className="px-4 py-2 font-mono text-xs tabular-nums">{a.finding_count}</td>
                  <td className="px-4 py-2">
                    <div className="flex max-w-[14rem] flex-wrap gap-1">
                      {a.aliases.length === 0 ? <span className="text-xs text-slate-600">–</span> : a.aliases.map((x) => <Chip key={x}>{x}</Chip>)}
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-1">
                      {a.sources.map((s) => (
                        <SourceBadge key={s} source={s} />
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
