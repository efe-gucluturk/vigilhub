"use client";

import { useCallback, useState } from "react";
import { AssetDrawer } from "@/components/AssetDrawer";
import { AssetsTable } from "@/components/AssetsTable";
import { FindingsExplorer } from "@/components/FindingsExplorer";
import { Header } from "@/components/Header";
import { IncidentsPanel } from "@/components/IncidentsPanel";
import { IngestModal } from "@/components/IngestModal";
import { KeyGate } from "@/components/KeyGate";
import { KpiCards } from "@/components/KpiCards";
import { Toasts } from "@/components/Toasts";
import type { Asset } from "@/lib/types";
import { useHub } from "@/lib/useHub";

export default function Dashboard() {
  const hub = useHub();
  const [selected, setSelected] = useState<Asset | null>(null);
  const [ingestOpen, setIngestOpen] = useState(false);
  const { signOut } = hub;
  const rejected = useCallback(() => signOut("That API key was rejected."), [signOut]);

  if (!hub.ready) return null; // wait for sessionStorage restore to avoid a sign-in flash

  if (!hub.apiKey) {
    return <KeyGate onLogin={hub.login} initialError={hub.authError} />;
  }

  return (
    <>
      <Header
        status={hub.status}
        busy={hub.busy}
        onSeed={() => void hub.run("seed")}
        onCorrelate={() => void hub.run("correlate")}
        onIngest={() => setIngestOpen(true)}
        onSignOut={() => signOut()}
      />
      <main className="mx-auto max-w-7xl space-y-5 px-4 py-5">
        <KpiCards stats={hub.stats} />
        <IncidentsPanel incidents={hub.incidents} apiKey={hub.apiKey} onAuthError={rejected} />
        <AssetsTable assets={hub.assets} onSelect={setSelected} />
        <FindingsExplorer apiKey={hub.apiKey} tick={hub.tick} onAuthError={rejected} />
      </main>

      {selected && (
        <AssetDrawer
          apiKey={hub.apiKey}
          asset={hub.assets.find((a) => a.id === selected.id) ?? selected}
          tick={hub.tick}
          onClose={() => setSelected(null)}
          onAuthError={rejected}
        />
      )}
      {ingestOpen && (
        <IngestModal apiKey={hub.apiKey} onClose={() => setIngestOpen(false)} onAuthError={rejected} />
      )}
      <Toasts toasts={hub.toasts} />
    </>
  );
}
