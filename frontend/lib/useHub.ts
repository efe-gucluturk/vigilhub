"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, WS_URL } from "./api";
import { clearKey, loadKey, saveKey } from "./session";
import type { Asset, HubEvent, Incident, LiveStatus, Stats } from "./types";

const AUTH_FAILED = 1008;
const REFRESH_DEBOUNCE_MS = 150;

export interface Toast {
  id: number;
  kind: "ok" | "error";
  text: string;
}

function describeEvent(ev: HubEvent): string {
  switch (ev.type) {
    case "ingest_completed":
      return `Ingested ${ev.data.accepted} ${ev.data.source} findings`;
    case "correlation_updated":
      return `Correlation updated: ${ev.data.incidents} incidents`;
    case "demo_seeded":
      return `Demo data seeded: ${ev.data.correlation.incidents} incidents`;
  }
}

function isHubEvent(v: unknown): v is HubEvent {
  if (!v || typeof v !== "object") return false;
  const t = (v as { type?: unknown }).type;
  return t === "ingest_completed" || t === "correlation_updated" || t === "demo_seeded";
}

export function useHub() {
  const [ready, setReady] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [status, setStatus] = useState<LiveStatus>("offline");
  const [stats, setStats] = useState<Stats | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [tick, setTick] = useState(0); // bumps on every data change; children refetch on it
  const [busy, setBusy] = useState<"seed" | "correlate" | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [authError, setAuthError] = useState("");
  const toastId = useRef(0);

  const toast = useCallback((kind: Toast["kind"], text: string) => {
    const id = ++toastId.current;
    setToasts((t) => [...t.slice(-3), { id, kind, text }]);
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000);
  }, []);

  const signOut = useCallback((message = "") => {
    clearKey();
    setApiKey("");
    setStats(null);
    setIncidents([]);
    setAssets([]);
    setStatus("offline");
    setAuthError(message);
  }, []);

  // Restore the session key after mount (sessionStorage does not exist during SSR).
  useEffect(() => {
    setApiKey(loadKey());
    setReady(true);
  }, []);

  const refresh = useCallback(async () => {
    if (!apiKey) return;
    try {
      const [s, i, a] = await Promise.all([
        api.stats(apiKey),
        api.incidents(apiKey),
        api.assets(apiKey),
      ]);
      setStats(s);
      setIncidents(i);
      setAssets(a);
      setTick((n) => n + 1);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) signOut("That API key was rejected.");
      else toast("error", e instanceof Error ? e.message : "Refresh failed");
    }
  }, [apiKey, signOut, toast]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // WebSocket with an auth-frame handshake (the key is never put in the URL) and
  // exponential-backoff reconnect.
  useEffect(() => {
    if (!apiKey) return;
    let socket: WebSocket | null = null;
    let retry = 0;
    let timer: number | undefined;
    let debounce: number | undefined;
    let disposed = false;

    const connect = () => {
      setStatus("connecting");
      socket = new WebSocket(WS_URL);
      socket.onopen = () => socket?.send(JSON.stringify({ type: "auth", api_key: apiKey }));
      socket.onmessage = (msg: MessageEvent<string>) => {
        let data: unknown;
        try {
          data = JSON.parse(msg.data);
        } catch {
          return;
        }
        if (data && typeof data === "object" && (data as { type?: unknown }).type === "auth_ok") {
          retry = 0;
          setStatus("live");
          return;
        }
        if (isHubEvent(data)) {
          toast("ok", describeEvent(data));
          window.clearTimeout(debounce);
          debounce = window.setTimeout(() => void refresh(), REFRESH_DEBOUNCE_MS);
        }
      };
      socket.onclose = (ev) => {
        if (disposed) return;
        setStatus("offline");
        if (ev.code === AUTH_FAILED) {
          signOut("The event stream rejected that API key.");
          return;
        }
        timer = window.setTimeout(connect, Math.min(15000, 1000 * 2 ** retry++));
      };
    };
    connect();

    return () => {
      disposed = true;
      window.clearTimeout(timer);
      window.clearTimeout(debounce);
      socket?.close();
    };
  }, [apiKey, refresh, signOut, toast]);

  /** Validates the key against the API before keeping it. Returns an error message or "". */
  const login = useCallback(async (candidate: string): Promise<string> => {
    const key = candidate.trim();
    if (!key) return "Enter your API key.";
    try {
      await api.stats(key);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return "That API key was rejected.";
      return e instanceof Error ? e.message : "Could not verify the key.";
    }
    saveKey(key);
    setAuthError("");
    setApiKey(key);
    return "";
  }, []);

  const run = useCallback(
    async (kind: "seed" | "correlate") => {
      if (!apiKey || busy) return;
      setBusy(kind);
      try {
        if (kind === "seed") await api.seed(apiKey);
        else await api.correlate(apiKey);
        // With the socket down no broadcast will arrive, so refresh directly.
        if (status !== "live") await refresh();
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) signOut("That API key was rejected.");
        else toast("error", e instanceof Error ? e.message : "Action failed");
      } finally {
        setBusy(null);
      }
    },
    [apiKey, busy, refresh, signOut, status, toast],
  );

  return {
    ready,
    apiKey,
    authError,
    status,
    stats,
    incidents,
    assets,
    tick,
    busy,
    toasts,
    toast,
    login,
    signOut,
    refresh,
    run,
  };
}

export type Hub = ReturnType<typeof useHub>;
