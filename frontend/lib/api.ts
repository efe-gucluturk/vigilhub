import type {
  Asset,
  AssetDetail,
  CorrelateResult,
  Finding,
  Incident,
  IngestResult,
  SeedResult,
  Severity,
  Source,
  Stats,
} from "./types";

export const API_BASE = (process.env.NEXT_PUBLIC_VIGILHUB_API ?? "http://127.0.0.1:8000").replace(
  /\/+$/,
  "",
);
export const WS_URL = `${API_BASE.replace(/^http/, "ws")}/api/v1/ws`;
export const MAX_BODY_BYTES = 2 * 1024 * 1024; // keep in sync with config.MAX_BODY_BYTES

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function describe(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) =>
        d && typeof d === "object" && "msg" in d ? String((d as { msg: unknown }).msg) : "invalid",
      )
      .join("; ");
  }
  return "request failed";
}

async function request<T>(key: string, path: string, init: RequestInit = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { ...(init.headers ?? {}), "X-API-Key": key },
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, `Cannot reach the VigilHub API at ${API_BASE}`);
  }
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { detail?: unknown };
      message = describe(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message);
  }
  return (await res.json()) as T;
}

export const api = {
  stats: (key: string) => request<Stats>(key, "/api/v1/stats"),
  assets: (key: string) => request<Asset[]>(key, "/api/v1/assets?limit=500"),
  asset: (key: string, id: string) =>
    request<AssetDetail>(key, `/api/v1/assets/${encodeURIComponent(id)}`),
  incidents: (key: string) => request<Incident[]>(key, "/api/v1/incidents?limit=200"),
  findings: (key: string, f: { source?: Source | ""; severity?: Severity | "" }) => {
    const q = new URLSearchParams({ limit: "500" });
    if (f.source) q.set("source", f.source);
    if (f.severity) q.set("severity", f.severity);
    return request<Finding[]>(key, `/api/v1/findings?${q}`);
  },
  correlate: (key: string) =>
    request<CorrelateResult>(key, "/api/v1/correlate", { method: "POST" }),
  seed: (key: string) => request<SeedResult>(key, "/api/v1/demo/seed", { method: "POST" }),
  ingest: (key: string, source: Source, body: string, target: string) => {
    const q = target.trim() ? `?${new URLSearchParams({ target: target.trim() })}` : "";
    return request<IngestResult>(key, `/api/v1/ingest/${source}${q}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
  },
};
