"use client";

import { Upload } from "lucide-react";
import { useState, type ChangeEvent, type FormEvent } from "react";
import { api, ApiError, MAX_BODY_BYTES } from "@/lib/api";
import { SOURCES, SOURCE_LABEL, type IngestResult, type Source } from "@/lib/types";
import { Overlay, btn, btnPrimary, field } from "./ui";

export function IngestModal({
  apiKey,
  onClose,
  onAuthError,
}: {
  apiKey: string;
  onClose: () => void;
  onAuthError: () => void;
}) {
  const [source, setSource] = useState<Source>("reconvigil");
  const [target, setTarget] = useState("");
  const [body, setBody] = useState("");
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState<IngestResult | null>(null);
  const [sending, setSending] = useState(false);

  const bytes = new TextEncoder().encode(body).length;

  async function onFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > MAX_BODY_BYTES) {
      setError(`${file.name} is larger than the 2 MB ingestion limit.`);
      return;
    }
    setFileName(file.name);
    setBody(await file.text());
    setError("");
    setResult(null);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setResult(null);
    if (!body.trim()) return setError("Paste or upload a report first.");
    if (bytes > MAX_BODY_BYTES) return setError("Report is larger than the 2 MB ingestion limit.");
    try {
      JSON.parse(body);
    } catch {
      return setError("That is not valid JSON.");
    }
    setSending(true);
    try {
      setResult(await api.ingest(apiKey, source, body, target));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onAuthError();
      else setError(err instanceof Error ? err.message : "Ingest failed");
    } finally {
      setSending(false);
    }
  }

  return (
    <Overlay title="Ingest report" onClose={onClose}>
      <form onSubmit={submit} className="space-y-4 p-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block text-sm">
            <span className="mb-1 block text-slate-300">Source tool</span>
            <select value={source} onChange={(e) => setSource(e.target.value as Source)} className={field}>
              {SOURCES.map((s) => (
                <option key={s} value={s}>
                  {SOURCE_LABEL[s]}
                </option>
              ))}
            </select>
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-slate-300">
              Target <span className="text-slate-500">(optional)</span>
            </span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. repo name for SARIF"
              maxLength={512}
              className={field}
            />
          </label>
        </div>

        <label className="block text-sm">
          <span className="mb-1 block text-slate-300">Report file (JSON or SARIF)</span>
          <input
            type="file"
            accept=".json,.sarif,application/json"
            onChange={onFile}
            className="block w-full text-sm text-slate-400 file:mr-3 file:rounded-md file:border file:border-ink-600 file:bg-ink-800 file:px-3 file:py-1.5 file:text-slate-200 hover:file:bg-ink-700"
          />
          {fileName && <span className="mt-1 block text-xs text-slate-500">{fileName}</span>}
        </label>

        <label className="block text-sm">
          <span className="mb-1 flex justify-between text-slate-300">
            <span>…or paste JSON</span>
            <span className="font-mono text-xs text-slate-500">{(bytes / 1024).toFixed(1)} KB / 2048 KB</span>
          </span>
          <textarea
            value={body}
            onChange={(e) => {
              setBody(e.target.value);
              setFileName("");
              setResult(null);
            }}
            rows={9}
            spellCheck={false}
            className={`${field} font-mono text-xs`}
            placeholder='{"tool": {"name": "reconvigil"}, "scan": {...}}'
          />
        </label>

        {error && (
          <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">
            {error}
          </p>
        )}
        {result && (
          <div role="status" className="rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">
            Stored {result.accepted} {result.source} findings ({result.skipped} skipped). The dashboard updates live.
            {result.warnings.length > 0 && (
              <ul className="mt-1 list-disc pl-5 text-xs text-emerald-200/80">
                {result.warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <button type="button" className={btn} onClick={onClose}>
            {result ? "Done" : "Cancel"}
          </button>
          <button type="submit" className={btnPrimary} disabled={sending}>
            <Upload size={15} />
            {sending ? "Ingesting…" : "Ingest"}
          </button>
        </div>
      </form>
    </Overlay>
  );
}
