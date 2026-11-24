"use client";

import { KeyRound, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Overlay, btnPrimary, field } from "./ui";

export function KeyGate({
  onLogin,
  initialError,
}: {
  onLogin: (key: string) => Promise<string>;
  initialError: string;
}) {
  const [value, setValue] = useState("");
  const [error, setError] = useState("");
  const [checking, setChecking] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setChecking(true);
    setError(await onLogin(value));
    setChecking(false);
  }

  const shown = error || initialError;

  return (
    <Overlay title="Operator sign-in" onClose={() => undefined} closable={false}>
      <form onSubmit={submit} className="space-y-4 p-5">
        <div className="flex items-start gap-3 text-sm text-slate-400">
          <ShieldCheck className="mt-0.5 shrink-0 text-blue-400" size={18} />
          <p>
            Paste the key from your local <code className="font-mono text-slate-300">.vigilhub_key</code>{" "}
            file (created by <code className="font-mono text-slate-300">vigilhub init-db</code>). It is
            kept in this tab&apos;s session storage only and sent as the{" "}
            <code className="font-mono text-slate-300">X-API-Key</code> header.
          </p>
        </div>
        <label className="block text-sm">
          <span className="mb-1 flex items-center gap-1.5 text-slate-300">
            <KeyRound size={14} /> API key
          </span>
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            autoFocus
            value={value}
            onChange={(e) => setValue(e.target.value)}
            className={`${field} font-mono`}
            placeholder="paste key"
            maxLength={256}
          />
        </label>
        {shown && (
          <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">
            {shown}
          </p>
        )}
        <button type="submit" disabled={checking || !value.trim()} className={`${btnPrimary} w-full justify-center`}>
          {checking ? "Verifying…" : "Unlock dashboard"}
        </button>
      </form>
    </Overlay>
  );
}
