# VigilHub

VigilHub is a small security dashboard I built as a first-year Information Security Technology
student. It is the "hub" for three other tools I wrote: **VigilSIEM** (log alerts),
**GitVigil** (repo/secret/IaC scanning) and **ReconVigil** (attack-surface recon).

Each tool is useful alone, but a real incident usually shows up in more than one of them.
VigilHub reads all three outputs, puts the findings onto shared **assets**, and groups related
findings into **incidents**.

This is a learning project, not a product. It runs locally, has one API key, and has not been
audited by anyone but me and some automated tools (ruff, bandit, pytest).

## What it does

- Ingests JSON reports from VigilSIEM, GitVigil (JSON or SARIF) and ReconVigil.
- Normalizes targets so the same machine is recognised across tools
  (for example `staging.acmecorp.example` from ReconVigil, its IP `203.0.113.10` from VigilSIEM,
  and the repo that deploys it from GitVigil all end up on one asset).
- Scores each asset's risk from 0 to 100.
- Correlates findings into incidents, e.g. *exposed `.env` on a host* + *leaked cloud key in its
  repo* + *brute-force attempts against its IP*.
- Shows everything in a live dashboard (WebSocket updates) and can write a short triage for
  each incident (optionally with a local AI model).

The correlation code is deterministic: the same findings always give the same incident ids.

## Architecture

```
 VigilSIEM        GitVigil         ReconVigil
 (log alerts)   (repo scanning)   (attack surface)
      |               |                 |
      +---------------+-----------------+
                      |  JSON / SARIF reports
                      v
        +---------------------------+
        |  adapters/  (parse, drop  |   untrusted text is sanitized,
        |  secrets, validate)       |   targets must normalize
        +-------------+-------------+
                      v
        +---------------------------+
        |  SQLite (WAL)  assets +   |   parameterized SQL only
        |  findings + incidents     |
        +------+------------+-------+
               |            |
               v            v
      correlation/       ai/analyst.py ----> Ollama (local, optional)
      (pure functions)        |                 |
               |              +--- if Ollama is off: rule-based triage
               v
        +---------------------------+
        |  FastAPI  127.0.0.1:8000  |  X-API-Key on every /api/v1 route
        |  REST + WebSocket stream  |
        +-------------+-------------+
                      |
                      v
        +---------------------------+
        |  Next.js dashboard        |  http://127.0.0.1:3000
        |  (React text nodes only)  |
        +---------------------------+
```

## Quickstart (Windows)

You need Python 3.12+, Node.js 20+ and PowerShell.

```powershell
git clone https://github.com/efe-gucluturk/vigilhub
cd vigilhub
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
.\start.ps1
```

`start.ps1`:

1. creates `vigilhub.db` and `.vigilhub_key` on the first run (`vigilhub init-db`) and prints
   the key so you can copy it,
2. runs `npm install` in `frontend/` if needed,
3. starts the API on `127.0.0.1:8000` and the dashboard on `127.0.0.1:3000`,
4. stops both when you press `Ctrl+C`.

Then open <http://127.0.0.1:3000>, paste the key, and press **Seed demo** in the header. That
loads made-up reports from all three tools (using reserved example addresses) and correlates
them, so you get a full incident to look at. The dashboard updates live over the WebSocket
when you ingest or correlate from somewhere else, for example the CLI:

```powershell
vigilhub status
vigilhub seed-demo
```

If you would rather do it by hand: `vigilhub init-db`, then `vigilhub serve` in one terminal and
`cd frontend; npm install; npm run dev` in another.

### Optional: local AI triage with Ollama

Expand an incident and click **Analyze Incident**. VigilHub asks a model running on *your own
machine* for a summary, how the findings connect, and 3-5 fixes.

```powershell
ollama pull qwen2.5:7b
ollama serve      # skip if the Ollama app is already running
```

Nothing is sent to the internet. If Ollama is not running, is too slow (45 s timeout), or returns
something that is not the JSON shape I asked for, VigilHub automatically falls back to a
rule-based triage and the dashboard labels it **Offline Rule Triage**. So the button always
works; it just gives a simpler answer without the model.

| Variable | Default | Meaning |
|---|---|---|
| `VIGILHUB_OLLAMA_URL` | `http://127.0.0.1:11434/api/generate` | Must be `127.0.0.1` or `localhost` |
| `VIGILHUB_OLLAMA_MODEL` | `qwen2.5:7b` | Any model you have pulled |

A small 7B model can be wrong. Treat the output as a starting point for a human, not a verdict.

## Input formats

| Source | Format |
|---|---|
| `vigilsiem` | JSON list of alerts, `{"alerts": [...]}`, or a list of raw events |
| `gitvigil` | `gitvigil scan --format json` output, or SARIF v2.1.0 |
| `reconvigil` | ReconVigil JSON report (`{"tool", "scan": {...}}`) |

## API

`GET /health` is open. Everything under `/api/v1` needs the `X-API-Key` header:

- `POST /ingest/{source}`, `POST /correlate`, `POST /demo/seed`
- `GET /assets`, `GET /assets/{id}`, `GET /findings`, `GET /incidents`, `GET /stats`
- `POST /incidents/{id}/analyze` returns `summary`, `attack_chain`, `remediation_steps`,
  `model` and `fallback_used`
- `WS /ws` streams `ingest_completed`, `correlation_updated` and `demo_seeded` events

```powershell
curl.exe -H "X-API-Key: $(Get-Content .vigilhub_key)" http://127.0.0.1:8000/api/v1/incidents
```

## Security design notes

I tried to treat every scanner report as hostile input, since the whole point of the tool is
handling data from things that look at attackers.

- **API keys**: only the SHA-256 hash is stored in the database. Checking a key uses
  `hmac.compare_digest` against every active hash (no early exit). The raw key only exists in
  the local `.vigilhub_key` file, which is in `.gitignore` along with `*.db*`.
- **SQL injection**: parameterized queries only. Optional filters use `? IS NULL OR col = ?`
  instead of building strings.
- **Payload limit**: request bodies are capped at 2 MB, checked on `Content-Length` and again on
  the streamed bytes. The CLI uses the same limit for files.
- **Untrusted text**: control and bidi/format characters are stripped and fields are truncated
  when a `Finding` is created. Targets must also normalize to a valid host, IP, domain or repo or
  the record is rejected.
- **Secret stripping**: GitVigil's optional raw `secret` field is dropped by the adapter. Only
  redacted matches are stored. Before anything goes to the AI model, secret-looking strings
  (AWS keys, GitHub tokens, JWTs, private keys, `password=...`) are redacted again.
- **Prompt injection**: finding text is put inside `<evidence>` tags, any fake closing tag in the
  data is neutralised, and the prompt says to treat it as data. The model's reply is parsed
  strictly and sanitized; if it does not match the schema it is thrown away. This reduces the
  risk but I can't claim it removes it, which is why the output is only advice.
- **SSRF**: the Ollama URL is only used if its host is `127.0.0.1` or `localhost`. Redirects and
  proxy environment variables are ignored.
- **XSS**: the dashboard renders all scanner text (and AI text) as React text nodes. There is no
  `dangerouslySetInnerHTML`, `innerHTML`, `eval` or `localStorage`, and a test
  (`tests/test_frontend_guard.py`) fails if one is added. The API key is kept in
  `sessionStorage`, so it disappears when the tab closes, and is never part of the built bundle.
- **WebSocket**: the key is never accepted in the URL (it would end up in logs). Use the
  `X-API-Key` handshake header or a first `auth` frame within 5 seconds, otherwise the
  connection is closed with 1008.
- **CORS / Origin**: only `http://localhost:3000` and `http://127.0.0.1:3000` are allowed, for
  both CORS and the WebSocket.
- **Defaults**: the server binds to `127.0.0.1`, `/docs` and OpenAPI are disabled, and responses
  carry security headers (CSP, `nosniff`, `no-store`, frame deny).

### Known limits

- One shared API key, no user accounts or roles.
- Plain HTTP on localhost only. Put a reverse proxy with TLS in front before exposing it anywhere.
- Correlation rules are simple and hand-written (see `correlation/engine.py`).

## Development

```powershell
ruff check .
bandit -r src/ -c pyproject.toml
pytest -v
cd frontend; npx tsc --noEmit; npm run build
```

The same checks run in GitHub Actions (`.github/workflows/ci.yml`). Tests run offline; Ollama
is mocked. See `CLAUDE.md` for the engineering rules.

## Layout

```
src/vigilhub/
  adapters/      one parser per tool (accept the other tool's schema)
  correlation/   target normalization + incident rules (pure, deterministic)
  ai/            Ollama client and offline fallback triage
  api/           FastAPI app, auth, middleware, WebSocket
  db.py          all SQL          service.py  business logic          cli.py  typer CLI
frontend/        Next.js + Tailwind dashboard
tests/           pytest suite
```
