# VigilHub

Security command center for the Vigil toolchain. It ingests reports from
[VigilSIEM](../vigilsiem), [GitVigil](../gitvigil) and [ReconVigil](../reconvigil),
normalizes targets into assets, scores asset risk (0-100), and links findings from
different tools into incidents (e.g. exposed staging host + leaked key + active brute force).

## Quick start

```
python -m venv .venv && .venv\Scripts\activate
pip install -e ".[dev]"
vigilhub init-db          # creates vigilhub.db and a local .vigilhub_key
vigilhub seed-demo        # loads sample findings from all three tools and correlates
vigilhub status
vigilhub serve            # http://127.0.0.1:8000, send the key in X-API-Key
```

```
curl -H "X-API-Key: $(cat .vigilhub_key)" http://127.0.0.1:8000/api/v1/incidents
```

## Accepted input

| Source | Format |
|---|---|
| `vigilsiem` | JSON list of alerts (`/alerts` API shape), `{"alerts": [...]}`, or a list of raw events |
| `gitvigil` | `gitvigil scan --format json` output, or SARIF v2.1.0 |
| `reconvigil` | ReconVigil JSON report (`{"tool", "scan": {...}}`) |

## API

`GET /health` is open. Everything under `/api/v1` needs `X-API-Key`:
`POST /ingest/{source}`, `GET /assets[/{id}]`, `GET /findings?source=&severity=&asset=`,
`GET /incidents`, `POST /correlate`, `POST /demo/seed`. Request bodies are capped at 2 MB.

See `CLAUDE.md` for the engineering and security rules.
