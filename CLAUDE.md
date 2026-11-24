# VigilHub engineering rules

VigilHub ingests output from VigilSIEM, GitVigil and ReconVigil, normalizes it into
assets and findings, and correlates findings across tools into incidents.
Python 3.12+, `src/vigilhub/` layout.

## Commands

```
python -m venv .venv && .venv\Scripts\activate
pip install -e ".[dev]"
ruff check .
bandit -r src/ -c pyproject.toml
pytest -v
```

All three must pass before a change is done. Tests run offline: no network, no
sibling repositories needed (fixtures are built in `vigilhub.demo` and `tests/`).

## Security rules (non-negotiable)

1. **SQL**: parameterized queries only (`?` placeholders) in static SQL. Never build SQL
   with f-strings or concatenation; optional filters use `? IS NULL OR col = ?`.
   SQLite runs in `WAL` mode with `foreign_keys=ON`.
2. **API keys**: store only the SHA-256 hash. Compare with `hmac.compare_digest`
   against every active hash (no early exit). Raw keys exist only in the local
   `.vigilhub_key` file created by `init-db`; that file and `*.db*` stay in `.gitignore`.
3. **Payload limit**: 2 MB max request body (`config.MAX_BODY_BYTES`), enforced on
   `Content-Length` and on streamed bytes. CLI file ingestion applies the same limit.
4. **Untrusted strings**: everything from a scanner report is untrusted (rule titles,
   commit messages, log lines, targets). `sanitize.sanitize_text` strips control and
   bidi/format characters and truncates; `Finding` applies it in validators so no path
   skips it. Targets must additionally pass `normalize_target` or the record is rejected.
   Data is stored raw otherwise (no HTML escaping) - any future UI must escape on output.
5. **No hardcoded secrets**: no keys, tokens or passwords in source. Tests use values
   generated at runtime or obviously fake literals.
6. **Never ingest raw secrets**: GitVigil's optional `secret` field is dropped by the
   adapter. Only redacted matches are stored.
7. **Rich output**: wrap untrusted text in `rich.text.Text` so it is not parsed as markup.
8. The server binds `127.0.0.1` by default. The OpenAPI/docs endpoints are disabled.

## Conventions

- Adapters (`adapters/`) accept the *other tool's* schema, so their input models use
  `extra="ignore"`; everything VigilHub produces (`models.py`) uses `extra="forbid"`.
- Correlation (`correlation/`) is pure and deterministic: models in, models out, no I/O,
  no clocks, no randomness. Same findings must always yield the same incident ids.
- DB access lives in `db.py`; business logic in `service.py`; API and CLI are thin.
- Keep comments for the *why*. Line length 100, ruff rules `E,F,W,I,B,UP,S,SIM,RUF`.
