"""Runtime configuration: constants and environment-derived paths."""

from __future__ import annotations

import os
from pathlib import Path

MAX_BODY_BYTES = 2 * 1024 * 1024  # strict ingestion payload ceiling (API and CLI)
MAX_FINDINGS_PER_REPORT = 10_000
MAX_API_KEY_LENGTH = 256

# Browser origins allowed to call the API (CORS) and open the event stream.
ALLOWED_ORIGINS = ("http://localhost:3000", "http://127.0.0.1:3000")

# Local AI triage (Ollama). Loopback only unless the operator explicitly opts out.
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
DEFAULT_OLLAMA_MODEL = "qwen2.5:7b"
OLLAMA_TIMEOUT_SECONDS = 45.0
OLLAMA_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost"})

DEFAULT_DB = "vigilhub.db"
DEFAULT_KEY_FILE = ".vigilhub_key"


def db_path(override: Path | str | None = None) -> Path:
    return Path(override or os.environ.get("VIGILHUB_DB") or DEFAULT_DB)


def key_file_path(override: Path | str | None = None) -> Path:
    return Path(override or os.environ.get("VIGILHUB_KEY_FILE") or DEFAULT_KEY_FILE)


def ollama_url() -> str:
    return os.environ.get("VIGILHUB_OLLAMA_URL") or DEFAULT_OLLAMA_URL


def ollama_model() -> str:
    return os.environ.get("VIGILHUB_OLLAMA_MODEL") or DEFAULT_OLLAMA_MODEL


def ollama_allow_remote() -> bool:
    return os.environ.get("VIGILHUB_OLLAMA_ALLOW_REMOTE") == "1"
