"""Runtime configuration: constants and environment-derived paths."""

from __future__ import annotations

import os
from pathlib import Path

MAX_BODY_BYTES = 2 * 1024 * 1024  # strict ingestion payload ceiling (API and CLI)
MAX_FINDINGS_PER_REPORT = 10_000
MAX_API_KEY_LENGTH = 256

DEFAULT_DB = "vigilhub.db"
DEFAULT_KEY_FILE = ".vigilhub_key"


def db_path(override: Path | str | None = None) -> Path:
    return Path(override or os.environ.get("VIGILHUB_DB") or DEFAULT_DB)


def key_file_path(override: Path | str | None = None) -> Path:
    return Path(override or os.environ.get("VIGILHUB_KEY_FILE") or DEFAULT_KEY_FILE)
