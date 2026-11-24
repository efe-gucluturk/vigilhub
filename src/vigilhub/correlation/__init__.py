"""Asset normalization and cross-tool correlation."""

from vigilhub.correlation.engine import build_assets, correlate
from vigilhub.correlation.normalize import normalize_target

__all__ = ["build_assets", "correlate", "normalize_target"]
