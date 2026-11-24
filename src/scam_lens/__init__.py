"""scam-lens: an offline, rule-based explainer for suspicious messages."""

from .analyzer import LIKELY_SCAM, NO_KNOWN_RED_FLAGS, SUSPICIOUS, Finding, Report, analyze
from .rules import Pack, list_packs, load_pack, load_pack_file

__version__ = "0.1.0"

__all__ = [
    "analyze", "Report", "Finding", "Pack", "load_pack", "load_pack_file", "list_packs",
    "NO_KNOWN_RED_FLAGS", "SUSPICIOUS", "LIKELY_SCAM", "__version__",
]
