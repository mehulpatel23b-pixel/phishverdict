"""phishverdict - offline phishing-URL triage CLI."""
__version__ = "1.0.0"

from .engine import Result, analyze, triage  # noqa: F401
