"""Redaction.

Two consumers of a finding are outside our trust boundary: the report the user
may forward to an investor, and the LLM in the explanation layer. Neither should
ever receive a live credential. Redaction happens once, at Evidence construction,
so that nothing downstream has to remember to do it.
"""

from __future__ import annotations

MIN_KEEP = 12


def redact_secret(value: str) -> str:
    """Reduce a credential to something recognisable but useless.

    >>> redact_secret("sk-abcdefghijklmnopqrstuvwxyz")
    'sk-a...wxyz (27 chars)'
    """
    stripped = value.strip().strip("\"'")
    if len(stripped) < MIN_KEEP:
        return f"[redacted {len(stripped)} chars]"
    return f"{stripped[:4]}...{stripped[-4:]} ({len(stripped)} chars)"


def redact_in_line(line: str, secret: str, *, max_length: int = 200) -> str:
    """Return `line` with `secret` replaced by its redaction, trimmed for display."""
    cleaned = line.strip()
    stripped = secret.strip().strip("\"'")
    if stripped:
        cleaned = cleaned.replace(stripped, redact_secret(stripped))
    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 1] + "…"
    return cleaned
