"""Machine-readable report.

This is the canonical artifact: the HTML is rendered from it, the API returns it,
and CI can diff two of them. Keeping one schema means the shareable report and the
`--json` output can never disagree.
"""

from __future__ import annotations

from preflight.models import ScanResult


def render_json(result: ScanResult, *, indent: int = 2) -> str:
    return result.model_dump_json(indent=indent)
