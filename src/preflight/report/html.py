"""Human-readable report.

Structure follows spec section 7 exactly, including the two sections that are
easy to skip and are the reason a clean report is worth paying for: what we
checked and did not find, and what we did not check at all.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from preflight.models import CheckStatus, ScanResult, Severity

_TEMPLATES = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(_TEMPLATES),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(result: ScanResult) -> str:
    template = _env.get_template("report.html.j2")
    sections = [
        (severity, result.by_severity(severity))
        for severity in (Severity.FATAL, Severity.SERIOUS, Severity.HYGIENE)
    ]
    return template.render(
        result=result,
        sections=[(sev, items) for sev, items in sections if items],
        passed=[c for c in result.checks if c.status is CheckStatus.PASSED],
        skipped=[c for c in result.checks if c.status is CheckStatus.SKIPPED],
        errored=[c for c in result.checks if c.status is CheckStatus.ERRORED],
    )
