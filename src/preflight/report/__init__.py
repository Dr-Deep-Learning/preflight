"""Report rendering. The report is the product (spec section 7)."""

from preflight.report.html import render_html
from preflight.report.json_report import render_json

__all__ = ["render_html", "render_json"]
