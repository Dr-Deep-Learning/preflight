"""Command line interface.

`preflight scan <dir>` is the whole product this week. The exit code is part of
the interface: non-zero when something at or above the threshold was found, so
the same binary works as a pre-commit hook and a CI gate.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

import preflight.rules  # noqa: F401 - imported to populate the rule registry
from preflight import RULESET_VERSION, __version__
from preflight.engine import REGISTRY, run_scan
from preflight.explain import get_explainer
from preflight.ingest import ScanTargetError
from preflight.models import Severity
from preflight.report import render_html, render_json

app = typer.Typer(add_completion=False, help="Pre-launch security review for AI-built apps.")

_THRESHOLDS = {"fatal": Severity.FATAL, "serious": Severity.SERIOUS, "hygiene": Severity.HYGIENE}


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Directory to scan. Must be one you own.")],
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write the JSON report here.")
    ] = None,
    html_out: Annotated[
        Path | None, typer.Option("--html", help="Write the HTML report here.")
    ] = None,
    explainer: Annotated[str, typer.Option(help="static | anthropic")] = "static",
    fail_on: Annotated[str, typer.Option(help="fatal | serious | hygiene | none")] = "fatal",
) -> None:
    """Scan a local project directory."""
    try:
        chosen = get_explainer(explainer)
    except ValueError as exc:
        # The library raises a library error; translating it into a CLI usage
        # error is this edge's job, not the library's.
        raise typer.BadParameter(str(exc)) from exc

    try:
        result = run_scan(path, explainer=chosen)
    except ScanTargetError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    colour = typer.colors.GREEN if result.verdict.safe_to_launch else typer.colors.RED
    typer.secho(f"\n  {result.verdict.headline}", fg=colour, bold=True)
    typer.echo(f"  {result.verdict.detail}\n")
    typer.echo(
        f"  stack: {result.fingerprint.framework.value} / {result.fingerprint.backend.value}"
        f"   rules run: {len(result.checks)}   findings: {len(result.findings)}\n"
    )
    for finding in result.findings:
        mark = "!" if finding.severity is Severity.FATAL else "-"
        suffix = "" if finding.confidence.value == "confirmed" else "  (unverified)"
        typer.echo(f"  {mark} [{finding.rule_id}] {finding.title}{suffix}")
        for evidence in finding.evidence[:3]:
            where = f"{evidence.path}:{evidence.line}" if evidence.line else evidence.path
            typer.echo(f"      {where}")
    typer.echo("")

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(render_json(result), encoding="utf-8")
        typer.echo(f"  json report: {json_out}")
    if html_out is not None:
        html_out.parent.mkdir(parents=True, exist_ok=True)
        html_out.write_text(render_html(result), encoding="utf-8")
        typer.echo(f"  html report: {html_out}")

    if fail_on != "none":
        threshold = _THRESHOLDS.get(fail_on)
        if threshold is None:
            raise typer.BadParameter(f"unknown severity {fail_on!r}")
        if any(f.severity.rank <= threshold.rank for f in result.findings):
            raise typer.Exit(code=1)


@app.command()
def rules() -> None:
    """List the ruleset. Publishing this openly is the distribution plan (spec section 9)."""
    typer.echo(f"Preflight {__version__}, ruleset {RULESET_VERSION}\n")
    for rule in REGISTRY:
        gate = rule.applicability
        gates = []
        if gate.backends:
            gates.append("backend " + "/".join(sorted(b.value for b in gate.backends)))
        if gate.frameworks:
            gates.append("framework " + "/".join(sorted(f.value for f in gate.frameworks)))
        if gate.payments:
            gates.append("payments " + "/".join(sorted(p.value for p in gate.payments)))
        typer.echo(f"  {rule.id:<4} {rule.severity.value:<8} {rule.title}")
        typer.echo(f"       applies to: {', '.join(gates) if gates else 'every stack'}")
        if rule.catalog_ids:
            typer.echo(f"       catalog:    {', '.join(rule.catalog_ids)}")


@app.command()
def version() -> None:
    """Print versions."""
    typer.echo(f"preflight {__version__} (ruleset {RULESET_VERSION})")


def main() -> None:  # pragma: no cover - console script shim
    sys.exit(app())


if __name__ == "__main__":  # pragma: no cover
    main()
