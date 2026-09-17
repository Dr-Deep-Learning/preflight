"""CLI, including the exit codes that make it usable as a CI gate."""

import json

from typer.testing import CliRunner

from conftest import CLEAN, VULNERABLE
from preflight.cli import app

runner = CliRunner()


def test_scan_of_a_broken_app_exits_nonzero():
    result = runner.invoke(app, ["scan", str(VULNERABLE)])
    assert result.exit_code == 1
    assert "Not safe to launch" in result.stdout


def test_scan_of_a_clean_app_exits_zero():
    result = runner.invoke(app, ["scan", str(CLEAN)])
    assert result.exit_code == 0
    assert "Clean" in result.stdout


def test_fail_on_none_always_exits_zero():
    result = runner.invoke(app, ["scan", str(VULNERABLE), "--fail-on", "none"])
    assert result.exit_code == 0


def test_reports_are_written(tmp_path):
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    runner.invoke(
        app, ["scan", str(VULNERABLE), "--json", str(json_path), "--html", str(html_path)]
    )
    assert json.loads(json_path.read_text())["findings"]
    assert "Preflight report" in html_path.read_text()


def test_missing_directory_exits_two(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path / "nope")])
    assert result.exit_code == 2


def test_rules_command_lists_the_ruleset():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    for rule_id in ("F1", "F2", "S1", "S2"):
        assert rule_id in result.stdout
