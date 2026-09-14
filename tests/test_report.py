"""The report is the product (spec section 7), so its structure is asserted."""

import json

from conftest import SERVICE_ROLE_JWT
from preflight.explain import StaticExplainer
from preflight.models import ScanResult
from preflight.report import render_html, render_json


def test_json_round_trips(vulnerable_scan):
    restored = ScanResult.model_validate(json.loads(render_json(vulnerable_scan)))
    assert restored.verdict.headline == vulnerable_scan.verdict.headline
    assert len(restored.findings) == len(vulnerable_scan.findings)


def test_html_leads_with_the_verdict(vulnerable_scan):
    html = render_html(vulnerable_scan)
    assert "Not safe to launch" in html
    assert html.index("Not safe to launch") < html.index("Fix these now")


def test_html_lists_what_was_checked_and_what_was_not(clean_scan):
    html = render_html(clean_scan)
    assert "What we checked and did not find" in html
    assert "What we did not check" in html
    assert "does not connect to your database" in html


def test_a_clean_report_never_claims_the_app_is_secure(clean_scan):
    """Spec section 12 calls a false all-clear existential. The wording is a test."""
    html = render_html(clean_scan)
    assert "does not mean your application is secure" in html


def test_unverified_findings_are_labelled_in_the_report(vulnerable_scan):
    assert "unverified — check this manually" in render_html(vulnerable_scan)


def test_no_credential_survives_into_the_html(vulnerable_scan):
    html = render_html(vulnerable_scan)
    assert SERVICE_ROLE_JWT not in html
    assert "sk-preflightFIXTUREkeyDoNotUse7f3a91c4b8e2d6" not in html
    assert "preflightFixturePw9312" not in html


def test_explanations_replace_the_static_text_when_present(vulnerable_scan):
    from preflight.engine import replace_explanation

    explained = vulnerable_scan.model_copy(
        update={
            "findings": [
                replace_explanation(f, StaticExplainer().explain(f, vulnerable_scan.fingerprint))
                for f in vulnerable_scan.findings
            ]
        }
    )
    assert "What someone could do with this" in render_html(explained)
