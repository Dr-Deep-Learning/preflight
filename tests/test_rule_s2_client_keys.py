"""S2: third-party keys reachable from the browser."""

from preflight.engine import REGISTRY
from preflight.models import Confidence, Severity

RULE = REGISTRY.get("S2")


def findings_for(ctx):
    return list(RULE.check(ctx))


def by_title(findings, needle):
    return [f for f in findings if needle in f.title]


def test_key_literal_in_bundled_code_is_reported(vulnerable_ctx):
    (finding,) = by_title(findings_for(vulnerable_ctx), "ships to the browser")
    assert finding.severity is Severity.SERIOUS
    assert finding.confidence is Confidence.CONFIRMED
    assert {e.path for e in finding.evidence} == {"src/components/Chat.tsx"}


def test_public_prefixed_secret_is_reported(vulnerable_ctx):
    (finding,) = by_title(findings_for(vulnerable_ctx), "public environment prefix")
    (evidence,) = finding.evidence
    assert evidence.path == ".env"
    assert "VITE_OPENAI_API_KEY" in evidence.snippet
    assert "inline" in (evidence.note or "")


def test_the_key_value_is_redacted_in_the_env_finding(vulnerable_ctx):
    (finding,) = by_title(findings_for(vulnerable_ctx), "public environment prefix")
    assert "FIXTUREkeyDoNotUse" not in finding.evidence[0].snippet


def test_server_only_files_are_not_reported(vulnerable_ctx):
    paths = {e.path for f in findings_for(vulnerable_ctx) for e in f.evidence}
    assert "api/webhook.js" not in paths


def test_publishable_public_variables_are_allowlisted(clean_ctx):
    """NEXT_PUBLIC_SUPABASE_ANON_KEY ends in _KEY and is completely fine."""
    assert findings_for(clean_ctx) == []


def test_anon_key_hardcoded_in_a_component_is_not_reported(clean_ctx):
    assert findings_for(clean_ctx) == []
