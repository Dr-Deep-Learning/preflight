"""F1: tables created without row-level security."""

from preflight.engine import REGISTRY
from preflight.models import (
    Backend,
    BlastRadius,
    Confidence,
    Fingerprint,
    Framework,
    Severity,
)

RULE = REGISTRY.get("F1")


def findings_for(ctx):
    return list(RULE.check(ctx))


def test_unprotected_tables_are_reported(vulnerable_ctx):
    (finding,) = findings_for(vulnerable_ctx)
    tables = {
        e.snippet.removeprefix("CREATE TABLE ").removesuffix(" ...") for e in finding.evidence
    }
    assert tables == {"profiles", "messages", "subscriptions"}
    assert finding.severity is Severity.FATAL


def test_a_correctly_protected_table_is_not_reported(vulnerable_ctx):
    (finding,) = findings_for(vulnerable_ctx)
    assert "waitlist" not in {e.snippet for e in finding.evidence}
    assert "waitlist" not in finding.summary


def test_a_policy_without_enabled_rls_is_called_out(vulnerable_ctx):
    """CREATE POLICY on a table with RLS off does nothing, and reads like a fix."""
    (finding,) = findings_for(vulnerable_ctx)
    note = next(e.note for e in finding.evidence if "messages" in (e.snippet or ""))
    assert "no effect" in (note or "")
    assert "do nothing until row-level security is enabled" in finding.summary


def test_the_finding_is_unverified_because_migrations_are_intent_not_state(vulnerable_ctx):
    (finding,) = findings_for(vulnerable_ctx)
    assert finding.confidence is Confidence.UNVERIFIED


def test_user_data_tables_raise_the_blast_radius(vulnerable_ctx):
    (finding,) = findings_for(vulnerable_ctx)
    assert finding.blast_radius is BlastRadius.TOTAL


def test_a_correct_project_produces_nothing(clean_ctx):
    assert findings_for(clean_ctx) == []


def test_a_dropped_table_is_not_reported(clean_ctx):
    """clean-app creates and drops a staging table in the same migration set."""
    assert findings_for(clean_ctx) == []


def test_the_rule_is_gated_to_supabase():
    firebase = Fingerprint(framework=Framework.NEXTJS, backend=Backend.FIREBASE)
    supabase = Fingerprint(framework=Framework.NEXTJS, backend=Backend.SUPABASE)
    assert RULE.applicability.skip_reason(firebase) == "not applicable to a firebase backend"
    assert RULE.applicability.matches(supabase)
