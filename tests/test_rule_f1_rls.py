"""F1: tables created without row-level security."""

from conftest import context_for
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


# --- one repository, several databases ---------------------------------------


def write(root, relative, text):
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


PROTECTED = """
create table profiles (id uuid primary key, email text);
alter table profiles enable row level security;
"""

UNPROTECTED = "create table profiles (id uuid primary key, email text);\n"


def test_two_apps_in_one_repo_do_not_mask_each_other(tmp_path):
    """The monorepo false negative, found by running the scanner on its own repo.

    Pooling every `.sql` file under the scan root into one schema let the
    protected `profiles` in one app vouch for the unprotected `profiles` in
    another -- and the defect disappeared from the report entirely.
    """
    write(tmp_path, "apps/clean/supabase/migrations/0001_init.sql", PROTECTED)
    write(tmp_path, "apps/broken/supabase/migrations/0001_init.sql", UNPROTECTED)

    (finding,) = findings_for(context_for(tmp_path))
    assert {e.path for e in finding.evidence} == {"apps/broken/supabase/migrations/0001_init.sql"}


def test_each_unprotected_app_gets_its_own_finding(tmp_path):
    write(tmp_path, "apps/one/supabase/migrations/0001_init.sql", UNPROTECTED)
    write(tmp_path, "apps/two/supabase/migrations/0001_init.sql", UNPROTECTED)

    findings = findings_for(context_for(tmp_path))
    assert len(findings) == 2
    assert {f.title for f in findings} == {
        "1 table may be readable by anyone in apps/one",
        "1 table may be readable by anyone in apps/two",
    }


def test_a_single_app_is_not_labelled_with_its_directory(vulnerable_ctx):
    """The name only appears when there is something to disambiguate."""
    (finding,) = findings_for(vulnerable_ctx)
    assert finding.title == "3 tables may be readable by anyone"
    assert finding.summary.startswith("Your migrations create")


def test_rls_enabled_in_a_later_migration_of_the_same_app_still_counts(tmp_path):
    """Grouping must not become per-file: protection legitimately arrives later."""
    write(tmp_path, "supabase/migrations/0001_init.sql", UNPROTECTED)
    write(
        tmp_path,
        "supabase/migrations/0002_rls.sql",
        "alter table profiles enable row level security;\n",
    )
    assert findings_for(context_for(tmp_path)) == []


def test_nested_migrations_are_found_at_any_depth(tmp_path):
    """The preferred glob used to be anchored to the repository root, so a
    nested app fell through to "every .sql file in the tree"."""
    write(tmp_path, "packages/api/supabase/migrations/0001_init.sql", UNPROTECTED)
    write(tmp_path, "docs/notes.sql", "select 1;\n")

    (finding,) = findings_for(context_for(tmp_path))
    assert {e.path for e in finding.evidence} == {"packages/api/supabase/migrations/0001_init.sql"}


def test_the_monorepo_blind_spot_is_declared():
    assert any("several applications" in limit for limit in RULE.limits)


def test_the_rule_is_gated_to_supabase():
    firebase = Fingerprint(framework=Framework.NEXTJS, backend=Backend.FIREBASE)
    supabase = Fingerprint(framework=Framework.NEXTJS, backend=Backend.SUPABASE)
    assert RULE.applicability.skip_reason(firebase) == "not applicable to a firebase backend"
    assert RULE.applicability.matches(supabase)
