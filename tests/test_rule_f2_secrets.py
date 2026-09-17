"""F2: privileged credentials in source, and environment files under git."""

from conftest import SERVICE_ROLE_JWT, context_for
from preflight.engine import REGISTRY
from preflight.models import BlastRadius, Confidence, Severity

RULE = REGISTRY.get("F2")


def findings_for(ctx):
    return list(RULE.check(ctx))


def by_title(findings, needle):
    return [f for f in findings if needle in f.title]


def test_service_role_key_in_client_code_is_a_confirmed_fatal(vulnerable_ctx):
    (finding,) = by_title(findings_for(vulnerable_ctx), "Supabase service-role key is hardcoded")
    assert finding.severity is Severity.FATAL
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.blast_radius is BlastRadius.TOTAL
    assert {e.path for e in finding.evidence} == {"src/lib/supabaseClient.ts"}


def test_evidence_never_contains_the_credential(vulnerable_ctx):
    for finding in findings_for(vulnerable_ctx):
        for evidence in finding.evidence:
            assert SERVICE_ROLE_JWT not in evidence.snippet


def test_the_env_finding_enumerates_every_credential_in_the_file(vulnerable_ctx):
    """One finding per file, evidence per credential -- a line-by-line report of a
    .env would bury the one thing the reader has to act on."""
    (finding,) = by_title(findings_for(vulnerable_ctx), "Environment file")
    lines = " ".join(e.snippet for e in finding.evidence)
    assert "SUPABASE_SERVICE_ROLE_KEY" in lines
    assert "DATABASE_URL" in lines
    assert "VITE_OPENAI_API_KEY" in lines
    assert all(e.path == ".env" for e in finding.evidence)


def test_the_anon_key_line_in_the_same_file_is_not_evidence(vulnerable_ctx):
    (finding,) = by_title(findings_for(vulnerable_ctx), "Environment file")
    assert "VITE_SUPABASE_ANON_KEY" not in " ".join(e.snippet for e in finding.evidence)


def test_the_corpus_env_file_is_reported(vulnerable_ctx):
    (finding,) = by_title(findings_for(vulnerable_ctx), "Environment file")
    assert {e.path for e in finding.evidence} == {".env"}


def test_env_file_outside_a_git_repository_is_unverified(tmp_path):
    """Without git we cannot tell whether the file was committed, and saying it was
    would be an accusation built on an inference."""
    (tmp_path / "package.json").write_text('{"dependencies": {"vite": "^5.0.0"}}')
    (tmp_path / ".env").write_text(f"SUPABASE_SERVICE_ROLE_KEY={SERVICE_ROLE_JWT}\n")
    (finding,) = by_title(findings_for(context_for(tmp_path)), "Environment file")
    assert finding.confidence is Confidence.UNVERIFIED
    assert "check manually" in finding.summary.lower()
    assert finding.blast_radius is BlastRadius.BROAD


def test_env_file_tracked_by_git_is_confirmed(git_project):
    (finding,) = by_title(findings_for(context_for(git_project)), "Environment file")
    assert finding.confidence is Confidence.CONFIRMED
    assert "committed to git" in finding.title
    assert "git rm --cached" in finding.remediation.fix


def test_example_env_files_are_ignored(vulnerable_ctx):
    paths = {e.path for f in findings_for(vulnerable_ctx) for e in f.evidence}
    assert ".env.example" not in paths


def test_a_committed_env_of_publishable_keys_is_not_a_finding(clean_ctx):
    """clean-app commits .env.local with three NEXT_PUBLIC_ values. That is fine."""
    assert findings_for(clean_ctx) == []


def test_server_side_env_reads_are_not_findings(clean_ctx):
    """`process.env.SUPABASE_SERVICE_ROLE_KEY` is the correct pattern, not a leak."""
    assert findings_for(clean_ctx) == []
