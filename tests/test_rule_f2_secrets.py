"""F2: privileged credentials in source, and environment files under git."""

import subprocess

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


# -- placeholder .env files ------------------------------------------------
#
# These four tests exist because of a real false positive. Surveying public
# AI-built repositories, the only "confirmed FATAL" the scanner produced in the
# whole sample was a committed `.env` whose every value read `your-<name>-here`.
# The name-only fallback path had no test coverage at all, which is how a rule
# that already knew what a placeholder looks like managed to report one anyway.

PLACEHOLDER_ENV = """\
# Authentication
BETTER_AUTH_SECRET=your-super-secret-key-change-this
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_SECRET=your-github-client-secret
CLOUDINARY_API_KEY=your-cloudinary-api-key
CLOUDINARY_API_SECRET=your-cloudinary-api-secret
"""


def _committed(tmp_path, env_text):
    (tmp_path / "package.json").write_text('{"dependencies": {"vite": "^5.0.0"}}')
    (tmp_path / ".env").write_text(env_text)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A", "-f"], cwd=tmp_path, check=True)
    return context_for(tmp_path)


def test_a_committed_env_of_placeholders_is_not_a_finding(tmp_path):
    """Verbatim from NassimEH/WeListenMusic@cf0df1b9, the false positive itself."""
    assert findings_for(_committed(tmp_path, PLACEHOLDER_ENV)) == []


def test_one_real_value_among_placeholders_still_reports(tmp_path):
    """Suppressing placeholders must not suppress the file they are sitting in."""
    env = PLACEHOLDER_ENV + f"SUPABASE_SERVICE_ROLE_KEY={SERVICE_ROLE_JWT}\n"
    (finding,) = by_title(findings_for(_committed(tmp_path, env)), "Environment file")
    assert finding.confidence is Confidence.CONFIRMED
    assert [e.line for e in finding.evidence] == [7]


def test_a_credential_shaped_name_with_an_unrecognised_value_is_unverified(tmp_path):
    """The file is committed -- a fact. That it holds a live key is a guess."""
    env = "ACME_API_KEY=k83nfj20dkeo1p\n"
    (finding,) = by_title(findings_for(_committed(tmp_path, env)), "Environment file")
    assert finding.confidence is Confidence.UNVERIFIED
    assert "committed to git" in finding.title
    assert "None of the values look like a real key" in finding.summary


def test_the_placeholder_rule_is_the_one_documented_in_limits():
    assert any("placeholder" in limit for limit in RULE.limits)


def test_example_env_files_are_ignored(vulnerable_ctx):
    paths = {e.path for f in findings_for(vulnerable_ctx) for e in f.evidence}
    assert ".env.example" not in paths


def test_a_committed_env_of_publishable_keys_is_not_a_finding(clean_ctx):
    """clean-app commits .env.local with three NEXT_PUBLIC_ values. That is fine."""
    assert findings_for(clean_ctx) == []


def test_server_side_env_reads_are_not_findings(clean_ctx):
    """`process.env.SUPABASE_SERVICE_ROLE_KEY` is the correct pattern, not a leak."""
    assert findings_for(clean_ctx) == []
