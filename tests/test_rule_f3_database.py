"""F3: an application database committed to the repository.

Written against real git repositories built in `tmp_path` rather than against a
stub, for the same reason F2's tracked/untracked tests are: whether a file is
committed is the entire basis of the finding, and `git ls-files` is the only
thing that actually answers it.
"""

import sqlite3
import subprocess

import pytest

from conftest import context_for
from preflight.engine import REGISTRY
from preflight.models import BlastRadius, Confidence, Severity
from preflight.rules.f3_committed_database import looks_like_fixture

RULE = REGISTRY.get("F3")


def findings_for(ctx):
    return list(RULE.check(ctx))


def make_db(path, tables):
    """tables: {name: row count}. Values are generated and never asserted on --
    the rule must not read them, so the tests must not depend on them."""
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    for name, rows in tables.items():
        connection.execute(f"CREATE TABLE {name} (id INTEGER PRIMARY KEY, value TEXT)")
        connection.executemany(
            f"INSERT INTO {name} (value) VALUES (?)", [(f"row-{i}",) for i in range(rows)]
        )
    connection.commit()
    connection.close()
    return path


@pytest.fixture
def repo(tmp_path):
    """A git repository with everything in it staged."""

    def build(relpath, tables, *, commit=True):
        (tmp_path / "package.json").write_text('{"dependencies": {"vite": "^5.0.0"}}')
        make_db(tmp_path / relpath, tables)
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        if commit:
            subprocess.run(["git", "add", "-A", "-f"], cwd=tmp_path, check=True)
        return context_for(tmp_path)

    return build


# -- the trigger ---------------------------------------------------------------


def test_one_row_in_an_identity_table_is_the_trigger(repo):
    """Not a threshold. One stranger's row in a public repository is a
    disclosure, and there is no count at which that stops being true."""
    (finding,) = findings_for(repo("prisma/dev.db", {"users": 1}))
    assert finding.severity is Severity.FATAL
    assert finding.confidence is Confidence.CONFIRMED


def test_a_single_user_row_is_not_a_whole_database_exposure(repo):
    """Severity and blast radius answer different questions. One `users` row is
    almost always the author's own test account; TOTAL reads as "every user's
    records" and would be an overstatement, which is how a true finding gets
    dismissed along with everything else in the report."""
    (one,) = findings_for(repo("prisma/dev.db", {"users": 1}))
    assert one.blast_radius is BlastRadius.BROAD
    assert one.severity is Severity.FATAL, "still fatal -- it is a person's record"


def test_more_than_one_person_is_a_whole_database_exposure(repo):
    (finding,) = findings_for(repo("prisma/dev.db", {"users": 2}))
    assert finding.blast_radius is BlastRadius.TOTAL


def test_a_single_row_is_not_described_as_rows(repo):
    """Found by reading a real report: `artists` (1 rows)."""
    (finding,) = findings_for(repo("prisma/dev.db", {"users": 1}))
    assert "(1 row)" in finding.summary
    assert "1 rows" not in finding.summary


def test_row_count_scales_severity_not_the_gate(repo):
    """Many rows and one row are both FATAL; the count is reported, not judged."""
    (finding,) = findings_for(repo("prisma/dev.db", {"users": 500}))
    assert finding.severity is Severity.FATAL
    assert "500 rows" in finding.summary


def test_an_empty_database_is_hygiene_not_an_exposure(repo):
    """Nothing has leaked. But the file will fill up and keep being committed."""
    (finding,) = findings_for(repo("prisma/dev.db", {"users": 0, "sessions": 0}))
    assert finding.severity is Severity.HYGIENE
    assert finding.blast_radius is BlastRadius.CONTAINED
    assert "no rows in it" in finding.summary
    assert "while it is still empty" in finding.summary


def test_rows_in_no_identity_table_are_serious_not_fatal(repo):
    (finding,) = findings_for(repo("data/app.db", {"feature_flags": 12}))
    assert finding.severity is Severity.SERIOUS
    assert finding.blast_radius is BlastRadius.BROAD


def test_an_untracked_database_is_not_reported(repo):
    """The developer already did the right thing; saying nothing is correct."""
    assert findings_for(repo("prisma/dev.db", {"users": 40}, commit=False)) == []


# -- what the rule refuses to do -----------------------------------------------


def test_no_column_value_ever_appears_in_the_finding(repo):
    """The scope line: table names and counts, nothing else. If this test ever
    fails, the rule has started reading user data."""
    ctx = repo("prisma/dev.db", {"users": 3})
    (finding,) = findings_for(ctx)
    rendered = finding.model_dump_json()
    assert "row-0" not in rendered
    assert "row-1" not in rendered


def test_the_finding_says_it_cannot_tell_seed_data_from_real_data(repo):
    (finding,) = findings_for(repo("tests/fixtures/seed.db", {"users": 9}))
    assert "never reads column values" in finding.summary


def test_counts_are_reported_as_evidence(repo):
    (finding,) = findings_for(repo("prisma/dev.db", {"users": 3, "sessions": 2}))
    (evidence,) = finding.evidence
    assert evidence.path == "prisma/dev.db"
    assert "no values read" in (evidence.note or "")
    assert "users=3" in (evidence.note or "")
    assert "sessions=2" in (evidence.note or "")


# -- path context --------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["fixtures/app.db", "db/test.sqlite3", "seeds/data.db", "src/sample_users.db"],
)
def test_sample_data_paths_are_recognised(path):
    assert looks_like_fixture(path)


@pytest.mark.parametrize("path", ["prisma/dev.db", "data/app.db", "db.sqlite3"])
def test_application_database_paths_are_not(path):
    assert not looks_like_fixture(path)


def test_a_fixture_path_is_downgraded_but_never_silenced(repo):
    """`test.db` full of real rows is a mistake people make. Quieter, not gone."""
    (finding,) = findings_for(repo("tests/test.db", {"users": 40}))
    assert finding.severity is Severity.SERIOUS
    assert finding.title.startswith("Database")


def test_a_fixture_path_never_falls_below_hygiene(repo):
    (finding,) = findings_for(repo("fixtures/empty.db", {"users": 0}))
    assert finding.severity is Severity.HYGIENE


# -- format ---------------------------------------------------------------------


def test_a_db_file_that_is_not_sqlite_is_skipped(tmp_path):
    """Some other product's `.db`. Reported by nobody rather than guessed at."""
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "leveldb.db").write_bytes(b"\x00\x01not a sqlite file at all" * 50)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A", "-f"], cwd=tmp_path, check=True)
    assert findings_for(context_for(tmp_path)) == []


def test_the_database_is_not_indexed_as_a_text_file(repo):
    """Decoding a database as UTF-8 produces byte soup that trips the pattern
    rules. `data_paths` exists so that cannot happen."""
    ctx = repo("prisma/dev.db", {"users": 2})
    assert "prisma/dev.db" not in ctx.index.paths
    assert "prisma/dev.db" in ctx.index.data_paths


def test_a_glob_still_reaches_a_database(repo):
    """`matching` is a question about paths, so it spans both lists."""
    ctx = repo("prisma/dev.db", {"users": 2})
    assert ctx.index.matching("**/*.{db,sqlite3}") == ("prisma/dev.db",)


# -- the corpus ------------------------------------------------------------------


def test_the_corpus_database_is_downgraded_by_its_own_path(vulnerable_ctx):
    """`fixtures/vulnerable-app/data/app.db` is a real finding when the app is
    scanned on its own, and sample data when this repository is scanned. Both
    are correct, and the survey run against this repo exercises the second."""
    (finding,) = findings_for(vulnerable_ctx)
    assert finding.severity is Severity.FATAL, "scanned as an app, it is the real thing"
    assert looks_like_fixture("fixtures/vulnerable-app/data/app.db"), (
        "scanned as part of this repository, the same file is sample data"
    )


def test_the_clean_app_commits_no_database(clean_ctx):
    assert findings_for(clean_ctx) == []
