"""F3 -- an application database committed to the repository.

Found by surveying real repositories, not by planning: a Lovable app in the
Tier 2 sample commits `prisma/dev.db`. Every rule written before this one looks
for a *credential*, which can be rotated. A committed database is the other
kind of exposure. The rows are already copied into every clone and fork, there
is nothing to rotate, and deleting the file changes nothing about the copies.

Three design decisions, all of them consequences of one rule:

**The contents are never read.** Table names and `COUNT(*)`, nothing else. No
column values, not one. That is the line drawn in the project's scope
statement, and it is the reason this check cannot distinguish seeded demo rows
from real ones -- the signal that would separate them (do the addresses all end
in `@example.com`?) lives in the values. So the rule does not try. It uses
where the file sits instead, which is public information about the repository.

**One row is the trigger, not a threshold.** A non-empty identity table is the
finding. There is no count at which a stranger's email address stops being a
disclosure, and no count at which seeded data becomes real, so a threshold
would be a number chosen to feel reasonable and defend nothing. The count sets
severity and blast radius; it does not open the gate.

**Path decides tone, and only downwards.** A database under `fixtures/` or
named `*sample*` is downgraded. It is never upgraded, and a downgrade never
suppresses the finding entirely: `test.db` full of real rows is a mistake
people make, and the report should still say the file is in the repository.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from preflight.engine import Applicability, ScanContext, register
from preflight.models import (
    BlastRadius,
    Confidence,
    Evidence,
    Finding,
    Remediation,
    Severity,
)

#: Every SQLite file on disk begins with these bytes. A `.db` that does not is
#: some other product's format and out of scope -- reported by nobody rather
#: than guessed at.
_SQLITE_MAGIC = b"SQLite format 3\x00"

#: Tables whose rows are about *a person*. A non-empty one of these is the
#: difference between an exposure and an untidy repository.
_IDENTITY_TABLES = (
    "user",
    "account",
    "session",
    "customer",
    "profile",
    "member",
    "subscriber",
    "credential",
    "password",
    "token",
    "auth",
    "order",
    "payment",
    "invoice",
    "message",
    "contact",
    "lead",
    "email",
)

#: Directory and filename markers that say "this is sample data". Evidence from
#: the path only; the file is still reported, one level quieter.
_FIXTURE_DIRS = frozenset(
    {
        "fixtures",
        "fixture",
        "seed",
        "seeds",
        "test",
        "tests",
        "__tests__",
        "testdata",
        "example",
        "examples",
        "demo",
        "demos",
        "sample",
        "samples",
        "mock",
        "mocks",
    }
)
_FIXTURE_NAME_MARKERS = ("test", "sample", "demo", "fixture", "mock", "seed", "example")

#: SQLite's own bookkeeping, plus the tables its extensions create.
_INTERNAL_PREFIXES = ("sqlite_", "_litestream", "_prisma_")


@dataclass(frozen=True)
class _Database:
    path: str
    size: int
    tables: tuple[tuple[str, int], ...]  # (name, row count) -- counts only
    unreadable: str | None = None

    @property
    def populated(self) -> tuple[tuple[str, int], ...]:
        return tuple((name, rows) for name, rows in self.tables if rows > 0)

    @property
    def identity(self) -> tuple[tuple[str, int], ...]:
        return tuple((n, r) for n, r in self.populated if _is_identity_table(n))

    @property
    def rows(self) -> int:
        return sum(rows for _, rows in self.tables)


def _is_identity_table(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _IDENTITY_TABLES)


def looks_like_fixture(relpath: str) -> bool:
    """True when the *path* says sample data. The contents are not consulted.

    >>> looks_like_fixture("fixtures/vulnerable-app/data/app.db")
    True
    >>> looks_like_fixture("db/test.sqlite3")
    True
    >>> looks_like_fixture("prisma/dev.db")
    False
    """
    parts = PurePosixPath(relpath).parts
    if any(part.lower() in _FIXTURE_DIRS for part in parts[:-1]):
        return True
    stem = PurePosixPath(relpath).stem.lower()
    return any(marker in stem for marker in _FIXTURE_NAME_MARKERS)


def _is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(16) == _SQLITE_MAGIC
    except OSError:
        return False


def inspect(path: Path) -> tuple[tuple[str, int], ...] | str:
    """Table names and row counts, or a string explaining why neither is known.

    Opened read-only and immutable, so the scan cannot modify, lock, or
    journal the user's file. `COUNT(*)` is the only query issued against a
    user table; no column is ever selected.
    """
    uri = f"file:{path.as_uri()[len('file:') :]}?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5)
    except sqlite3.Error as exc:  # pragma: no cover - platform dependent
        return f"could not be opened ({exc.__class__.__name__})"
    try:
        connection.execute("PRAGMA query_only = ON")
        names = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
            if not row[0].lower().startswith(_INTERNAL_PREFIXES)
        ]
        counted: list[tuple[str, int]] = []
        for name in names:
            # The table name is an identifier from the file itself, so it is
            # quoted rather than interpolated bare; parameters cannot carry an
            # identifier in SQL.
            quoted = '"' + name.replace('"', '""') + '"'
            counted.append(
                (name, connection.execute(f"SELECT count(*) FROM {quoted}").fetchone()[0])
            )
    except sqlite3.DatabaseError as exc:
        return f"is not readable as a database ({exc.__class__.__name__})"
    finally:
        connection.close()
    return tuple(counted)


@register
class CommittedDatabase:
    id: str = "F3"
    title: str = "Application database in the repository"
    severity: Severity = Severity.FATAL
    applicability: Applicability = Applicability.anything()
    catalog_ids: tuple[str, ...] = ("SEC-004",)
    limits: tuple[str, ...] = (
        "Only SQLite databases are inspected. A committed Postgres dump, MongoDB "
        "export, or `.db` file in another product's format is not detected.",
        "Table names and row counts are read; no column value is ever read. Seeded "
        "demo data and real user data are therefore indistinguishable to this "
        "check, and it says so in the finding rather than guessing.",
        "A database deleted in a later commit is still in git history, and this "
        "scan reads the working tree only.",
    )

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.index.data_paths:
            if ctx.git.is_tracked(path) is False:
                continue
            database = self._load(ctx, path)
            if database is None:
                continue
            yield self._finding(ctx, database)

    # -- reading -------------------------------------------------------------

    @staticmethod
    def _load(ctx: ScanContext, path: str) -> _Database | None:
        absolute = ctx.root / path
        if not _is_sqlite(absolute):
            return None
        size = ctx.index.size_of(path)
        from preflight.ingest import MAX_DATA_FILE_BYTES

        if size > MAX_DATA_FILE_BYTES:
            return _Database(path=path, size=size, tables=(), unreadable="is too large to open")
        read = inspect(absolute)
        if isinstance(read, str):
            return _Database(path=path, size=size, tables=(), unreadable=read)
        return _Database(path=path, size=size, tables=read)

    # -- reporting -----------------------------------------------------------

    def _finding(self, ctx: ScanContext, db: _Database) -> Finding:
        fixture = looks_like_fixture(db.path)
        tracked = ctx.git.is_tracked(db.path)
        severity, radius = self._weigh(db, fixture=fixture)

        return Finding(
            rule_id=self.id,
            title=self._title(db, fixture=fixture),
            severity=severity,
            # Whether the file is in the repository is a fact git answers.
            # Whether the rows are real is a question this rule refuses to ask.
            confidence=Confidence.CONFIRMED if tracked is True else Confidence.UNVERIFIED,
            summary=self._summary(db, fixture=fixture, tracked=tracked),
            blast_radius=radius,
            evidence=[
                Evidence(
                    path=db.path,
                    snippet=f"SQLite database, {_human_size(db.size)}",
                    note=self._contents_note(db),
                )
            ],
            remediation=Remediation(
                fix=(
                    "A committed database cannot be rotated the way a key can -- "
                    "assume every row is already copied.\n\n"
                    f"1. `git rm --cached {db.path}` and add it to `.gitignore`:\n"
                    "   *.db\n   *.sqlite3\n"
                    "2. Purge it from history if the repository is public:\n"
                    f"   git filter-repo --path {db.path} --invert-paths\n"
                    "3. If the rows are real, treat this as a data breach: invalidate "
                    "every session, force a password reset, and check whether your "
                    "jurisdiction requires you to notify the people in the table.\n"
                    "4. Move development data outside the project directory, or point "
                    "your dev database at a throwaway instance."
                ),
                verify=(
                    f"`git ls-files --error-unmatch {db.path}` should fail with "
                    '"did not match any file(s) known to git".'
                ),
            ),
        )

    @staticmethod
    def _weigh(db: _Database, *, fixture: bool) -> tuple[Severity, BlastRadius]:
        if db.identity:
            # Any row about a person is FATAL -- that is the trigger, and it has
            # no threshold. Blast radius is a different question: it says how
            # many people this reaches, and TOTAL reads as "every user's
            # records". A database whose `users` table holds one row is almost
            # always the author's own test account, and calling that a
            # whole-database exposure is the kind of overstatement that gets a
            # report dismissed along with the true findings in it.
            people = max(rows for _, rows in db.identity)
            severity = Severity.FATAL
            radius = BlastRadius.TOTAL if people > 1 else BlastRadius.BROAD
        elif db.populated:
            severity, radius = Severity.SERIOUS, BlastRadius.BROAD
        else:
            severity, radius = Severity.HYGIENE, BlastRadius.CONTAINED
        if fixture:
            # One level quieter, never silent, and never below hygiene.
            downgraded = {Severity.FATAL: Severity.SERIOUS, Severity.SERIOUS: Severity.HYGIENE}
            severity = downgraded.get(severity, Severity.HYGIENE)
            radius = BlastRadius.CONTAINED if radius is BlastRadius.CONTAINED else BlastRadius.BROAD
        return severity, radius

    @staticmethod
    def _title(db: _Database, *, fixture: bool) -> str:
        name = PurePosixPath(db.path).name
        if db.unreadable is not None:
            return f"Database file `{name}` is in your repository"
        if not db.populated:
            return f"Empty database `{name}` is in your repository"
        if fixture:
            return f"Database `{name}` with data is in your repository"
        if db.identity:
            return f"Your application database `{name}` is published in this repository"
        return f"Database `{name}` with data is in your repository"

    @staticmethod
    def _summary(db: _Database, *, fixture: bool, tracked: bool | None) -> str:
        whereabouts = (
            f"`{db.path}` is tracked by git"
            if tracked is True
            else f"`{db.path}` is in the project and we could not read git to tell "
            "whether it has been committed"
        )
        if db.unreadable is not None:
            return (
                f"{whereabouts}, and it {db.unreadable}. If it holds application data, "
                "everyone who can clone this repository has a copy of it."
            )
        if not db.populated:
            return (
                f"{whereabouts}. It has no rows in it, so nothing has leaked -- but the "
                "file will collect data as you use the app and will keep being "
                "committed. Add it to `.gitignore` now, while it is still empty."
            )

        summary = (
            f"{whereabouts}, so every row in it is in each clone and fork of this "
            "repository. It holds "
            + ", ".join(
                f"`{name}` ({rows} row{'' if rows == 1 else 's'})"
                for name, rows in db.populated[:5]
            )
            + (" and other tables" if len(db.populated) > 5 else "")
            + ". "
        )
        if db.identity:
            first = db.identity[0][0]
            summary += (
                f"`{first}` names data about people. Unlike a leaked key, this cannot be "
                "rotated: anyone who cloned the repository already has the rows."
            )
        else:
            summary += "None of the table names suggest personal data, but check them yourself."
        if fixture:
            summary += (
                " The path suggests this is sample data. This check never reads column "
                "values, so it cannot confirm that -- you can, in one look."
            )
        return summary

    @staticmethod
    def _contents_note(db: _Database) -> str:
        if db.unreadable is not None:
            return f"file {db.unreadable}"
        if not db.tables:
            return "no tables"
        listed = ", ".join(f"{name}={rows}" for name, rows in db.tables[:8])
        return f"row counts only, no values read: {listed}"


def _human_size(size: int) -> str:
    """
    >>> _human_size(900)
    '900 bytes'
    >>> _human_size(45_000)
    '43 KB'
    """
    if size < 1024:
        return f"{size} bytes"
    if size < 1024 * 1024:
        return f"{size // 1024} KB"
    return f"{size / (1024 * 1024):.1f} MB"
