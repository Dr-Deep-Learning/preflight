"""F1 -- database access control, static half.

Spec section 5, Tier 1, and the single most common cause of real breaches in this
population: 88% of audited vibe-coded apps had row-level security entirely off.

The authoritative version of this check queries the live database (ingestion mode
B). This is the static half: read the SQL migrations, build the set of tables the
project creates in the public schema, and subtract the set it enables RLS on. What
is left is exposed to anyone holding the anon key -- which is every visitor,
because the anon key ships in the browser by design.

Two details that matter more than they look:

* **Policies without RLS are inert.** `CREATE POLICY` on a table where RLS was
  never enabled does nothing at all, and it reads to a non-engineer like the
  problem is solved. That case gets a louder note, not a quieter one.
* **Confidence is UNVERIFIED, always.** Migrations describe intent, not state.
  Someone may have enabled RLS by clicking in the dashboard. Reporting this as
  confirmed would be exactly the false positive spec section 11 says to treat as
  the metric that matters, so the finding says "check this" and tells them the
  one-line query that settles it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from preflight.engine import Applicability, ScanContext, register
from preflight.models import (
    Backend,
    BlastRadius,
    Confidence,
    Evidence,
    Finding,
    Remediation,
    Severity,
)

_COMMENTS = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)
_CREATE_TABLE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?P<name>[\w.\"]+)", re.IGNORECASE
)
_DROP_TABLE = re.compile(r"drop\s+table\s+(?:if\s+exists\s+)?(?P<name>[\w.\"]+)", re.IGNORECASE)
_ENABLE_RLS = re.compile(
    r"alter\s+table\s+(?:only\s+)?(?P<name>[\w.\"]+)\s+enable\s+row\s+level\s+security",
    re.IGNORECASE,
)
_CREATE_POLICY = re.compile(
    r"create\s+policy\s+[^\n]*?\s+on\s+(?P<name>[\w.\"]+)", re.IGNORECASE | re.DOTALL
)

#: Schemas Supabase manages itself; their RLS is not the user's to configure.
_MANAGED_SCHEMAS = frozenset({"auth", "storage", "realtime", "vault", "extensions", "graphql"})

#: Table names that strongly imply per-user rows. Decides TOTAL vs BROAD.
_USER_DATA_HINTS = (
    "user",
    "profile",
    "account",
    "message",
    "chat",
    "order",
    "payment",
    "subscription",
    "invoice",
    "session",
    "document",
    "note",
    "post",
    "customer",
    "contact",
    "lead",
    "file",
    "upload",
)


@dataclass(frozen=True)
class _Table:
    name: str
    path: str
    line: int


def _normalise(raw: str) -> tuple[str, str]:
    """Return (schema, table) lowercased, quotes stripped."""
    cleaned = raw.replace('"', "").strip().lower()
    schema, _, table = cleaned.rpartition(".")
    return (schema or "public", table)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _looks_like_user_data(table: str) -> bool:
    return any(hint in table for hint in _USER_DATA_HINTS)


@register
class MissingRowLevelSecurity:
    id: str = "F1"
    title: str = "Database access control (row-level security)"
    severity: Severity = Severity.FATAL
    applicability: Applicability = Applicability(backends=frozenset({Backend.SUPABASE}))
    limits: tuple[str, ...] = (
        "Row-level security is read from SQL migrations only. This scan does not connect to "
        "your database, so RLS enabled by hand in the dashboard is not visible to it.",
        "The contents of policies are not evaluated: a table with a policy of `USING (true)` "
        "is reported as protected.",
    )

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        migrations = self._migration_files(ctx)
        if not migrations:
            return

        created: dict[tuple[str, str], _Table] = {}
        dropped: set[tuple[str, str]] = set()
        rls_enabled: set[tuple[str, str]] = set()
        policied: set[tuple[str, str]] = set()

        for path in migrations:
            sql = _COMMENTS.sub(" ", ctx.read(path))
            for match in _CREATE_TABLE.finditer(sql):
                key = _normalise(match.group("name"))
                if key[0] in _MANAGED_SCHEMAS:
                    continue
                created.setdefault(key, _Table(key[1], path, _line_of(sql, match.start())))
            for match in _DROP_TABLE.finditer(sql):
                dropped.add(_normalise(match.group("name")))
            for match in _ENABLE_RLS.finditer(sql):
                rls_enabled.add(_normalise(match.group("name")))
            for match in _CREATE_POLICY.finditer(sql):
                policied.add(_normalise(match.group("name")))

        unprotected = sorted(
            (
                table
                for key, table in created.items()
                if key not in dropped and key not in rls_enabled
            ),
            key=lambda t: (not _looks_like_user_data(t.name), t.name),
        )
        if not unprotected:
            return

        inert_policies = sorted(t.name for t in unprotected if ("public", t.name) in policied)
        names = [t.name for t in unprotected]
        holds_user_data = [n for n in names if _looks_like_user_data(n)]

        evidence = [
            Evidence(
                path=table.path,
                line=table.line,
                snippet=f"CREATE TABLE {table.name} ...",
                note=(
                    "a policy exists for this table but row-level security is never enabled, "
                    "so the policy has no effect"
                    if table.name in inert_policies
                    else "no ENABLE ROW LEVEL SECURITY for this table in any migration"
                ),
            )
            for table in unprotected
        ]

        yield Finding(
            rule_id=self.id,
            title=(f"{len(names)} table{'s' if len(names) != 1 else ''} may be readable by anyone"),
            severity=Severity.FATAL,
            confidence=Confidence.UNVERIFIED,
            summary=(
                "Your migrations create "
                + ", ".join(f"`{n}`" for n in names[:6])
                + (" and others" if len(names) > 6 else "")
                + " without enabling row-level security. Supabase's anon key is published in your "
                "front-end on purpose; it is safe only while row-level security is on. Without it, "
                "anyone who opens your site can read "
                + (
                    f"the rows in `{holds_user_data[0]}`."
                    if holds_user_data
                    else "these tables in full."
                )
                + (
                    " Policies are defined for "
                    + ", ".join(f"`{n}`" for n in inert_policies)
                    + " but they do nothing until row-level security is enabled."
                    if inert_policies
                    else ""
                )
            ),
            blast_radius=BlastRadius.TOTAL if holds_user_data else BlastRadius.BROAD,
            evidence=evidence,
            remediation=Remediation(
                fix=(
                    "In the Supabase SQL editor, for each table listed:\n\n"
                    + "\n".join(
                        f"ALTER TABLE public.{n} ENABLE ROW LEVEL SECURITY;" for n in names[:10]
                    )
                    + "\n\nEnabling RLS with no policy denies everything, which will break "
                    "your app until you add one. For a table with a per-user `user_id` column "
                    "the usual policy is:\n\n"
                    'CREATE POLICY "owner reads own rows" ON public.<table>\n'
                    "  FOR SELECT TO authenticated USING (auth.uid() = user_id);\n\n"
                    "Add the equivalent INSERT/UPDATE/DELETE policies before you ship."
                ),
                verify=(
                    "Run this in the SQL editor; every row should come back with "
                    "rowsecurity = true:\n\n"
                    "SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';"
                ),
            ),
        )

    @staticmethod
    def _migration_files(ctx: ScanContext) -> tuple[str, ...]:
        preferred = ctx.index.matching("supabase/migrations/*.sql", "migrations/*.sql")
        return tuple(sorted(preferred or ctx.index.with_suffix(".sql")))
