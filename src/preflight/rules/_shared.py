"""Helpers shared by rules.

Two things live here because both F2 and S2 need them and disagreeing about them
would produce contradictory findings on the same file:

* what counts as an environment file that is *supposed* to hold fake values, and
* which public-prefixed variables are public on purpose.

The second is the allowlist that keeps the false-positive rate near zero.
`NEXT_PUBLIC_SUPABASE_ANON_KEY` ends in `_KEY`, is committed by every Supabase
tutorial, and is completely fine. A scanner that reports it is a scanner nobody
finishes reading.
"""

from __future__ import annotations

import re

from preflight.models import Evidence
from preflight.redact import redact_in_line
from preflight.rules.secrets import SecretMatch, looks_like_placeholder

EXAMPLE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist")

#: Public-prefixed variables that are published by design.
KNOWN_SAFE_PUBLIC = frozenset(
    {
        "NEXT_PUBLIC_SUPABASE_ANON_KEY",
        "VITE_SUPABASE_ANON_KEY",
        "PUBLIC_SUPABASE_ANON_KEY",
        "EXPO_PUBLIC_SUPABASE_ANON_KEY",
        "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY",
        "VITE_STRIPE_PUBLISHABLE_KEY",
        "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
        "NEXT_PUBLIC_FIREBASE_API_KEY",
        "VITE_FIREBASE_API_KEY",
        "NEXT_PUBLIC_POSTHOG_KEY",
        "NEXT_PUBLIC_SENTRY_DSN",
    }
)

PUBLIC_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_", "EXPO_PUBLIC_")

#: A variable whose *name* claims to hold a credential.
SECRETISH_NAME = re.compile(
    r"^(?P<name>[A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|SERVICE_ROLE|_KEY)"
    r"[A-Z0-9_]*)\s*=\s*(?P<value>\S.*)$"
)

PUBLIC_SENSITIVE_NAME = re.compile(
    r"^(?P<prefix>NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_)"
    r"(?P<name>[A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|SERVICE_ROLE)[A-Z0-9_]*)"
    r"\s*=\s*(?P<value>\S.*)$"
)


def is_example_env(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered.endswith(EXAMPLE_ENV_SUFFIXES)
        or "example" in lowered
        or "sample" in lowered
        or "template" in lowered
    )


def is_env_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env")


def secretish_assignments(text: str) -> list[tuple[int, str, str]]:
    """Lines that name a credential and are not a known-public variable.

    Returns (line number, variable name, raw line).
    """
    found: list[tuple[int, str, str]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = SECRETISH_NAME.match(line)
        if match is None:
            continue
        name = match.group("name")
        if name in KNOWN_SAFE_PUBLIC:
            continue
        value = match.group("value").strip().strip("\"'")
        if not value:
            continue
        if looks_like_placeholder(value):
            # `GOOGLE_CLIENT_SECRET=your-google-client-secret` names a credential
            # and holds nothing. Surveying real repositories, this was every value
            # in the only .env the scanner flagged -- see docs/PLAN.md.
            continue
        found.append((number, name, line))
    return found


def evidence_from(match: SecretMatch, path: str, note: str | None = None) -> Evidence:
    """Build redacted evidence. The raw credential never leaves this function."""
    return Evidence(
        path=path,
        line=match.line_number,
        snippet=redact_in_line(match.line, match.value),
        note=note,
    )
