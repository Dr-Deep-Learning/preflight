"""F2 -- privileged key exposure.

Spec section 5, Tier 1: "Service-role key, admin SDK credential, or any secret
that bypasses access control present in client bundle, public repo, or `.env`
committed to git. Total compromise regardless of every other control."

Two distinct defects live under this id, and they need separating because their
fixes are different:

* a privileged credential written into source, and
* an environment file that git is tracking, which puts every secret in it into
  history and onto every clone and fork.

The second is where the confirmed/unverified distinction earns its keep. A `.env`
sitting on disk proves nothing -- that is how `.env` is supposed to work. A `.env`
that `git ls-files` reports as tracked is confirmed. When git is unavailable we
say so and downgrade rather than accusing someone on an inference.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath

from preflight.engine import Applicability, ScanContext, register
from preflight.models import Confidence, Evidence, Finding, Remediation, Severity
from preflight.rules._shared import (
    evidence_from,
    is_env_file,
    is_example_env,
    secretish_assignments,
)
from preflight.rules.secrets import SecretKind, iter_secret_matches

_BLAST_RADIUS = {
    "supabase-service-role": 98,
    "private-key-block": 95,
    "postgres-connection-string": 92,
    "aws-access-key-id": 85,
    "stripe-secret-key": 84,
}

_ROTATE_FIRST = (
    "Rotate the credential first. Removing it from the code does not un-leak it -- "
    "assume anyone who has seen the repository has a copy."
)


@register
class PrivilegedSecretExposure:
    id: str = "F2"
    title: str = "Privileged key exposure"
    severity: Severity = Severity.FATAL
    applicability: Applicability = Applicability.anything()
    limits: tuple[str, ...] = (
        "Secrets that were committed and later deleted are not detected: this scan reads "
        "the working tree, not git history.",
        "Secrets held only in a hosting provider's dashboard are out of scope.",
    )

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        yield from self._committed_env_files(ctx)
        yield from self._privileged_credentials_in_source(ctx)

    # -- .env tracked by git -------------------------------------------------

    def _committed_env_files(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.index.paths:
            name = PurePosixPath(path).name
            if not is_env_file(name) or is_example_env(name):
                continue

            tracked = ctx.git.is_tracked(path)
            if tracked is False:
                continue

            text = ctx.read(path)
            matches = list(iter_secret_matches(text))
            evidence: list[Evidence] = [evidence_from(m, path) for m in matches]
            if not evidence:
                # No value matched a known credential shape. Fall back to variable
                # names, minus the ones that are public on purpose -- a committed
                # file of NEXT_PUBLIC_ publishable keys is not a leak, and saying it
                # is would be the false positive that makes the report unreadable.
                named = secretish_assignments(text)
                if not named:
                    continue
                evidence = [
                    Evidence(
                        path=path,
                        line=number,
                        snippet=f"{name}=...",
                        note="the name says credential; the value did not match a known shape",
                    )
                    for number, name, _line in named
                ]

            confirmed = tracked is True
            yield Finding(
                rule_id=self.id,
                title=(
                    "Environment file committed to git"
                    if confirmed
                    else "Environment file may be committed to git"
                ),
                severity=Severity.FATAL,
                confidence=Confidence.CONFIRMED if confirmed else Confidence.UNVERIFIED,
                summary=(
                    f"`{path}` is tracked by git, so every secret in it is in your repository's "
                    "history and in every clone and fork of it."
                    if confirmed
                    else f"`{path}` exists and this project is not a git repository we could read, "
                    "so we could not tell whether it has been committed. Check manually."
                ),
                blast_radius=90 if confirmed else 60,
                evidence=evidence,
                remediation=Remediation(
                    fix=(
                        f"{_ROTATE_FIRST}\n"
                        f"1. Rotate every key in `{path}`.\n"
                        f"2. `git rm --cached {path}` and add `{path}` to `.gitignore`.\n"
                        "3. Move the values into your hosting provider's environment settings "
                        "(Vercel, Netlify, Fly, Render all have this under project settings).\n"
                        "4. Purge history with `git filter-repo --path "
                        f"{path} --invert-paths` if the repository is public."
                    ),
                    verify=(
                        f"`git ls-files --error-unmatch {path}` should fail with "
                        '"did not match any file(s) known to git".'
                    ),
                ),
            )

    # -- privileged credentials written into source --------------------------

    def _privileged_credentials_in_source(self, ctx: ScanContext) -> Iterable[Finding]:
        by_pattern: dict[str, list[Evidence]] = {}
        labels: dict[str, str] = {}
        consequences: dict[str, str] = {}

        for path in ctx.index.paths:
            name = PurePosixPath(path).name
            if is_env_file(name):
                continue  # handled above; reporting twice is noise
            text = ctx.read(path)
            if not text:
                continue
            for match in iter_secret_matches(text, kinds=frozenset({SecretKind.PRIVILEGED})):
                key = match.pattern.id
                by_pattern.setdefault(key, []).append(evidence_from(match, path))
                labels[key] = match.pattern.label
                consequences[key] = match.pattern.consequence

        for pattern_id, evidence in sorted(by_pattern.items()):
            label = labels[pattern_id]
            yield Finding(
                rule_id=self.id,
                title=f"{label} is hardcoded in your source",
                severity=Severity.FATAL,
                confidence=Confidence.CONFIRMED,
                summary=(
                    f"A {label.lower()} appears in {len(evidence)} "
                    f"file location{'s' if len(evidence) != 1 else ''}. {consequences[pattern_id]}"
                ),
                blast_radius=_BLAST_RADIUS.get(pattern_id, 80),
                evidence=evidence,
                remediation=Remediation(
                    fix=(
                        f"{_ROTATE_FIRST}\n"
                        f"1. Rotate the {label.lower()} in the provider's dashboard.\n"
                        "2. Read it from a server-side environment variable instead of a literal, "
                        "and only from code that runs on the server.\n"
                        "3. If this value was ever needed in the browser, that is the bug: use the "
                        "public/anon key there and put the privileged call behind an endpoint "
                        "you own."
                    ),
                    verify=(
                        "Search the repository for the key prefix and confirm zero results, then "
                        "confirm the old key is revoked in the provider dashboard."
                    ),
                ),
            )
