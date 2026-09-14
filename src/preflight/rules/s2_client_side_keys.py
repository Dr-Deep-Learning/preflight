"""S2 -- third-party API key exposure in client code.

Spec section 5, Tier 2: "LLM provider, email, SMS, or maps keys in client code --
the 'surprise $40k bill' class."

The interesting part of this rule is not the regexes, it is the definition of
"client code". Two things put a value in the browser bundle:

1. a literal in a file that the bundler ships, and
2. an environment variable named with the framework's public prefix, because the
   bundler substitutes those at build time whether or not the developer realises it.

The second is invisible in a diff and is why `VITE_OPENAI_API_KEY` is one of the
most common findings in this population. Both are confirmed findings: no runtime
observation is needed, the build tool's documented behaviour is the proof.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath

from preflight.engine import Applicability, ScanContext, register
from preflight.fingerprint import is_client_reachable
from preflight.models import Confidence, Evidence, Finding, Remediation, Severity
from preflight.redact import redact_in_line
from preflight.rules._shared import (
    KNOWN_SAFE_PUBLIC,
    PUBLIC_SENSITIVE_NAME,
    evidence_from,
    is_env_file,
    is_example_env,
)
from preflight.rules.secrets import SecretKind, iter_secret_matches


@register
class ClientSideThirdPartyKeys:
    id: str = "S2"
    title: str = "Third-party API key exposure"
    severity: Severity = Severity.SERIOUS
    applicability: Applicability = Applicability.anything()
    limits: tuple[str, ...] = (
        "Only source files are inspected. A key injected by a build step or a CDN script "
        "would not be seen without fetching the deployed bundle.",
        "Whether a leaked key is domain-restricted on the provider's side cannot be "
        "determined from the code.",
    )

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        yield from self._literals_in_client_files(ctx)
        yield from self._public_prefixed_secrets(ctx)

    def _literals_in_client_files(self, ctx: ScanContext) -> Iterable[Finding]:
        by_pattern: dict[str, list[Evidence]] = {}
        labels: dict[str, str] = {}
        consequences: dict[str, str] = {}

        for path in ctx.index.paths:
            text = ctx.read(path)
            if not text or not is_client_reachable(path, ctx.fingerprint, content=text):
                continue
            for match in iter_secret_matches(text, kinds=frozenset({SecretKind.THIRD_PARTY})):
                key = match.pattern.id
                by_pattern.setdefault(key, []).append(
                    evidence_from(match, path, note="this file is bundled and served to browsers")
                )
                labels[key] = match.pattern.label
                consequences[key] = match.pattern.consequence

        for pattern_id, evidence in sorted(by_pattern.items()):
            label = labels[pattern_id]
            yield Finding(
                rule_id=self.id,
                title=f"{label} is in code that ships to the browser",
                severity=Severity.SERIOUS,
                confidence=Confidence.CONFIRMED,
                summary=(
                    f"A {label.lower()} is written into front-end source. Anyone can read it with "
                    f"view-source or the network tab. {consequences[pattern_id]}"
                ),
                blast_radius=65,
                evidence=evidence,
                remediation=Remediation(
                    fix=(
                        f"1. Rotate the {label.lower()} now; treat it as public.\n"
                        "2. Move the call server-side -- a Next.js route handler, a Supabase edge "
                        "function, or any small endpoint you control -- and keep the key in that "
                        "server's environment.\n"
                        "3. Have the browser call your endpoint instead of the vendor directly.\n"
                        "4. Add a spend limit on the vendor account as a backstop."
                    ),
                    verify=(
                        "Build the app and search the output bundle for the key prefix: "
                        "`npm run build && grep -r 'sk-' dist/ .next/` should return nothing."
                    ),
                ),
            )

    def _public_prefixed_secrets(self, ctx: ScanContext) -> Iterable[Finding]:
        evidence: list[Evidence] = []
        for path in ctx.index.paths:
            name = PurePosixPath(path).name
            if not is_env_file(name) or is_example_env(name):
                continue
            for number, line in enumerate(ctx.read(path).splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                match = PUBLIC_SENSITIVE_NAME.match(stripped)
                if match is None:
                    continue
                variable = match.group("prefix") + match.group("name")
                if variable in KNOWN_SAFE_PUBLIC:
                    continue
                evidence.append(
                    Evidence(
                        path=path,
                        line=number,
                        snippet=redact_in_line(stripped, match.group("value")),
                        note=(
                            f"the {match.group('prefix')} prefix tells your build tool to inline "
                            "this value into the browser bundle"
                        ),
                    )
                )

        if not evidence:
            return
        yield Finding(
            rule_id=self.id,
            title="A secret is named with a public environment prefix",
            severity=Severity.SERIOUS,
            confidence=Confidence.CONFIRMED,
            summary=(
                f"{len(evidence)} environment variable{'s' if len(evidence) != 1 else ''} "
                "look like secrets but carry a public prefix. Build tools substitute those into "
                "the JavaScript they ship, so the value is readable by anyone who opens dev tools."
            ),
            blast_radius=70,
            evidence=evidence,
            remediation=Remediation(
                fix=(
                    "1. Rotate the key.\n"
                    "2. Rename the variable without the public prefix (`OPENAI_API_KEY`, not "
                    "`VITE_OPENAI_API_KEY`).\n"
                    "3. Read it only from server-side code. If the browser needed it, the browser "
                    "should be calling your server instead of the vendor."
                ),
                verify=("After a rebuild, the value must not appear anywhere in the built assets."),
            ),
        )
