"""The rule engine.

Three ideas, and they are the architecture:

1. A rule is an object satisfying `Rule`, not a function in a big if/else. Adding
   a check is adding a file; nothing else in the system changes.
2. A rule declares the stacks it applies to (`Applicability`) rather than opening
   with a guard clause. The engine does the gating, so skipping is uniform,
   recorded, and reportable -- which is what makes "what we checked" honest.
3. Rules are deterministic and produce `Finding` objects. Nothing in this module
   can call a language model. The explanation layer runs strictly afterwards, on
   findings that already exist. That boundary is enforced by module structure, not
   by a prompt (spec section 12: "the LLM explains, it never detects"), and
   `tests/test_architecture.py` asserts it rather than trusting this paragraph.

The `Explainer` protocol this module accepts is declared in `preflight.models`,
not here, so that `preflight.explain` can be typed against it without importing
the engine at all.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar, runtime_checkable

from preflight import RULESET_VERSION, __version__
from preflight.fingerprint import fingerprint_project
from preflight.ingest import FileIndex, GitInfo, LocalDirectorySource
from preflight.models import (
    Backend,
    CheckOutcome,
    CheckStatus,
    Confidence,
    Explainer,
    Explanation,
    Finding,
    Fingerprint,
    Framework,
    PaymentProvider,
    ScanResult,
    Severity,
    Verdict,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanContext:
    """Everything a rule is allowed to see. Read-only by construction."""

    root: Path
    index: FileIndex
    git: GitInfo
    fingerprint: Fingerprint

    def read(self, relpath: str) -> str:
        return self.index.read_text(relpath)


@dataclass(frozen=True)
class Applicability:
    """Declarative stack gate.

    `None` means "don't care". An UNKNOWN value on the fingerprint always matches:
    when we could not identify the stack we would rather run the check and mark
    the finding unverified than silently skip it.
    """

    backends: frozenset[Backend] | None = None
    frameworks: frozenset[Framework] | None = None
    payments: frozenset[PaymentProvider] | None = None

    @staticmethod
    def anything() -> Applicability:
        return Applicability()

    def skip_reason(self, fp: Fingerprint) -> str | None:
        if (
            self.backends is not None
            and fp.backend is not Backend.UNKNOWN
            and fp.backend not in self.backends
        ):
            return f"not applicable to a {fp.backend.value} backend"
        if (
            self.frameworks is not None
            and fp.framework is not Framework.UNKNOWN
            and fp.framework not in self.frameworks
        ):
            return f"not applicable to {fp.framework.value}"
        if self.payments is not None and fp.payments not in self.payments:
            return f"no {'/'.join(sorted(p.value for p in self.payments))} integration detected"
        return None

    def matches(self, fp: Fingerprint) -> bool:
        return self.skip_reason(fp) is None


@runtime_checkable
class Rule(Protocol):
    """The contract every check implements."""

    id: str
    title: str
    severity: Severity
    applicability: Applicability
    #: Catalog entries this rule implements, e.g. ("SEC-001", "SEC-003").
    #: The catalog is the shared vocabulary between deterministic rules and any
    #: later model-driven check, so a rule that reports in its own private
    #: numbering cannot be compared with anything. `tests/test_catalog.py`
    #: asserts every id here exists.
    catalog_ids: tuple[str, ...]
    #: Honest scope statement fragments for report section "what we did not check".
    limits: tuple[str, ...]

    def check(self, ctx: ScanContext) -> Iterable[Finding]: ...


class RuleRegistry:
    """Ordered collection of rules. One default instance; tests build their own."""

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def add(self, rule: Rule) -> None:
        if rule.id in self._rules:
            raise ValueError(f"duplicate rule id {rule.id!r}")
        self._rules[rule.id] = rule

    def __iter__(self) -> Iterator[Rule]:
        return iter(sorted(self._rules.values(), key=lambda r: (r.severity.rank, r.id)))

    def __len__(self) -> int:
        return len(self._rules)

    def get(self, rule_id: str) -> Rule:
        return self._rules[rule_id]

    def ids(self) -> tuple[str, ...]:
        return tuple(r.id for r in self)


REGISTRY = RuleRegistry()


RuleT = TypeVar("RuleT", bound=Rule)


def register(cls: type[RuleT]) -> type[RuleT]:
    """Class decorator. Import of a rule module is what puts it in the registry."""
    REGISTRY.add(cls())
    return cls


def build_verdict(findings: list[Finding]) -> Verdict:
    """Spec section 7.1: one unambiguous line.

    Only confirmed fatal findings block a launch. An unverified fatal is reported
    loudly but does not get to call someone's product unsafe on an inference.
    """
    fatal = [f for f in findings if f.severity is Severity.FATAL]
    confirmed_fatal = [f for f in fatal if f.confidence is Confidence.CONFIRMED]
    serious = [f for f in findings if f.severity is Severity.SERIOUS]
    hygiene = [f for f in findings if f.severity is Severity.HYGIENE]

    if confirmed_fatal:
        return Verdict(
            headline="Not safe to launch",
            detail=(
                f"{len(confirmed_fatal)} confirmed issue"
                f"{'s' if len(confirmed_fatal) != 1 else ''} that can expose your users' data."
            ),
            safe_to_launch=False,
        )
    if fatal:
        return Verdict(
            headline="Check these before you launch",
            detail=(
                f"{len(fatal)} possible critical issue{'s' if len(fatal) != 1 else ''} "
                "we could not confirm from the code alone."
            ),
            safe_to_launch=False,
        )
    if serious:
        return Verdict(
            headline="Safe to launch",
            detail=(
                f"{len(serious)} item{'s' if len(serious) != 1 else ''} to fix "
                "before you charge money."
            ),
            safe_to_launch=True,
        )
    if hygiene:
        return Verdict(
            headline="Safe to launch",
            detail=f"{len(hygiene)} housekeeping item(s) to fix this month.",
            safe_to_launch=True,
        )
    return Verdict(
        headline="Clean",
        detail="Every check in this ruleset passed. See the scope statement below.",
        safe_to_launch=True,
    )


def run_scan(
    target: Path,
    *,
    registry: RuleRegistry | None = None,
    explainer: Explainer | None = None,
    scan_id: str | None = None,
) -> ScanResult:
    """Ingest, fingerprint, run every applicable rule, then explain. In that order."""
    registry = registry if registry is not None else REGISTRY
    started = dt.datetime.now(dt.UTC)

    root, index, git = LocalDirectorySource(root=target).load()
    fingerprint = fingerprint_project(index)
    ctx = ScanContext(root=root, index=index, git=git, fingerprint=fingerprint)

    findings: list[Finding] = []
    checks: list[CheckOutcome] = []
    not_checked: list[str] = []

    for rule in registry:
        not_checked.extend(rule.limits)
        skip = rule.applicability.skip_reason(fingerprint)
        if skip is not None:
            checks.append(
                CheckOutcome(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    status=CheckStatus.SKIPPED,
                    detail=skip,
                )
            )
            continue
        try:
            produced = list(rule.check(ctx))
        except Exception:
            log.exception("rule %s failed", rule.id)
            checks.append(
                CheckOutcome(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    status=CheckStatus.ERRORED,
                    detail="the check failed to run; treat as unchecked",
                )
            )
            continue

        findings.extend(produced)
        checks.append(
            CheckOutcome(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                status=CheckStatus.FOUND if produced else CheckStatus.PASSED,
                detail=(
                    f"{len(produced)} finding{'s' if len(produced) != 1 else ''}"
                    if produced
                    else "no issues found"
                ),
            )
        )

    # Spec section 6, "Ranking": blast radius, not CVSS.
    findings.sort(key=lambda f: f.sort_key)

    if explainer is not None:
        findings = [_explained(f, fingerprint, explainer) for f in findings]

    return ScanResult(
        scan_id=scan_id or uuid.uuid4().hex[:12],
        target=str(root),
        started_at=started,
        finished_at=dt.datetime.now(dt.UTC),
        preflight_version=__version__,
        ruleset_version=RULESET_VERSION,
        fingerprint=fingerprint,
        verdict=build_verdict(findings),
        findings=findings,
        checks=checks,
        not_checked=sorted(set(not_checked)),
    )


def _explained(finding: Finding, fingerprint: Fingerprint, explainer: Explainer) -> Finding:
    """Attach an explanation. A failure here degrades the report; it never fails the scan."""
    try:
        explanation = explainer.explain(finding, fingerprint)
    except Exception:
        log.exception("explainer failed for %s", finding.rule_id)
        return finding
    return replace_explanation(finding, explanation)


def replace_explanation(finding: Finding, explanation: Explanation) -> Finding:
    return finding.model_copy(update={"explanation": explanation})


# `Explainer` is deliberately absent: it is owned by `preflight.models`, and
# re-exporting it here would invite `explain/` to import the engine to get it.
__all__ = [
    "REGISTRY",
    "Applicability",
    "Rule",
    "RuleRegistry",
    "ScanContext",
    "build_verdict",
    "register",
    "run_scan",
]
