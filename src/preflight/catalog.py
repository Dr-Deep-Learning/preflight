"""The defect catalog.

One YAML file per defect, in `preflight/defects/`, loaded and validated here.
The catalog is the shared vocabulary: a deterministic rule and (later) a model
check that find the same defect report the same ID, so the two can be compared,
counted and evaluated together.

Three things this module exists to prevent, all of which were already true of the
catalog when it was first written:

* **Two severity vocabularies.** The catalog says `critical`/`high`/`medium`; the
  engine says `FATAL`/`SERIOUS`/`HYGIENE`, which render as "Fix these now",
  "Before you charge money", "This month". `CatalogSeverity.severity` is the one
  mapping between them, and a test pins it.
* **Stack tokens that do not exist.** `applies_to.stacks` is a closed vocabulary
  (`StackToken`), so a typo fails validation instead of silently gating nothing.
  Some tokens name things the fingerprinter cannot yet detect -- `express`,
  `serverless`, `vue`. Those are recorded as undetectable rather than quietly
  dropped, and they make the gate permissive (see `to_applicability`).
* **Globs that match nothing.** The catalog is written with brace alternation
  (`**/*.{js,ts}`), which no Python glob implementation understands. Patterns are
  expanded here and matched with gitignore semantics, and a test asserts every
  pattern actually reaches a file in the fixture corpus.

Nothing in this module detects anything. It loads data.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from importlib import resources

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from preflight.engine import Applicability
from preflight.ingest import expand_braces
from preflight.models import Backend, Framework, PaymentProvider, Severity

CATALOG_PACKAGE = "preflight"
CATALOG_DIRNAME = "defects"


class CatalogError(ValueError):
    """A defect file is missing, unparseable, or invalid."""


class DefectCategory(StrEnum):
    SECRETS = "secrets"
    ACCESS_CONTROL = "access-control"
    INJECTION = "injection"
    PAYMENTS = "payments"
    COST = "cost"
    CONFIG = "config"


class Detector(StrEnum):
    """Who finds this defect.

    `BOTH` is the interesting one: a cheap deterministic rule finds candidates
    and the model confirms, so model cost scales with suspicious code rather than
    with repository size.
    """

    RULE = "rule"
    LLM = "llm"
    BOTH = "both"


class DefectStatus(StrEnum):
    ACTIVE = "active"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"


class CatalogSeverity(StrEnum):
    """The catalog's severity words, and the one place they map to the engine's.

    These are deliberately the generic security words, because the catalog is an
    internal artifact that cites CWEs. The engine's `Severity` carries the
    founder-facing headings instead. Keeping both means the catalog can be read
    by a security engineer and the report by someone who is not one -- but it only
    works while exactly one mapping exists, which is this.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"

    @property
    def severity(self) -> Severity:
        return {
            "critical": Severity.FATAL,
            "high": Severity.SERIOUS,
            "medium": Severity.HYGIENE,
        }[self.value]


class StackToken(StrEnum):
    """The closed vocabulary `applies_to.stacks` may use."""

    ANY = "any"
    SUPABASE = "supabase"
    FIREBASE = "firebase"
    NEXTJS = "nextjs"
    VITE = "vite"
    REACT = "react"
    VUE = "vue"
    EXPRESS = "express"
    SERVERLESS = "serverless"
    STRIPE = "stripe"
    PADDLE = "paddle"


@dataclass(frozen=True)
class StackConstraint:
    """What one stack token means to the fingerprinter.

    `undetectable` marks a token naming something real that `fingerprint.py`
    cannot currently identify -- an Express server, a serverless deployment, a Vue
    front end. Recording that is the point: it is the difference between "this
    check does not apply" and "we cannot tell whether it applies", and only the
    first is safe to skip on.
    """

    backends: frozenset[Backend] = frozenset()
    frameworks: frozenset[Framework] = frozenset()
    payments: frozenset[PaymentProvider] = frozenset()
    undetectable: bool = False


_STACK_CONSTRAINTS: dict[StackToken, StackConstraint] = {
    StackToken.ANY: StackConstraint(),
    StackToken.SUPABASE: StackConstraint(backends=frozenset({Backend.SUPABASE})),
    StackToken.FIREBASE: StackConstraint(backends=frozenset({Backend.FIREBASE})),
    StackToken.NEXTJS: StackConstraint(frameworks=frozenset({Framework.NEXTJS})),
    StackToken.VITE: StackConstraint(frameworks=frozenset({Framework.VITE_REACT})),
    # "react" is not one framework: it is every framework we detect that renders
    # React, so it must not narrow the gate to any single one of them.
    StackToken.REACT: StackConstraint(
        frameworks=frozenset({Framework.NEXTJS, Framework.VITE_REACT, Framework.REMIX})
    ),
    StackToken.VUE: StackConstraint(undetectable=True),
    StackToken.EXPRESS: StackConstraint(undetectable=True),
    StackToken.SERVERLESS: StackConstraint(undetectable=True),
    StackToken.STRIPE: StackConstraint(payments=frozenset({PaymentProvider.STRIPE})),
    StackToken.PADDLE: StackConstraint(payments=frozenset({PaymentProvider.PADDLE})),
}

UNDETECTABLE_TOKENS = frozenset(
    token for token, constraint in _STACK_CONSTRAINTS.items() if constraint.undetectable
)


class AppliesTo(BaseModel):
    model_config = ConfigDict(frozen=True)

    stacks: tuple[StackToken, ...] = Field(min_length=1)
    globs: tuple[str, ...] = Field(min_length=1)

    @field_validator("globs")
    @classmethod
    def _globs_expand_cleanly(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for pattern in value:
            if pattern.count("{") != pattern.count("}"):
                raise ValueError(f"unbalanced braces in glob {pattern!r}")
            if "{" in pattern.partition("{")[2].partition("}")[0]:
                raise ValueError(f"nested braces are not supported: {pattern!r}")
        return value

    @property
    def patterns(self) -> tuple[str, ...]:
        """Globs with brace alternation expanded, ready for gitignore matching."""
        expanded: list[str] = []
        for pattern in self.globs:
            expanded.extend(expand_braces(pattern))
        return tuple(dict.fromkeys(expanded))

    @property
    def constraints(self) -> tuple[StackConstraint, ...]:
        return tuple(_STACK_CONSTRAINTS[token] for token in self.stacks)

    @property
    def constrained_dimensions(self) -> frozenset[str]:
        """Which fingerprint dimensions these tokens would narrow."""
        dimensions: set[str] = set()
        for constraint in self.constraints:
            if constraint.backends:
                dimensions.add("backend")
            if constraint.frameworks:
                dimensions.add("framework")
            if constraint.payments:
                dimensions.add("payments")
        return frozenset(dimensions)

    def to_applicability(self) -> Applicability:
        """Turn the token list into an engine gate.

        The tokens are a disjunction -- "Next.js *or* Express *or* serverless" --
        while `Applicability` conjoins its dimensions. So if any token cannot be
        evaluated, the project cannot be ruled out and the honest gate is no gate
        at all. Narrowing to only the detectable tokens would silently skip the
        check on exactly the projects we could not identify.
        """
        constraints = self.constraints
        if StackToken.ANY in self.stacks or any(c.undetectable for c in constraints):
            return Applicability.anything()

        backends: frozenset[Backend] = frozenset().union(*(c.backends for c in constraints))
        frameworks: frozenset[Framework] = frozenset().union(*(c.frameworks for c in constraints))
        payments: frozenset[PaymentProvider] = frozenset().union(*(c.payments for c in constraints))
        return Applicability(
            backends=backends or None,
            frameworks=frameworks or None,
            payments=payments or None,
        )


class Defect(BaseModel):
    """One catalog entry.

    IDs are permanent. Never renumber, never reuse; retire with
    `status: deprecated` so that a report produced last year still means
    something.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(pattern=r"^[A-Z]{3,4}-\d{3}$")
    title: str = Field(min_length=1)
    category: DefectCategory
    severity: CatalogSeverity
    detector: Detector
    status: DefectStatus
    applies_to: AppliesTo
    cwe: tuple[int, ...] = ()
    description: str = Field(min_length=1)
    why_ai_apps: str = Field(min_length=1)
    bad_example: str = Field(min_length=1)
    good_example: str = Field(min_length=1)
    false_positive_notes: str = Field(min_length=1)
    references: tuple[str, ...] = ()

    @property
    def filename(self) -> str:
        return f"{self.id.lower()}.yaml"

    @property
    def engine_severity(self) -> Severity:
        return self.severity.severity

    @property
    def has_rule(self) -> bool:
        """Whether a deterministic rule is meant to exist for this entry."""
        return self.detector in {Detector.RULE, Detector.BOTH}


def parse_defect(text: str, *, source: str) -> Defect:
    """Validate one defect document. `source` only decorates the error message."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CatalogError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise CatalogError(f"{source}: expected a mapping at the top level")
    try:
        return Defect.model_validate(raw)
    except ValueError as exc:
        raise CatalogError(f"{source}: {exc}") from exc


@lru_cache(maxsize=1)
def load_catalog() -> tuple[Defect, ...]:
    """Every defect, ordered by ID.

    Read through `importlib.resources` rather than a path relative to this file,
    so it works identically from a clone, from an installed wheel and from inside
    the container -- where the Dockerfile copies `src` and nothing else.
    """
    directory = resources.files(CATALOG_PACKAGE) / CATALOG_DIRNAME
    defects: list[Defect] = []
    seen: dict[str, str] = {}

    for entry in sorted(directory.iterdir(), key=lambda e: e.name):
        if not entry.name.endswith(".yaml"):
            continue  # the catalog's own README.md, and anything else
        defect = parse_defect(entry.read_text(encoding="utf-8"), source=entry.name)
        if defect.filename != entry.name:
            raise CatalogError(
                f"{entry.name}: declares id {defect.id!r}, which belongs in {defect.filename!r}"
            )
        if defect.id in seen:
            raise CatalogError(
                f"{entry.name}: duplicate id {defect.id!r}, also in {seen[defect.id]}"
            )
        seen[defect.id] = entry.name
        defects.append(defect)

    if not defects:
        raise CatalogError(f"no defect files found in {CATALOG_PACKAGE}/{CATALOG_DIRNAME}")
    return tuple(sorted(defects, key=lambda d: d.id))


def catalog_by_id() -> dict[str, Defect]:
    return {defect.id: defect for defect in load_catalog()}


def get_defect(defect_id: str) -> Defect:
    try:
        return catalog_by_id()[defect_id]
    except KeyError as exc:
        raise CatalogError(f"no such defect: {defect_id!r}") from exc
