"""Domain types.

Everything that crosses a module boundary in Preflight is one of these. They are
Pydantic models so that the JSON report, the HTTP API and the test assertions all
agree on one schema rather than three.
"""

from __future__ import annotations

import datetime as dt
from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Spec section 5. Three tiers, ordered by what they mean for a launch."""

    FATAL = "fatal"
    SERIOUS = "serious"
    HYGIENE = "hygiene"

    @property
    def rank(self) -> int:
        return {"fatal": 0, "serious": 1, "hygiene": 2}[self.value]

    @property
    def heading(self) -> str:
        return {
            "fatal": "Fix these now",
            "serious": "Before you charge money",
            "hygiene": "This month",
        }[self.value]


class Confidence(StrEnum):
    """Spec section 6, "Verification".

    CONFIRMED means the engine observed the defect directly in evidence it read.
    UNVERIFIED means the engine inferred it and could not confirm without access
    it does not have. Only CONFIRMED findings are allowed to set a fatal verdict;
    an unverified finding is reported as "check this manually".
    """

    CONFIRMED = "confirmed"
    UNVERIFIED = "unverified"


class BlastRadius(StrEnum):
    """How much is exposed, and how easily (spec section 6, "Ranking").

    Three levels, defined in the spec's own terms -- how many user records are
    reachable -- rather than a 0-100 score. A score implies precision the ruleset
    does not have: nobody can say what distinguishes 92 from 90, and pretending
    otherwise is its own small dishonesty.

    Three rather than four because three is what the ruleset actually
    distinguishes. Inventing a fourth level would mean guessing at a definition
    with no rule to anchor it.
    """

    #: One user's own data, or spend held under a provider-side cap.
    CONTAINED = "contained"
    #: Many records, or uncapped spend.
    BROAD = "broad"
    #: Every row, or takeover of the account itself.
    TOTAL = "total"

    @property
    def rank(self) -> int:
        """Worst first, so it can be used directly as a sort key."""
        return {"total": 0, "broad": 1, "contained": 2}[self.value]

    @property
    def impact(self) -> str:
        """What someone could actually do with it. Read straight into the report."""
        return {
            "total": (
                "Whole-database exposure. Someone acting on this reaches every user's "
                "records, not just their own."
            ),
            "broad": (
                "Broad exposure. Expect data or spend to be taken at scale, not one "
                "record at a time."
            ),
            "contained": "Limited but real exposure. Worth fixing before you take money.",
        }[self.value]


class Framework(StrEnum):
    NEXTJS = "nextjs"
    VITE_REACT = "vite-react"
    REMIX = "remix"
    UNKNOWN = "unknown"


class Backend(StrEnum):
    SUPABASE = "supabase"
    FIREBASE = "firebase"
    NONE = "none"
    UNKNOWN = "unknown"


class AuthProvider(StrEnum):
    SUPABASE_AUTH = "supabase-auth"
    FIREBASE_AUTH = "firebase-auth"
    CLERK = "clerk"
    AUTH0 = "auth0"
    NEXTAUTH = "nextauth"
    UNKNOWN = "unknown"


class PaymentProvider(StrEnum):
    STRIPE = "stripe"
    PADDLE = "paddle"
    NONE = "none"


class Fingerprint(BaseModel):
    """What we think this project is.

    Rules are gated on this. A Firebase app must never see an RLS rule; that
    gating is what keeps the false-positive rate and the report length down.
    """

    model_config = ConfigDict(frozen=True)

    framework: Framework = Framework.UNKNOWN
    backend: Backend = Backend.UNKNOWN
    auth: AuthProvider = AuthProvider.UNKNOWN
    payments: PaymentProvider = PaymentProvider.NONE
    client_env_prefixes: tuple[str, ...] = ()
    client_globs: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()


class Evidence(BaseModel):
    """A pointer into the user's code. Snippets are redacted before construction."""

    path: str
    line: int | None = None
    snippet: str = ""
    note: str | None = None


class Remediation(BaseModel):
    """The deterministic, stack-aware fallback fix, written by the rule author.

    This exists so that a report is useful with the LLM switched off entirely.
    The explanation layer improves on this; it is never the only source of it.
    """

    fix: str
    verify: str


class Explanation(BaseModel):
    """The four-part founder-readable rendering of a finding (spec section 6)."""

    what_it_means: str
    attacker_impact: str
    fix: str
    verify: str
    source: Literal["llm", "static"] = "static"


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    summary: str
    blast_radius: BlastRadius
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: Remediation
    explanation: Explanation | None = None

    @property
    def sort_key(self) -> tuple[int, int, int, str]:
        """Spec section 6: blast radius, not CVSS.

        Ordering inside a level is by rule id -- arbitrary, and deliberately so.
        When two findings are both total compromise, which one is printed first
        does not change what the reader should do next.
        """
        return (
            self.severity.rank,
            0 if self.confidence is Confidence.CONFIRMED else 1,
            self.blast_radius.rank,
            self.rule_id,
        )


@runtime_checkable
class Explainer(Protocol):
    """Turns a finding the engine has already produced into founder-readable prose.

    This protocol lives in `models` rather than in `engine` on purpose. Its whole
    signature is made of types declared in this file, and putting it here is what
    lets `preflight.explain` be typed correctly while still importing nothing but
    `preflight.models` -- so "the explanation layer cannot reach the engine" stays
    literally true, and `tests/test_architecture.py` can assert it.

    An implementation receives a finding that exists and returns four strings. It
    is never asked whether the finding is real, and there is no argument through
    which it could see the project.
    """

    def explain(self, finding: Finding, fingerprint: Fingerprint) -> Explanation: ...


class CheckStatus(StrEnum):
    PASSED = "passed"
    FOUND = "found"
    SKIPPED = "skipped"
    ERRORED = "errored"


class CheckOutcome(BaseModel):
    """One row of "what we checked" (spec section 7.5).

    A clean report is only worth paying for if it says what it looked at, so the
    engine records an outcome for every rule -- including the ones it skipped and
    why it skipped them.
    """

    rule_id: str
    title: str
    severity: Severity
    status: CheckStatus
    detail: str | None = None


class Verdict(BaseModel):
    headline: str
    detail: str
    safe_to_launch: bool


class ScanResult(BaseModel):
    scan_id: str
    target: str
    started_at: dt.datetime
    finished_at: dt.datetime
    preflight_version: str
    ruleset_version: str
    fingerprint: Fingerprint
    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list)
    checks: list[CheckOutcome] = Field(default_factory=list)
    not_checked: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity is severity]
