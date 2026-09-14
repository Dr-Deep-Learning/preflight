"""Domain types.

Everything that crosses a module boundary in Preflight is one of these. They are
Pydantic models so that the JSON report, the HTTP API and the test assertions all
agree on one schema rather than three.
"""

from __future__ import annotations

import datetime as dt
from enum import StrEnum
from typing import Literal

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
    blast_radius: int = Field(ge=0, le=100)
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: Remediation
    explanation: Explanation | None = None

    @property
    def sort_key(self) -> tuple[int, int, int, str]:
        return (
            self.severity.rank,
            0 if self.confidence is Confidence.CONFIRMED else 1,
            -self.blast_radius,
            self.rule_id,
        )


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
