"""The Claude-backed explainer.

One API call per confirmed finding. The call receives:

* the finding the engine already produced, and
* the stack fingerprint, so the fix is written for this project.

It does not receive the project's source, and it is not asked whether the finding
is real. The prompt says so, but the reason it is true is that this function is
only ever called with a `Finding` that already exists -- there is no argument it
could be given that would let it invent one, and no return value it could produce
that the engine would read as a new finding.

If the call fails, times out, or returns something that does not parse, we fall
back to the deterministic explanation. A degraded report beats a wrong one.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from preflight.explain.static import StaticExplainer
from preflight.models import Explanation, Finding, Fingerprint

log = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-sonnet-4-5"

SYSTEM_PROMPT = """\
You write security explanations for non-technical founders who built their app \
with AI coding tools. They can read a diff but cannot evaluate one. They will \
not act on a CVSS score. They will act on "anyone on the internet can currently \
read your users' email addresses -- here is the SQL to fix it".

You are given ONE finding that a deterministic scanner has already confirmed. \
Your job is only to explain it. Do not question whether it is real, do not \
speculate about other issues, and do not soften it. You have not seen the code \
and must not pretend otherwise: write only from the finding you are given.

Rules for the prose:
- Second person, present tense, plain words. No jargon without a five-word gloss.
- Never invent file names, table names, key values or line numbers. Use only what \
the finding gives you.
- The fix must be copy-pasteable and specific to the stack named below.
- No preamble, no reassurance, no "it is recommended that".

Reply with JSON only, exactly these four keys:
{"what_it_means": str, "attacker_impact": str, "fix": str, "verify": str}
what_it_means: one or two sentences.
attacker_impact: what someone could actually do today, concretely.
fix: numbered steps, with code or exact clicks.
verify: how they prove to themselves it worked."""


def _finding_payload(finding: Finding, fingerprint: Fingerprint) -> str:
    """Everything the model gets. Evidence snippets are already redacted."""
    return json.dumps(
        {
            "stack": {
                "framework": fingerprint.framework.value,
                "backend": fingerprint.backend.value,
                "auth": fingerprint.auth.value,
                "payments": fingerprint.payments.value,
            },
            "finding": {
                "rule": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "summary": finding.summary,
                "evidence": [
                    {"path": e.path, "line": e.line, "snippet": e.snippet, "note": e.note}
                    for e in finding.evidence[:8]
                ],
                "known_fix": finding.remediation.fix,
                "known_verification": finding.remediation.verify,
            },
        },
        indent=2,
    )


class AnthropicExplainer:
    """Explainer backed by the Anthropic Messages API."""

    def __init__(
        self,
        *,
        client: Any | None = None,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 900,
    ) -> None:
        self._model = model
        self._max_tokens = max_tokens
        self._fallback = StaticExplainer()
        if client is not None:
            self._client = client
        else:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover - optional dependency
                raise RuntimeError(
                    "the anthropic extra is not installed: `uv sync --extra llm`"
                ) from exc
            if not os.environ.get("ANTHROPIC_API_KEY"):
                raise RuntimeError("ANTHROPIC_API_KEY is not set")
            self._client = anthropic.Anthropic()

    def explain(self, finding: Finding, fingerprint: Fingerprint) -> Explanation:
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": _finding_payload(finding, fingerprint)}],
            )
            text = "".join(
                block.text for block in response.content if getattr(block, "type", "") == "text"
            )
            parsed = json.loads(_strip_fences(text))
            return Explanation(
                what_it_means=str(parsed["what_it_means"]),
                attacker_impact=str(parsed["attacker_impact"]),
                fix=str(parsed["fix"]),
                verify=str(parsed["verify"]),
                source="llm",
            )
        except Exception:
            log.warning("anthropic explainer failed for %s; using static", finding.rule_id)
            return self._fallback.explain(finding, fingerprint)


def _strip_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[-1]
        stripped = stripped.rsplit("```", 1)[0]
    return stripped.strip()
