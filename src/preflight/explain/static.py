"""The deterministic explainer.

Every rule ships a written fix and a written verification step, and every finding
carries a blast-radius level that knows its own impact sentence. This explainer
assembles those and invents nothing, which gives the product two things:

* a report that is complete and useful with the model switched off entirely, and
* a test suite that never touches the network and never asserts on model output.

It is the default. The language model is an upgrade to the prose, not a
dependency of the product.
"""

from __future__ import annotations

from preflight.models import Explanation, Finding, Fingerprint


class StaticExplainer:
    def explain(self, finding: Finding, fingerprint: Fingerprint) -> Explanation:
        stack = _describe_stack(fingerprint)
        return Explanation(
            what_it_means=finding.summary,
            attacker_impact=finding.blast_radius.impact,
            fix=(f"For your stack ({stack}):\n\n" if stack else "") + finding.remediation.fix,
            verify=finding.remediation.verify,
            source="static",
        )


def _describe_stack(fingerprint: Fingerprint) -> str:
    parts = [
        fingerprint.framework.value if fingerprint.framework.value != "unknown" else "",
        fingerprint.backend.value if fingerprint.backend.value not in {"unknown", "none"} else "",
    ]
    return " + ".join(p for p in parts if p)
