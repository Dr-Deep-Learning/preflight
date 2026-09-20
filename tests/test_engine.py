"""The engine: gating, ordering, verdicts, and the detection/explanation boundary."""

import pytest

from preflight.engine import (
    REGISTRY,
    Applicability,
    Rule,
    RuleRegistry,
    build_verdict,
    run_scan,
)
from preflight.models import (
    Backend,
    BlastRadius,
    CheckStatus,
    Confidence,
    Explanation,
    Finding,
    Fingerprint,
    Framework,
    PaymentProvider,
    Remediation,
    Severity,
)


def make_finding(**kwargs):
    defaults = {
        "rule_id": "X1",
        "title": "t",
        "severity": Severity.FATAL,
        "confidence": Confidence.CONFIRMED,
        "summary": "s",
        "blast_radius": BlastRadius.BROAD,
        "remediation": Remediation(fix="f", verify="v"),
    }
    return Finding(**{**defaults, **kwargs})


class TestApplicability:
    def test_none_means_do_not_care(self):
        fp = Fingerprint(backend=Backend.FIREBASE)
        assert Applicability.anything().matches(fp)

    def test_an_unmatched_backend_is_skipped_with_a_reason(self):
        gate = Applicability(backends=frozenset({Backend.SUPABASE}))
        assert gate.skip_reason(Fingerprint(backend=Backend.FIREBASE)) == (
            "not applicable to a firebase backend"
        )

    def test_unknown_stack_still_runs(self):
        """Under uncertainty we would rather check and mark unverified than skip."""
        gate = Applicability(backends=frozenset({Backend.SUPABASE}))
        assert gate.matches(Fingerprint(backend=Backend.UNKNOWN))

    def test_payment_gate_requires_a_provider(self):
        gate = Applicability(payments=frozenset({PaymentProvider.STRIPE}))
        assert not gate.matches(Fingerprint(payments=PaymentProvider.NONE))
        assert gate.matches(Fingerprint(payments=PaymentProvider.STRIPE))


class TestRegistry:
    def test_every_shipped_rule_satisfies_the_protocol(self):
        for rule in REGISTRY:
            assert isinstance(rule, Rule)
            assert rule.id and rule.title
            assert rule.limits, f"{rule.id} must state what it does not check"

    def test_the_shipped_ruleset_is_the_documented_one(self):
        assert REGISTRY.ids() == ("F1", "F2", "S1", "S2")

    def test_duplicate_ids_are_rejected(self):
        class Duplicate:
            id = "F1"
            title = "t"
            severity = Severity.FATAL
            applicability = Applicability.anything()
            catalog_ids = ()
            limits = ("none",)

            def check(self, ctx):
                return []

        registry = RuleRegistry()
        registry.add(Duplicate())
        with pytest.raises(ValueError, match="duplicate rule id"):
            registry.add(Duplicate())

    def test_rules_are_ordered_by_severity(self):
        ids = REGISTRY.ids()
        assert ids.index("F1") < ids.index("S2")


class TestVerdict:
    def test_confirmed_fatal_blocks_a_launch(self):
        verdict = build_verdict([make_finding()])
        assert verdict.headline == "Not safe to launch"
        assert not verdict.safe_to_launch

    def test_unverified_fatal_does_not_claim_certainty(self):
        """Calling someone's product unsafe on an inference is the trust-destroying move."""
        verdict = build_verdict([make_finding(confidence=Confidence.UNVERIFIED)])
        assert verdict.headline == "Check these before you launch"
        assert "could not confirm" in verdict.detail

    def test_serious_only_still_launches(self):
        verdict = build_verdict([make_finding(severity=Severity.SERIOUS)])
        assert verdict.safe_to_launch
        assert "before you charge money" in verdict.detail

    def test_nothing_found_is_clean(self):
        assert build_verdict([]).headline == "Clean"


class TestScan:
    def test_vulnerable_app_is_not_safe_to_launch(self, vulnerable_scan):
        assert vulnerable_scan.verdict.headline == "Not safe to launch"
        assert {f.rule_id for f in vulnerable_scan.findings} == {"F1", "F2", "S1", "S2"}

    def test_clean_app_is_clean(self, clean_scan):
        assert clean_scan.findings == []
        assert clean_scan.verdict.headline == "Clean"

    def test_findings_are_ranked_by_blast_radius_not_rule_order(self, vulnerable_scan):
        keys = [f.sort_key for f in vulnerable_scan.findings]
        assert keys == sorted(keys)
        assert vulnerable_scan.findings[0].severity is Severity.FATAL

    def test_every_rule_reports_an_outcome(self, vulnerable_scan, clean_scan):
        for result in (vulnerable_scan, clean_scan):
            assert {c.rule_id for c in result.checks} == set(REGISTRY.ids())

    def test_a_clean_scan_says_what_it_checked(self, clean_scan):
        assert all(c.status is CheckStatus.PASSED for c in clean_scan.checks)
        assert clean_scan.not_checked

    def test_a_firebase_project_skips_the_rls_rule(self, tmp_path):
        (tmp_path / "package.json").write_text('{"dependencies": {"firebase": "^10.0.0"}}')
        result = run_scan(tmp_path)
        skipped = {c.rule_id: c for c in result.checks if c.status is CheckStatus.SKIPPED}
        assert "F1" in skipped
        assert "firebase" in (skipped["F1"].detail or "")

    def test_a_broken_rule_does_not_lose_the_scan(self, tmp_path):
        class Exploding:
            id = "ZZ"
            title = "explodes"
            severity = Severity.HYGIENE
            applicability = Applicability.anything()
            catalog_ids = ()
            limits = ("nothing",)

            def check(self, ctx):
                raise RuntimeError("boom")

        registry = RuleRegistry()
        registry.add(Exploding())
        result = run_scan(tmp_path, registry=registry)
        assert result.checks[0].status is CheckStatus.ERRORED
        assert result.findings == []


class TestExplanationBoundary:
    def test_an_explainer_cannot_add_or_remove_findings(self, tmp_path):
        """The structural guarantee: explain() returns prose, not findings."""

        class Inventive:
            def explain(self, finding, fingerprint):
                return Explanation(
                    what_it_means="w", attacker_impact="a", fix="f", verify="v", source="llm"
                )

        from conftest import VULNERABLE

        plain = run_scan(VULNERABLE)
        explained = run_scan(VULNERABLE, explainer=Inventive())
        assert [f.rule_id for f in plain.findings] == [f.rule_id for f in explained.findings]
        assert all(f.explanation is not None for f in explained.findings)

    def test_a_failing_explainer_degrades_the_report_instead_of_the_scan(self, tmp_path):
        class Broken:
            def explain(self, finding, fingerprint):
                raise RuntimeError("model unavailable")

        from conftest import VULNERABLE

        result = run_scan(VULNERABLE, explainer=Broken())
        assert result.findings
        assert all(f.explanation is None for f in result.findings)
        assert all(f.remediation.fix for f in result.findings)


class TestFingerprintGating:
    def test_framework_gate(self):
        gate = Applicability(frameworks=frozenset({Framework.NEXTJS}))
        assert not gate.matches(Fingerprint(framework=Framework.VITE_REACT))
