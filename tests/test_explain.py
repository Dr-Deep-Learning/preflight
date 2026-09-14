"""The explanation layer, including the Anthropic client without a network call."""

import json

from conftest import SERVICE_ROLE_JWT
from preflight.explain import StaticExplainer, get_explainer
from preflight.explain.anthropic_explainer import SYSTEM_PROMPT, AnthropicExplainer
from preflight.models import Backend, Fingerprint, Framework


class FakeBlock:
    type = "text"

    def __init__(self, text):
        self.text = text


class FakeResponse:
    def __init__(self, text):
        self.content = [FakeBlock(text)]


class FakeMessages:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return FakeResponse(self.payload)


class FakeClient:
    def __init__(self, payload):
        self.messages = FakeMessages(payload)


FP = Fingerprint(framework=Framework.VITE_REACT, backend=Backend.SUPABASE)

GOOD = json.dumps(
    {
        "what_it_means": "Anyone can read your users' rows.",
        "attacker_impact": "They open dev tools and query the table.",
        "fix": "ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;",
        "verify": "SELECT rowsecurity FROM pg_tables;",
    }
)


def first_finding(scan):
    return scan.findings[0]


def test_static_explainer_uses_the_rule_authors_fix(vulnerable_scan):
    finding = first_finding(vulnerable_scan)
    explanation = StaticExplainer().explain(finding, FP)
    assert explanation.source == "static"
    assert finding.remediation.fix in explanation.fix
    assert explanation.verify == finding.remediation.verify


def test_static_explainer_names_the_stack(vulnerable_scan):
    explanation = StaticExplainer().explain(first_finding(vulnerable_scan), FP)
    assert "vite-react + supabase" in explanation.fix


def test_anthropic_explainer_parses_a_good_response(vulnerable_scan):
    explainer = AnthropicExplainer(client=FakeClient(GOOD))
    explanation = explainer.explain(first_finding(vulnerable_scan), FP)
    assert explanation.source == "llm"
    assert explanation.fix.startswith("ALTER TABLE")


def test_anthropic_explainer_falls_back_when_the_response_is_unusable(vulnerable_scan):
    explainer = AnthropicExplainer(client=FakeClient("I'm not sure, maybe check the docs?"))
    explanation = explainer.explain(first_finding(vulnerable_scan), FP)
    assert explanation.source == "static"


def test_fenced_json_is_tolerated(vulnerable_scan):
    explainer = AnthropicExplainer(client=FakeClient(f"```json\n{GOOD}\n```"))
    assert explainer.explain(first_finding(vulnerable_scan), FP).source == "llm"


def test_the_model_is_never_sent_a_raw_credential(vulnerable_scan):
    """Redaction happens at Evidence construction, so this holds by construction."""
    client = FakeClient(GOOD)
    explainer = AnthropicExplainer(client=client)
    for finding in vulnerable_scan.findings:
        explainer.explain(finding, FP)
    sent = json.dumps(client.messages.calls)
    assert SERVICE_ROLE_JWT not in sent
    assert "sk-preflightFIXTUREkeyDoNotUse7f3a91c4b8e2d6" not in sent
    assert "preflightFixturePw9312" not in sent


def test_the_prompt_forbids_detection():
    assert "already confirmed" in SYSTEM_PROMPT
    assert "Do not question whether it is real" in SYSTEM_PROMPT
    assert "must not pretend otherwise" in SYSTEM_PROMPT


def test_get_explainer_resolves_by_name():
    assert isinstance(get_explainer("static"), StaticExplainer)
