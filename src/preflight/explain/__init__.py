"""The explanation layer.

This package sits strictly downstream of detection. Everything in it receives a
`Finding` that the deterministic engine has already produced and turns it into
the four-part rendering the founder reads. Nothing in here can create, suppress,
or re-rank a finding.

That is not a promise, it is a property of the import graph: no module in this
package imports `preflight.engine`, and `tests/test_architecture.py` fails the
build if one ever does. The `Explainer` protocol lives in `preflight.models` so
that this package can be typed against it without reaching for the engine.

Spec section 12 lists "LLM hallucinating findings" as a high risk with the
response "structural fix: the LLM explains, it never detects. Enforce in
architecture, not in prompts." This package is that architecture.
"""

from preflight.explain.static import StaticExplainer
from preflight.models import Explainer

__all__ = ["StaticExplainer", "get_explainer"]


def get_explainer(name: str = "static") -> Explainer:
    """Resolve an explainer by name, importing optional dependencies lazily.

    Raises `ValueError` for an unknown name. Callers at an edge -- the CLI, the
    service -- translate that into whatever their transport calls a bad request;
    a library should not know what a command-line usage error looks like.
    """
    if name == "static":
        return StaticExplainer()
    if name == "anthropic":
        from preflight.explain.anthropic_explainer import AnthropicExplainer

        return AnthropicExplainer()
    raise ValueError(f"unknown explainer {name!r} (choose: static, anthropic)")
