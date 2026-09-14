"""The explanation layer.

This package sits strictly downstream of detection. Everything in it receives a
`Finding` that the deterministic engine has already produced and turns it into
the four-part rendering the founder reads. Nothing in here can create, suppress,
or re-rank a finding -- there is no code path from this package back into the
engine, which is the point.

Spec section 12 lists "LLM hallucinating findings" as a high risk with the
response "structural fix: the LLM explains, it never detects. Enforce in
architecture, not in prompts." This package is that architecture.
"""

from preflight.explain.static import StaticExplainer

__all__ = ["StaticExplainer", "get_explainer"]


def get_explainer(name: str = "static") -> object:
    """Resolve an explainer by name, importing optional dependencies lazily."""
    if name == "static":
        return StaticExplainer()
    if name == "anthropic":
        from preflight.explain.anthropic_explainer import AnthropicExplainer

        return AnthropicExplainer()
    raise ValueError(f"unknown explainer {name!r}")
