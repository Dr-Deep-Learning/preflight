"""S1: payment webhook handlers that never verify a signature.

This rule detects an absence, so most of these tests are about *not* firing: on a
correctly written handler, on ordinary server code that happens to mention
Stripe, on a client file, and on a hand-rolled but correct HMAC check.
"""

from conftest import context_for
from preflight.engine import REGISTRY
from preflight.models import (
    Backend,
    BlastRadius,
    Confidence,
    Fingerprint,
    Framework,
    PaymentProvider,
    Severity,
)

RULE = REGISTRY.get("S1")

NEXT_STRIPE_PKG = '{"dependencies": {"next": "^14.2.5", "stripe": "^16.6.0"}}'


def findings_for(ctx):
    return list(RULE.check(ctx))


def project(tmp_path, files, package_json=NEXT_STRIPE_PKG):
    (tmp_path / "package.json").write_text(package_json, encoding="utf-8")
    for relative, text in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return context_for(tmp_path)


# --- the corpus --------------------------------------------------------------


def test_the_unverified_handler_is_reported(vulnerable_ctx):
    (finding,) = findings_for(vulnerable_ctx)
    assert {e.path for e in finding.evidence} == {"api/webhook.js"}
    assert finding.severity is Severity.SERIOUS


def test_the_finding_is_unverified_because_middleware_is_invisible(vulnerable_ctx):
    """We read one file. Verification may legitimately live somewhere else."""
    (finding,) = findings_for(vulnerable_ctx)
    assert finding.confidence is Confidence.UNVERIFIED
    assert "confirm before" in finding.summary
    assert any("middleware" in limit for limit in RULE.limits)


def test_the_evidence_points_at_the_line_that_trusts_the_body(vulnerable_ctx):
    (finding,) = findings_for(vulnerable_ctx)
    (evidence,) = finding.evidence
    assert "JSON.parse" in evidence.snippet
    assert evidence.line is not None


def test_blast_radius_is_broad(vulnerable_ctx):
    (finding,) = findings_for(vulnerable_ctx)
    assert finding.blast_radius is BlastRadius.BROAD


def test_the_remediation_names_the_raw_body_trap(vulnerable_ctx):
    """Passing a parsed body to constructEvent is the mistake people make next."""
    (finding,) = findings_for(vulnerable_ctx)
    assert "RAW request body" in finding.remediation.fix
    assert "constructEvent" in finding.remediation.fix


def test_a_correct_handler_is_not_reported(clean_ctx):
    assert findings_for(clean_ctx) == []


# --- the ways it must not fire -----------------------------------------------


def test_ordinary_stripe_server_code_is_not_a_webhook_handler(tmp_path):
    """A checkout session endpoint mentions Stripe and is server-side. It is not a
    webhook, and a rule that flags it is unusable."""
    ctx = project(
        tmp_path,
        {
            "app/api/checkout/route.ts": (
                'import Stripe from "stripe";\n'
                "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);\n"
                "export async function POST() {\n"
                "  const session = await stripe.checkout.sessions.create({});\n"
                "  return Response.json({ url: session.url });\n"
                "}\n"
            )
        },
    )
    assert findings_for(ctx) == []


def test_a_hand_rolled_hmac_comparison_counts_as_verification(tmp_path):
    """Unusual, but correct. Recognising only the SDK call would report it."""
    ctx = project(
        tmp_path,
        {
            "app/api/webhook/route.ts": (
                'import Stripe from "stripe";\n'
                'import crypto from "crypto";\n'
                "export async function POST(request) {\n"
                "  const raw = await request.text();\n"
                '  const sig = request.headers.get("stripe-signature");\n'
                '  const expected = crypto.createHmac("sha256", process.env.WH_SECRET)\n'
                '    .update(raw).digest("hex");\n'
                "  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {\n"
                '    return new Response("bad signature", { status: 400 });\n'
                "  }\n"
                "  return Response.json({ received: true });\n"
                "}\n"
            )
        },
    )
    assert findings_for(ctx) == []


def test_a_client_file_is_never_a_webhook_handler(tmp_path):
    """Nothing in the browser bundle is an endpoint, whatever it is called."""
    ctx = project(
        tmp_path,
        {
            "components/webhookStatus.tsx": (
                'import Stripe from "stripe";\n'
                "export function WebhookStatus() { return <p>stripe-signature</p>; }\n"
            )
        },
    )
    assert findings_for(ctx) == []


def test_a_handler_is_found_by_its_signature_header_alone(tmp_path):
    """The path need not contain "webhook" -- reading the signed header is enough
    to say this file is meant to be an endpoint."""
    ctx = project(
        tmp_path,
        {
            "app/api/payments/route.ts": (
                'import Stripe from "stripe";\n'
                "export async function POST(request) {\n"
                '  const sig = request.headers.get("stripe-signature");\n'
                "  const event = await request.json();\n"
                "  return Response.json({ ok: true, sig, type: event.type });\n"
                "}\n"
            )
        },
    )
    (finding,) = findings_for(ctx)
    assert {e.path for e in finding.evidence} == {"app/api/payments/route.ts"}


def test_several_bad_handlers_are_one_finding_with_evidence_each(tmp_path):
    handler = (
        'import Stripe from "stripe";\n'
        "export async function POST(request) {\n"
        "  const event = await request.json();\n"
        "  return Response.json({ type: event.type });\n"
        "}\n"
    )
    ctx = project(
        tmp_path,
        {
            "app/api/webhook/route.ts": handler,
            "app/api/paddle-webhook/route.ts": handler,
        },
    )
    (finding,) = findings_for(ctx)
    assert len(finding.evidence) == 2
    assert "2 payment webhook handlers" in finding.title


# --- the gate ----------------------------------------------------------------


def test_the_rule_is_gated_on_a_detected_payment_provider():
    """A project with no payment SDK is skipped, and the report says why."""
    without = Fingerprint(framework=Framework.NEXTJS, backend=Backend.SUPABASE)
    with_stripe = Fingerprint(
        framework=Framework.NEXTJS, backend=Backend.SUPABASE, payments=PaymentProvider.STRIPE
    )
    assert RULE.applicability.skip_reason(without) == "no paddle/stripe integration detected"
    assert RULE.applicability.matches(with_stripe)


def test_a_provider_used_without_its_sdk_is_declared_as_a_blind_spot():
    """The gate reads package.json, so raw-HTTP integrations are invisible. That
    is a real limitation and it belongs in the report, not in a code comment."""
    assert any("raw HTTP" in limit for limit in RULE.limits)
