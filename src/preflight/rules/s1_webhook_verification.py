"""S1 -- payment webhook signature verification.

Spec section 5, Tier 2: "Stripe/Paddle webhook handlers that don't verify
signatures."

A webhook endpoint is a URL on your server that anyone on the internet can POST
to. Stripe signs every request it sends; verifying that signature is the only
thing separating "Stripe told me this order was paid" from "somebody told me this
order was paid". A handler that parses the body without verifying will believe a
forged `checkout.session.completed` and hand out the goods.

Why this rule is shaped differently from F1, F2 and S2
------------------------------------------------------

Those three detect the **presence** of something -- a key is in this file, a table
is created without protection. Presence is easy to evidence: you point at a line
number and the reader sees it.

This one detects an **absence**, and an absence has two ways to be wrong. We have
to be right that this file is a webhook handler, *and* right that nothing
anywhere verifies the signature. Two inferences, not one.

That drives three decisions:

* **The candidate test is narrow.** A file only qualifies if it is server-side,
  references a payment SDK, *and* either lives at a path containing "webhook" or
  reads a signature header. Anything less specific starts reporting ordinary
  server code.
* **Every finding is UNVERIFIED.** Verification may legitimately live in
  middleware, a shared wrapper, or a framework plugin in another file, and this
  rule reads one file at a time. Saying "check this" is the honest claim; saying
  "you are vulnerable" would be the false positive spec section 11 calls the
  metric that matters most.
* **The blind spots are declared in `limits`** and print in the report, because a
  rule that cannot see middleware should say so rather than let a reader assume
  it did.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import PurePosixPath

from preflight.engine import Applicability, ScanContext, register
from preflight.fingerprint import is_client_reachable
from preflight.models import (
    BlastRadius,
    Confidence,
    Evidence,
    Finding,
    PaymentProvider,
    Remediation,
    Severity,
)

_HANDLER_SUFFIXES = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"})

#: The file talks to a payment provider at all.
_PROVIDER = re.compile(
    r"""
      from\s+['"]stripe['"]
    | require\(\s*['"]stripe['"]\s*\)
    | ^\s*import\s+stripe\b
    | new\s+Stripe\s*\(
    | \bstripe\.
    | @paddle/paddle-node-sdk
    | \bpaddle\.
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)

#: The file reads the header a provider signs its requests with.
_SIGNATURE_HEADER = re.compile(r"stripe-signature|paddle-signature|svix-signature", re.IGNORECASE)

#: Something in this file actually checks the signature.
#:
#: `constructEvent` and `construct_event` are Stripe's own verifiers; `unmarshal`
#: is Paddle's. `timingSafeEqual` and `compare_digest` catch a correctly
#: hand-rolled HMAC comparison, which is unusual but legitimate -- and a rule that
#: only recognised the SDK call would report those as vulnerable.
_VERIFICATION = re.compile(
    r"""
      constructEvent(?:Async)?
    | construct_event
    | Webhook\.construct
    | verifyWebhookSignature
    | webhooks?\.unmarshal
    | \bunmarshal\s*\(
    | timingSafeEqual
    | compare_digest
    """,
    re.IGNORECASE | re.VERBOSE,
)

#: Where the request body is consumed. Used only to point the evidence somewhere
#: useful -- this is the line a reader needs to look at.
_BODY_READ = re.compile(
    r"""
      req(?:uest)?\.body
    | req(?:uest)?\.(?:text|json)\s*\(\s*\)
    | request\.data\b
    | JSON\.parse\s*\(
    """,
    re.IGNORECASE | re.VERBOSE,
)

_MAX_SNIPPET = 160


def _trim(line: str) -> str:
    cleaned = line.strip()
    return cleaned if len(cleaned) <= _MAX_SNIPPET else cleaned[: _MAX_SNIPPET - 1] + "…"


def _evidence_line(text: str) -> tuple[int, str]:
    """The most useful line to show: where the body is trusted, else the first
    provider reference, else the top of the file."""
    for pattern in (_BODY_READ, _PROVIDER):
        match = pattern.search(text)
        if match is not None:
            number = text.count("\n", 0, match.start()) + 1
            lines = text.splitlines()
            return number, _trim(lines[number - 1]) if number <= len(lines) else ""
    return 1, ""


@register
class UnverifiedPaymentWebhook:
    id: str = "S1"
    title: str = "Payment webhook signature verification"
    severity: Severity = Severity.SERIOUS
    applicability: Applicability = Applicability(
        payments=frozenset({PaymentProvider.STRIPE, PaymentProvider.PADDLE})
    )
    limits: tuple[str, ...] = (
        "Only Stripe and Paddle webhook handlers are recognised. A provider called over "
        "raw HTTP with no SDK dependency declared is not checked at all.",
        "Signature verification performed in middleware, a shared wrapper, or a framework "
        "plugin in another file is not visible to this check, which reads one file at a "
        "time. That is why these findings are reported as unverified.",
    )

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        unverified: list[Evidence] = []

        for path in sorted(ctx.index.paths):
            if PurePosixPath(path).suffix.lower() not in _HANDLER_SUFFIXES:
                continue
            text = ctx.read(path)
            if not text:
                continue
            if is_client_reachable(path, ctx.fingerprint, content=text):
                continue  # a browser file is not a webhook endpoint
            if not _PROVIDER.search(text):
                continue
            looks_like_handler = "webhook" in path.lower() or bool(_SIGNATURE_HEADER.search(text))
            if not looks_like_handler:
                continue
            if _VERIFICATION.search(text):
                continue

            number, snippet = _evidence_line(text)
            unverified.append(
                Evidence(
                    path=path,
                    line=number,
                    snippet=snippet,
                    note=(
                        "the request body is used without any signature check in this file"
                        if snippet
                        else "no signature verification found in this file"
                    ),
                )
            )

        if not unverified:
            return

        count = len(unverified)
        yield Finding(
            rule_id=self.id,
            title=(
                f"{count} payment webhook handler{'s' if count != 1 else ''} "
                "may accept forged requests"
            ),
            severity=Severity.SERIOUS,
            confidence=Confidence.UNVERIFIED,
            summary=(
                "Your webhook endpoint is a public URL: anyone on the internet can send it a "
                "request that looks exactly like one from Stripe. Stripe signs every request "
                "it sends, and this handler never checks that signature, so a forged "
                "`checkout.session.completed` would be believed — a subscription granted, or "
                "an order marked paid, without any money moving. We could not see verification "
                "in this file, but it may live in middleware you call elsewhere; confirm before "
                "you act."
            ),
            blast_radius=BlastRadius.BROAD,
            evidence=unverified,
            remediation=Remediation(
                fix=(
                    "1. In the Stripe dashboard, open Developers → Webhooks → your endpoint and "
                    "copy the signing secret. Store it server-side as `STRIPE_WEBHOOK_SECRET` — "
                    "never with a NEXT_PUBLIC_ or VITE_ prefix.\n"
                    "2. Verify before you trust anything in the body:\n\n"
                    "const sig = req.headers['stripe-signature'];\n"
                    "let event;\n"
                    "try {\n"
                    "  event = stripe.webhooks.constructEvent(\n"
                    "    rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);\n"
                    "} catch {\n"
                    "  return res.status(400).send('bad signature');\n"
                    "}\n\n"
                    "3. Pass the RAW request body, not a parsed object. Most frameworks parse "
                    "JSON for you and that breaks the signature — in Next.js route handlers use "
                    "`await request.text()`; in Express mount `express.raw({type: 'application/"
                    "json'})` on this route only.\n"
                    "4. Use `event` from that call for the rest of the handler, and never the "
                    "body you parsed yourself.\n"
                    "5. For Paddle, the equivalent is `paddle.webhooks.unmarshal(rawBody, "
                    "secret, signature)`."
                ),
                verify=(
                    "Send your endpoint a request with no signature header — it must be "
                    "rejected and nothing in your database may change:\n\n"
                    "curl -i -X POST https://your-app/api/webhook \\\n"
                    "  -H 'content-type: application/json' \\\n"
                    '  -d \'{"type":"checkout.session.completed"}\'\n\n'
                    "You want a 400. Then confirm real events still work with "
                    "`stripe trigger checkout.session.completed` from the Stripe CLI."
                ),
            ),
        )
