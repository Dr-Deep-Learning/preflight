"""The credential pattern catalogue shared by F2 and S2.

Two design decisions here are the difference between a useful scanner and a noisy
one:

* **Kind, not just shape.** A Supabase service-role key and a Google Maps key are
  both "a secret in the repo", but one is total compromise and the other is a
  billing incident. The kind drives which rule owns the match and what severity
  it carries.
* **Validators, not longer regexes.** Anything shaped like a JWT matches the
  Supabase pattern; only a JWT whose payload actually says `"role":"service_role"`
  is reported. Cheap semantic confirmation is what lets us claim a finding is
  confirmed rather than inferred.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum

from preflight.models import BlastRadius


class SecretKind(StrEnum):
    #: Bypasses access control or moves money. Fatal wherever it appears.
    PRIVILEGED = "privileged"
    #: Third-party vendor key. Serious when it is reachable from the browser.
    THIRD_PARTY = "third-party"


# Strings that look like credentials but are placeholders. "example" is
# deliberately absent: real leaked keys frequently contain it, and the fixture
# corpus relies on shape matching rather than an allowlist hole.
_PLACEHOLDER_MARKERS = (
    "your-",
    "your_",
    "yourkey",
    "<",
    "${",
    "process.env",
    "import.meta.env",
    "changeme",
    "replace-me",
    "placeholder",
    "xxxxxxxx",
    "todo",
    "0000000000000000000000000000",
)


def _decode_jwt_payload(token: str) -> dict[str, object] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload)
        parsed = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _is_service_role_jwt(token: str) -> bool:
    payload = _decode_jwt_payload(token)
    return bool(payload) and payload is not None and payload.get("role") == "service_role"


def _is_anon_jwt(token: str) -> bool:
    payload = _decode_jwt_payload(token)
    return bool(payload) and payload is not None and payload.get("role") == "anon"


@dataclass(frozen=True)
class SecretPattern:
    id: str
    label: str
    vendor: str
    kind: SecretKind
    regex: re.Pattern[str]
    consequence: str
    #: How much is exposed if this key leaks. Lives here, next to the sentence
    #: that explains it, so the two cannot drift -- and so no rule has to keep a
    #: private table of severities for the same catalogue.
    blast_radius: BlastRadius
    validator: Callable[[str], bool] | None = None

    def confirm(self, value: str) -> bool:
        return self.validator is None or self.validator(value)


_JWT = r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"

PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        id="supabase-service-role",
        label="Supabase service-role key",
        vendor="supabase",
        kind=SecretKind.PRIVILEGED,
        blast_radius=BlastRadius.TOTAL,
        regex=re.compile(_JWT),
        validator=_is_service_role_jwt,
        consequence=(
            "The service-role key bypasses row-level security entirely. Anyone holding it "
            "can read, edit and delete every row in your database."
        ),
    ),
    SecretPattern(
        id="postgres-connection-string",
        label="Postgres connection string with a password",
        vendor="postgres",
        kind=SecretKind.PRIVILEGED,
        blast_radius=BlastRadius.TOTAL,
        regex=re.compile(r"postgres(?:ql)?://[^\s:@'\"]+:[^\s@'\"]{4,}@[^\s'\"/]+"),
        consequence=(
            "Direct database access with whatever rights that role has, bypassing your app."
        ),
    ),
    SecretPattern(
        id="stripe-secret-key",
        label="Stripe secret key",
        vendor="stripe",
        kind=SecretKind.PRIVILEGED,
        blast_radius=BlastRadius.TOTAL,
        regex=re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{16,}"),
        consequence="Full API access to your Stripe account: refunds, charges, customer records.",
    ),
    SecretPattern(
        id="aws-access-key-id",
        label="AWS access key id",
        vendor="aws",
        kind=SecretKind.PRIVILEGED,
        # BROAD rather than TOTAL: what an AWS key reaches depends entirely on
        # its IAM policy, which we cannot see. Claiming total compromise would
        # be a guess dressed as a finding.
        blast_radius=BlastRadius.BROAD,
        regex=re.compile(r"AKIA[0-9A-Z]{16}"),
        consequence="Programmatic access to whatever the key's IAM policy allows.",
    ),
    SecretPattern(
        id="private-key-block",
        label="PEM private key",
        vendor="generic",
        kind=SecretKind.PRIVILEGED,
        blast_radius=BlastRadius.TOTAL,
        regex=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        consequence=(
            "A signing or service-account key. For a Firebase admin credential this is "
            "total database access."
        ),
    ),
    SecretPattern(
        id="anthropic-api-key",
        label="Anthropic API key",
        vendor="anthropic",
        kind=SecretKind.THIRD_PARTY,
        blast_radius=BlastRadius.BROAD,
        regex=re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
        consequence=(
            "Anyone can spend your model budget. This is the surprise-invoice class of leak."
        ),
    ),
    SecretPattern(
        id="openai-style-api-key",
        label="OpenAI-style API key",
        vendor="openai",
        kind=SecretKind.THIRD_PARTY,
        blast_radius=BlastRadius.BROAD,
        regex=re.compile(r"sk-(?!ant-)[A-Za-z0-9](?:[A-Za-z0-9_-]{19,})"),
        consequence=(
            "Anyone can spend your model budget. This is the surprise-invoice class of leak."
        ),
    ),
    SecretPattern(
        id="google-api-key",
        label="Google API key",
        vendor="google",
        kind=SecretKind.THIRD_PARTY,
        # Usually domain-restricted and quota-capped on the provider's side, so
        # the realistic damage is smaller than an uncapped model key.
        blast_radius=BlastRadius.CONTAINED,
        regex=re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        consequence="Maps and Places calls billed to you, unless the key is domain-restricted.",
    ),
    SecretPattern(
        id="sendgrid-api-key",
        label="SendGrid API key",
        vendor="sendgrid",
        kind=SecretKind.THIRD_PARTY,
        blast_radius=BlastRadius.BROAD,
        regex=re.compile(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
        consequence=(
            "Someone else can send mail as your domain, which also burns your sending reputation."
        ),
    ),
    SecretPattern(
        id="resend-api-key",
        label="Resend API key",
        vendor="resend",
        kind=SecretKind.THIRD_PARTY,
        blast_radius=BlastRadius.BROAD,
        regex=re.compile(r"re_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}"),
        consequence="Someone else can send mail as your domain.",
    ),
    SecretPattern(
        id="twilio-api-key",
        label="Twilio API key",
        vendor="twilio",
        kind=SecretKind.THIRD_PARTY,
        blast_radius=BlastRadius.BROAD,
        regex=re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        consequence="Outbound SMS billed to you.",
    ),
)

#: Not a leak, but worth recognising so we never mistake it for one.
SUPABASE_ANON_JWT = SecretPattern(
    id="supabase-anon-key",
    label="Supabase anon key",
    vendor="supabase",
    kind=SecretKind.THIRD_PARTY,
    blast_radius=BlastRadius.CONTAINED,
    regex=re.compile(_JWT),
    validator=_is_anon_jwt,
    consequence="Safe in the browser by design -- but only while row-level security is enabled.",
)


@dataclass(frozen=True)
class SecretMatch:
    pattern: SecretPattern
    value: str
    line_number: int
    line: str


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def iter_secret_matches(
    text: str,
    *,
    kinds: frozenset[SecretKind] | None = None,
    patterns: tuple[SecretPattern, ...] = PATTERNS,
) -> Iterator[SecretMatch]:
    """Yield confirmed credential matches, most specific pattern first.

    Overlapping spans are reported once: a `sk-ant-...` key is an Anthropic key,
    not also a generic OpenAI-style one.
    """
    claimed: list[tuple[int, int]] = []
    line_starts = _line_starts(text)
    for pattern in patterns:
        if kinds is not None and pattern.kind not in kinds:
            continue
        for match in pattern.regex.finditer(text):
            span = match.span()
            if any(span[0] < end and start < span[1] for start, end in claimed):
                continue
            value = match.group(0)
            if _looks_like_placeholder(value) or not pattern.confirm(value):
                continue
            claimed.append(span)
            number = _line_number(line_starts, span[0])
            yield SecretMatch(
                pattern=pattern,
                value=value,
                line_number=number,
                line=text.splitlines()[number - 1] if text else "",
            )


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            starts.append(index + 1)
    return starts


def _line_number(line_starts: list[int], offset: int) -> int:
    low, high = 0, len(line_starts) - 1
    while low < high:
        mid = (low + high + 1) // 2
        if line_starts[mid] <= offset:
            low = mid
        else:
            high = mid - 1
    return low + 1
