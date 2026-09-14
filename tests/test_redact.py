from conftest import SERVICE_ROLE_JWT
from preflight.redact import redact_in_line, redact_secret


def test_redaction_keeps_a_recognisable_stub():
    redacted = redact_secret("sk-preflightFIXTUREkeyDoNotUse7f3a91c4b8e2d6")
    assert redacted.startswith("sk-p")
    assert "FIXTURE" not in redacted


def test_short_values_are_removed_entirely():
    assert redact_secret("abc123") == "[redacted 6 chars]"


def test_the_secret_never_survives_into_a_snippet():
    line = f'  const SUPABASE_KEY = "{SERVICE_ROLE_JWT}";'
    snippet = redact_in_line(line, SERVICE_ROLE_JWT)
    assert SERVICE_ROLE_JWT not in snippet
    assert "SUPABASE_KEY" in snippet
