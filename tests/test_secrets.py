from conftest import ANON_JWT, SERVICE_ROLE_JWT
from preflight.rules.secrets import SecretKind, iter_secret_matches


def test_service_role_jwt_is_recognised_by_its_payload():
    matches = list(iter_secret_matches(f"const key = '{SERVICE_ROLE_JWT}';"))
    assert [m.pattern.id for m in matches] == ["supabase-service-role"]
    assert matches[0].pattern.kind is SecretKind.PRIVILEGED


def test_anon_jwt_is_not_a_finding():
    """The anon key is published on purpose. Shape alone must not condemn it."""
    assert list(iter_secret_matches(f"const key = '{ANON_JWT}';")) == []


def test_placeholders_are_ignored():
    text = "\n".join(
        [
            "SUPABASE_SERVICE_ROLE_KEY=your-service-role-key",
            "OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "DATABASE_URL=postgresql://postgres:${DB_PASSWORD}@db.example.co:5432/postgres",
        ]
    )
    assert list(iter_secret_matches(text)) == []


def test_anthropic_key_wins_over_the_generic_openai_shape():
    matches = list(iter_secret_matches("key = 'sk-ant-api03-preflightFIXTURE7f3a91c4b8e2d6xyz'"))
    assert [m.pattern.id for m in matches] == ["anthropic-api-key"]


def test_line_numbers_are_reported():
    text = "line one\nline two\nkey = 'sk-preflightFIXTUREkeyDoNotUse7f3a91c4b8e2d6'\n"
    (match,) = list(iter_secret_matches(text))
    assert match.line_number == 3


def test_kind_filter_narrows_the_catalogue():
    text = f"a = '{SERVICE_ROLE_JWT}'\nb = 'sk-preflightFIXTUREkeyDoNotUse7f3a91c4b8e2d6'"
    privileged = list(iter_secret_matches(text, kinds=frozenset({SecretKind.PRIVILEGED})))
    assert [m.pattern.id for m in privileged] == ["supabase-service-role"]
