from preflight.fingerprint import is_client_reachable
from preflight.models import AuthProvider, Backend, Framework, PaymentProvider


def test_vite_supabase_app_is_identified(vulnerable_ctx):
    fp = vulnerable_ctx.fingerprint
    assert fp.framework is Framework.VITE_REACT
    assert fp.backend is Backend.SUPABASE
    assert fp.auth is AuthProvider.SUPABASE_AUTH
    assert fp.client_env_prefixes == ("VITE_",)


def test_next_supabase_app_is_identified(clean_ctx):
    fp = clean_ctx.fingerprint
    assert fp.framework is Framework.NEXTJS
    assert fp.backend is Backend.SUPABASE
    assert fp.payments is PaymentProvider.STRIPE


def test_vite_src_is_client_reachable(vulnerable_ctx):
    fp = vulnerable_ctx.fingerprint
    assert is_client_reachable("src/components/Chat.tsx", fp)
    assert not is_client_reachable("api/webhook.js", fp)
    assert not is_client_reachable("supabase/migrations/0001_init.sql", fp)


def test_next_route_handlers_are_not_client_reachable(clean_ctx):
    fp = clean_ctx.fingerprint
    assert is_client_reachable("components/SupabaseProvider.tsx", fp)
    assert not is_client_reachable("app/api/checkout/route.ts", fp)


def test_use_server_directive_marks_a_file_server_only(clean_ctx):
    assert not is_client_reachable(
        "components/actions.tsx", clean_ctx.fingerprint, content='"use server";\nexport {}'
    )
