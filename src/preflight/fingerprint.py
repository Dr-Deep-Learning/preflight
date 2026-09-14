"""Stack fingerprinting.

Spec section 6: "Rules are gated on stack -- a Firebase app never sees an RLS
rule. This is what keeps false positives low and reports short."

The fingerprint is therefore not a nice-to-have label. It is the input to rule
selection, and it also decides which files count as client-reachable, which is
the whole basis of S2.
"""

from __future__ import annotations

import json
from pathlib import PurePosixPath

from preflight.ingest import FileIndex
from preflight.models import AuthProvider, Backend, Fingerprint, Framework, PaymentProvider

# Directories whose contents ship to the browser, per framework.
_NEXT_CLIENT_ROOTS = ("app", "src/app", "pages", "src/pages", "components", "src/components")
_VITE_CLIENT_ROOTS = ("src",)

# In Next.js these are server-only even though they live under a client root.
_NEXT_SERVER_MARKERS = (
    "/api/",
    "/route.ts",
    "/route.js",
    "/route.tsx",
    ".server.",
    "middleware.",
    "/actions.ts",
    "/actions.tsx",
)


def _load_package_json(index: FileIndex) -> dict[str, object]:
    for candidate in ("package.json", "app/package.json"):
        if index.exists(candidate):
            try:
                parsed = json.loads(index.read_text(candidate))
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return {}


def _dependencies(pkg: dict[str, object]) -> dict[str, str]:
    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        section = pkg.get(key)
        if isinstance(section, dict):
            for name, version in section.items():
                if isinstance(name, str):
                    deps[name] = str(version)
    return deps


def fingerprint_project(index: FileIndex) -> Fingerprint:
    pkg = _load_package_json(index)
    deps = _dependencies(pkg)
    evidence: list[str] = []

    def has(*names: str) -> bool:
        return any(n in deps for n in names)

    if has("next"):
        framework = Framework.NEXTJS
        evidence.append("package.json depends on next")
    elif has("@remix-run/react", "@remix-run/node"):
        framework = Framework.REMIX
        evidence.append("package.json depends on @remix-run")
    elif has("vite"):
        framework = Framework.VITE_REACT
        evidence.append("package.json depends on vite")
    else:
        framework = Framework.UNKNOWN

    if has("@supabase/supabase-js", "@supabase/ssr", "@supabase/auth-helpers-nextjs"):
        backend = Backend.SUPABASE
        evidence.append("package.json depends on @supabase/supabase-js")
    elif has("firebase", "firebase-admin"):
        backend = Backend.FIREBASE
        evidence.append("package.json depends on firebase")
    elif index.matching("supabase/migrations/*.sql", "supabase/config.toml"):
        backend = Backend.SUPABASE
        evidence.append("supabase/ directory present")
    elif index.named("firestore.rules", "firebase.json"):
        backend = Backend.FIREBASE
        evidence.append("firebase configuration files present")
    elif pkg:
        backend = Backend.NONE
    else:
        backend = Backend.UNKNOWN

    if has("@clerk/nextjs", "@clerk/clerk-react"):
        auth = AuthProvider.CLERK
    elif has("next-auth"):
        auth = AuthProvider.NEXTAUTH
    elif has("@auth0/auth0-react", "@auth0/nextjs-auth0"):
        auth = AuthProvider.AUTH0
    elif backend is Backend.SUPABASE:
        auth = AuthProvider.SUPABASE_AUTH
    elif backend is Backend.FIREBASE:
        auth = AuthProvider.FIREBASE_AUTH
    else:
        auth = AuthProvider.UNKNOWN

    if has("stripe", "@stripe/stripe-js"):
        payments = PaymentProvider.STRIPE
        evidence.append("package.json depends on stripe")
    elif has("@paddle/paddle-js"):
        payments = PaymentProvider.PADDLE
    else:
        payments = PaymentProvider.NONE

    prefixes: tuple[str, ...]
    globs: tuple[str, ...]
    if framework is Framework.NEXTJS:
        prefixes = ("NEXT_PUBLIC_",)
        globs = _NEXT_CLIENT_ROOTS
    elif framework is Framework.VITE_REACT:
        prefixes = ("VITE_",)
        globs = _VITE_CLIENT_ROOTS
    elif framework is Framework.REMIX:
        prefixes = ()
        globs = ("app",)
    else:
        prefixes = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_")
        globs = ("src", "app", "public", "components")

    return Fingerprint(
        framework=framework,
        backend=backend,
        auth=auth,
        payments=payments,
        client_env_prefixes=prefixes,
        client_globs=globs,
        evidence=tuple(evidence),
    )


def is_client_reachable(relpath: str, fingerprint: Fingerprint, *, content: str = "") -> bool:
    """Would this file's contents end up in a browser bundle?

    Cheap and conservative on purpose. Getting this wrong in the permissive
    direction produces a false positive on a server-only file, which spec
    section 11 calls the metric that matters most, so when in doubt we say no.
    """
    posix = PurePosixPath(relpath)
    if posix.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte", ".astro"}:
        return False

    normalised = "/" + relpath
    if any(marker in normalised for marker in _NEXT_SERVER_MARKERS):
        return False
    head = content[:400].lstrip()
    if head.startswith(('"use server"', "'use server'")):
        return False

    roots = fingerprint.client_globs or ("src",)
    return any(relpath == root or relpath.startswith(root + "/") for root in roots)
