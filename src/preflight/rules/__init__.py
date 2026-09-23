"""Rule package.

Importing this package is what populates the registry: each module's `@register`
decorator runs on import. Nothing else imports rules by name, so adding a check
means adding a module and one line here.
"""

from preflight.rules import (
    f1_row_level_security,
    f2_privileged_secrets,
    f3_committed_database,
    s1_webhook_verification,
    s2_client_side_keys,
)

__all__ = [
    "f1_row_level_security",
    "f2_privileged_secrets",
    "f3_committed_database",
    "s1_webhook_verification",
    "s2_client_side_keys",
]
