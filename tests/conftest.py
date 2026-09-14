"""Shared test fixtures.

Every assertion in this suite runs against the two applications in `fixtures/`.
That is deliberate: mocking the file system would let a rule pass its tests while
failing on the shape of code it will actually meet.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import preflight.rules  # noqa: F401 - populates the registry
from preflight.engine import ScanContext, run_scan
from preflight.fingerprint import fingerprint_project
from preflight.ingest import LocalDirectorySource, read_git_info
from preflight.models import ScanResult

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULNERABLE = FIXTURES / "vulnerable-app"
CLEAN = FIXTURES / "clean-app"

SERVICE_ROLE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByZWZsaWdodGZpeHR1cmUiLCJyb2xlIjoic2VydmljZV9yb2xl"
    "IiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjE4OTM0NTYwMDB9."
    "PREFLIGHTfixtureSIGNATUREnotVALIDservice_role"
)
ANON_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByZWZsaWdodGZpeHR1cmUiLCJyb2xlIjoiYW5vbiIsImlhdCI6"
    "MTczNTY4OTYwMCwiZXhwIjoxODkzNDU2MDAwfQ."
    "PREFLIGHTfixtureSIGNATUREnotVALIDanon"
)


def context_for(path: Path) -> ScanContext:
    root, index, git = LocalDirectorySource(root=path).load()
    return ScanContext(root=root, index=index, git=git, fingerprint=fingerprint_project(index))


@pytest.fixture(scope="session")
def vulnerable_scan() -> ScanResult:
    return run_scan(VULNERABLE)


@pytest.fixture(scope="session")
def clean_scan() -> ScanResult:
    return run_scan(CLEAN)


@pytest.fixture
def vulnerable_ctx() -> ScanContext:
    return context_for(VULNERABLE)


@pytest.fixture
def clean_ctx() -> ScanContext:
    return context_for(CLEAN)


@pytest.fixture
def git_project(tmp_path: Path) -> Path:
    """A real git repository with a real committed .env.

    The tracked/untracked distinction is the whole basis of F2's confirmed
    finding, so it is tested against git itself rather than a stubbed answer.
    """
    (tmp_path / "package.json").write_text('{"dependencies": {"vite": "^5.0.0"}}')
    (tmp_path / ".env").write_text(f"SUPABASE_SERVICE_ROLE_KEY={SERVICE_ROLE_JWT}\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A", "-f"], cwd=tmp_path, check=True)
    assert read_git_info(tmp_path).is_tracked(".env") is True
    return tmp_path
