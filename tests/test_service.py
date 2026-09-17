"""HTTP surface, including the guardrail that it fails closed."""

import os

import pytest
from fastapi.testclient import TestClient

from conftest import CLEAN, FIXTURES, VULNERABLE
from preflight.service.app import app


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PREFLIGHT_ALLOWED_ROOTS", str(FIXTURES))
    return TestClient(app)


@pytest.fixture
def unconfigured_client(monkeypatch):
    monkeypatch.delenv("PREFLIGHT_ALLOWED_ROOTS", raising=False)
    return TestClient(app)


def test_health(client):
    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    assert body["ruleset"]


def test_rules_endpoint_publishes_the_ruleset(client):
    body = client.get("/rules").json()
    assert [r["id"] for r in body["rules"]] == ["F1", "F2", "S1", "S2"]
    assert all(r["limits"] for r in body["rules"])


def test_scan_runs_and_can_be_fetched(client):
    created = client.post("/scans", json={"path": str(VULNERABLE)})
    assert created.status_code == 202
    scan_id = created.json()["scan_id"]

    status = client.get(f"/scans/{scan_id}").json()
    assert status["state"] == "complete"
    assert status["result"]["verdict"]["headline"] == "Not safe to launch"


def test_clean_project_reports_clean(client):
    scan_id = client.post("/scans", json={"path": str(CLEAN)}).json()["scan_id"]
    assert client.get(f"/scans/{scan_id}").json()["result"]["verdict"]["headline"] == "Clean"


def test_html_report_is_served(client):
    scan_id = client.post("/scans", json={"path": str(VULNERABLE)}).json()["scan_id"]
    response = client.get(f"/scans/{scan_id}/report.html")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Preflight report" in response.text


def test_a_path_outside_the_allowed_roots_is_refused(client):
    response = client.post("/scans", json={"path": str(os.sep)})
    assert response.status_code == 400
    assert "outside the allowed scan roots" in response.json()["detail"]


def test_the_service_fails_closed_when_unconfigured(unconfigured_client):
    """No allowed roots means no scanning at all. Failing open would mean scanning
    directories the operator never agreed to read."""
    response = unconfigured_client.post("/scans", json={"path": str(VULNERABLE)})
    assert response.status_code == 503


def test_unknown_scan_is_404(client):
    assert client.get("/scans/deadbeef").status_code == 404
