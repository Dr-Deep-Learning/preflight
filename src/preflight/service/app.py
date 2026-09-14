"""FastAPI application.

Endpoints are minimal on purpose: `POST /scans` starts one, `GET /scans/{id}`
reports on it, `GET /scans/{id}/report.html` renders it.

The one piece of real policy here is `PREFLIGHT_ALLOWED_ROOTS`. Spec section 6
makes ownership verification non-negotiable, and the honest version of that for a
local-directory scanner is that the service refuses to read outside directories
the operator configured. Without it set, the service accepts no targets at all --
failing closed, because the failure mode of failing open is scanning something
you do not own.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, Response
from pydantic import BaseModel, Field

import preflight.rules  # noqa: F401 - imported to populate the rule registry
from preflight import RULESET_VERSION, __version__
from preflight.engine import run_scan
from preflight.explain import StaticExplainer
from preflight.ingest import ScanTargetError, resolve_target
from preflight.models import ScanResult
from preflight.report import render_html
from preflight.service.store import InMemoryScanStore, ScanRecord, ScanState, ScanStore

app = FastAPI(
    title="Preflight",
    version=__version__,
    summary="Pre-launch security review for AI-built applications.",
)

STORE: ScanStore = InMemoryScanStore()


def allowed_roots() -> list[Path]:
    raw = os.environ.get("PREFLIGHT_ALLOWED_ROOTS", "")
    return [Path(part) for part in raw.split(os.pathsep) if part.strip()]


class ScanRequest(BaseModel):
    path: str = Field(description="Directory to scan, inside a configured allowed root.")


class ScanCreated(BaseModel):
    scan_id: str
    state: ScanState
    target: str


class ScanStatus(BaseModel):
    scan_id: str
    state: ScanState
    target: str
    error: str | None = None
    result: ScanResult | None = None


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__, "ruleset": RULESET_VERSION}


@app.get("/rules")
def rules() -> dict[str, object]:
    from preflight.engine import REGISTRY

    return {
        "ruleset_version": RULESET_VERSION,
        "rules": [
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity.value,
                "limits": list(rule.limits),
            }
            for rule in REGISTRY
        ],
    }


@app.post("/scans", response_model=ScanCreated, status_code=202)
def create_scan(request: ScanRequest, background: BackgroundTasks) -> ScanCreated:
    roots = allowed_roots()
    if not roots:
        raise HTTPException(
            status_code=503,
            detail=(
                "PREFLIGHT_ALLOWED_ROOTS is not configured; this service will not scan "
                "an unconstrained path."
            ),
        )
    try:
        target = resolve_target(request.path, roots)
    except ScanTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan_id = uuid.uuid4().hex[:12]
    STORE.put(ScanRecord(scan_id=scan_id, target=str(target)))
    background.add_task(_run, scan_id, target)
    return ScanCreated(scan_id=scan_id, state=ScanState.QUEUED, target=str(target))


@app.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan(scan_id: str) -> ScanStatus:
    record = _require(scan_id)
    return ScanStatus(
        scan_id=record.scan_id,
        state=record.state,
        target=record.target,
        error=record.error,
        result=record.result,
    )


@app.get("/scans/{scan_id}/report.html", response_class=Response)
def get_report(scan_id: str) -> Response:
    record = _require(scan_id)
    if record.result is None:
        raise HTTPException(status_code=409, detail=f"scan is {record.state.value}")
    return Response(content=render_html(record.result), media_type="text/html")


def _require(scan_id: str) -> ScanRecord:
    record = STORE.get(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="no such scan")
    return record


def _run(scan_id: str, target: Path) -> None:
    record = ScanRecord(scan_id=scan_id, target=str(target), state=ScanState.RUNNING)
    STORE.put(record)
    try:
        result = run_scan(target, explainer=StaticExplainer(), scan_id=scan_id)
    except Exception as exc:
        STORE.put(
            ScanRecord(scan_id=scan_id, target=str(target), state=ScanState.FAILED, error=str(exc))
        )
        return
    STORE.put(
        ScanRecord(scan_id=scan_id, target=str(target), state=ScanState.COMPLETE, result=result)
    )
