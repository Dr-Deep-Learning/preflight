"""Scan storage.

In-memory and deliberately behind an interface. Spec section 6 says findings are
stored and code is not, so whatever replaces this (Postgres, DynamoDB) stores
`ScanResult` objects only -- never the project it read.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from preflight.models import ScanResult


class ScanState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class ScanRecord:
    scan_id: str
    target: str
    state: ScanState = ScanState.QUEUED
    result: ScanResult | None = None
    error: str | None = None


class ScanStore(Protocol):
    def put(self, record: ScanRecord) -> None: ...
    def get(self, scan_id: str) -> ScanRecord | None: ...


@dataclass
class InMemoryScanStore:
    _records: dict[str, ScanRecord] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def put(self, record: ScanRecord) -> None:
        with self._lock:
            self._records[record.scan_id] = record

    def get(self, scan_id: str) -> ScanRecord | None:
        with self._lock:
            return self._records.get(scan_id)
