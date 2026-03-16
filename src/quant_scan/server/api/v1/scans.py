"""Scan endpoints — create and retrieve scans."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from quant_scan.core.context import ScanContext
from quant_scan.core.engine import ScanEngine
from quant_scan.core.enums import Severity
from quant_scan.server.api.v1 import router

# In-memory store (replace with DB in production)
_scan_store: dict[str, dict[str, Any]] = {}


class ScanRequest(BaseModel):
    """Request body for creating a scan."""

    targets: list[str] = Field(default_factory=lambda: ["."])
    severity: str = "info"
    exclude_patterns: list[str] = Field(default_factory=list)
    scanner_names: list[str] | None = None
    languages: list[str] = Field(default_factory=list)


class ScanStatus(BaseModel):
    """Status of a scan."""

    id: str
    status: str  # "pending", "running", "completed", "failed"
    created_at: str
    completed_at: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


def _run_scan_task(scan_id: str, request: ScanRequest) -> None:
    """Background task to run a scan."""
    try:
        _scan_store[scan_id]["status"] = "running"

        ctx = ScanContext(
            targets=[Path(t) for t in request.targets],
            exclude_patterns=request.exclude_patterns,
            min_severity=Severity(request.severity),
            languages=request.languages,
        )

        engine = ScanEngine()
        result = engine.run(ctx, scanner_names=request.scanner_names)

        _scan_store[scan_id]["status"] = "completed"
        _scan_store[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        _scan_store[scan_id]["result"] = result.model_dump(mode="json")

    except Exception as e:
        _scan_store[scan_id]["status"] = "failed"
        _scan_store[scan_id]["error"] = str(e)
        _scan_store[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()


@router.post("/scans", response_model=ScanStatus)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan (async)."""
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    _scan_store[scan_id] = {
        "id": scan_id,
        "status": "pending",
        "created_at": now,
        "completed_at": None,
        "result": None,
        "error": None,
    }

    background_tasks.add_task(_run_scan_task, scan_id, request)

    return ScanStatus(**_scan_store[scan_id])


@router.get("/scans/{scan_id}", response_model=ScanStatus)
async def get_scan(scan_id: str):
    """Get scan status and results."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatus(**_scan_store[scan_id])


@router.get("/scans", response_model=list[ScanStatus])
async def list_scans():
    """List all scans."""
    return [ScanStatus(**s) for s in _scan_store.values()]
