"""Report endpoints — generate reports from scan results."""
from __future__ import annotations

from fastapi import HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from quant_scan.core.models import ScanResult
from quant_scan.reports.generator import generate_report
from quant_scan.server.api.v1 import router
from quant_scan.server.api.v1.scans import _scan_store


@router.get("/scans/{scan_id}/report/{format}")
async def get_report(scan_id: str, format: str):
    """Generate a report for a completed scan."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = _scan_store[scan_id]
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail=f"Scan is {scan['status']}, not completed")

    if scan["result"] is None:
        raise HTTPException(status_code=400, detail="No results available")

    result = ScanResult.model_validate(scan["result"])
    report_text = generate_report(result, format)

    if format == "html" or format == "pdf":
        return HTMLResponse(content=report_text)
    elif format == "json" or format == "cbom":
        import json
        return JSONResponse(content=json.loads(report_text))
    else:
        return {"report": report_text}


@router.get("/scans/{scan_id}/migration")
async def get_migration_plan(scan_id: str, organization: str = "", hourly_rate: float = 150.0):
    """Generate a migration plan from scan results."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = _scan_store[scan_id]
    if scan["status"] != "completed" or scan["result"] is None:
        raise HTTPException(status_code=400, detail="Scan not completed")

    result = ScanResult.model_validate(scan["result"])

    from quant_scan.migration.planner import generate_migration_plan
    plan = generate_migration_plan(result, organization=organization, hourly_rate=hourly_rate)
    return plan.model_dump(mode="json")


@router.get("/scans/{scan_id}/compliance/gaps")
async def get_compliance_gaps(scan_id: str):
    """Get compliance gap analysis for a scan."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = _scan_store[scan_id]
    if scan["status"] != "completed" or scan["result"] is None:
        raise HTTPException(status_code=400, detail="Scan not completed")

    result = ScanResult.model_validate(scan["result"])

    from quant_scan.compliance.gap_analysis import analyze_compliance_gaps
    gaps = analyze_compliance_gaps(result)
    return gaps.model_dump(mode="json")
