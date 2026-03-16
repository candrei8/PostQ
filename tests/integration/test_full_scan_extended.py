"""Extended integration tests -- full scans with new scanners."""
from __future__ import annotations

from pathlib import Path

import pytest

from quant_scan.core.context import ScanContext
from quant_scan.core.engine import ScanEngine


FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_full_scan_all_scanners():
    """Full scan with all registered scanners should find findings."""
    ctx = ScanContext(targets=[FIXTURES])
    engine = ScanEngine()
    result = engine.run(ctx)
    assert result.summary.total_findings > 100
    scanners_used = {f.scanner_type for f in result.findings}
    assert "source" in scanners_used


def test_scan_with_quality_gate():
    """Scan results should work with quality gate evaluation."""
    from quant_scan.cicd.quality_gate import QualityGate
    ctx = ScanContext(targets=[FIXTURES])
    engine = ScanEngine()
    result = engine.run(ctx)
    gate = QualityGate(min_score=70)
    gr = gate.evaluate(result)
    assert gr.passed is False  # Fixtures are intentionally vulnerable


def test_scan_with_migration_plan():
    """Scan results should produce a migration plan."""
    from quant_scan.migration.planner import generate_migration_plan
    ctx = ScanContext(targets=[FIXTURES])
    engine = ScanEngine()
    result = engine.run(ctx)
    plan = generate_migration_plan(result, organization="Test", hourly_rate=100)
    assert plan.total_tasks > 0
    assert plan.total_estimated_hours > 0


def test_scan_with_cbom():
    """Scan results should produce a valid CBOM."""
    from quant_scan.cbom.generator import generate_cbom
    ctx = ScanContext(targets=[FIXTURES])
    engine = ScanEngine()
    result = engine.run(ctx)
    cbom = generate_cbom(result)
    assert cbom.total_algorithms > 0
    assert cbom.vulnerable_count > 0


def test_scan_with_gap_analysis():
    """Scan results should produce gap analysis."""
    from quant_scan.compliance.gap_analysis import analyze_compliance_gaps
    ctx = ScanContext(targets=[FIXTURES])
    engine = ScanEngine()
    result = engine.run(ctx)
    gaps = analyze_compliance_gaps(result)
    assert len(gaps.frameworks) > 0
    assert gaps.total_gaps > 0


def test_scan_sarif_output():
    """SARIF output should be valid JSON."""
    import json
    from quant_scan.reports.formats.sarif_report import render_sarif
    ctx = ScanContext(targets=[FIXTURES])
    engine = ScanEngine()
    result = engine.run(ctx)
    sarif = render_sarif(result)
    data = json.loads(sarif)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) > 0


def test_scan_pdf_output():
    """PDF HTML output should contain key sections."""
    from quant_scan.reports.formats.pdf_report import render_pdf_html
    ctx = ScanContext(targets=[FIXTURES])
    engine = ScanEngine()
    result = engine.run(ctx)
    html = render_pdf_html(result)
    assert "<html" in html
    assert "Findings" in html or "Hallazgos" in html


def test_scan_terraform_fixture():
    """IaC scanner should detect Terraform findings."""
    tf_file = FIXTURES / "sample.tf"
    if not tf_file.exists():
        pytest.skip("sample.tf not found")
    ctx = ScanContext(targets=[tf_file])
    engine = ScanEngine()
    result = engine.run(ctx, scanner_names=["iac"])
    iac_findings = [f for f in result.findings if f.scanner_type == "iac"]
    assert len(iac_findings) > 0
