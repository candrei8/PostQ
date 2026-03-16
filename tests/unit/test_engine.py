"""Tests for the scan engine."""

from quant_scan.core.context import ScanContext
from quant_scan.core.engine import ScanEngine
from quant_scan.core.enums import Severity


def test_engine_scan_vulnerable(vulnerable_python_path):
    ctx = ScanContext(targets=[vulnerable_python_path])
    engine = ScanEngine()
    result = engine.run(ctx, scanner_names=["source"])

    assert result.summary.total_findings > 5
    assert result.summary.score < 100
    assert result.summary.grade != "A"
    assert result.duration_seconds >= 0


def test_engine_scan_safe(safe_python_path):
    ctx = ScanContext(targets=[safe_python_path])
    engine = ScanEngine()
    result = engine.run(ctx, scanner_names=["source"])

    assert result.summary.total_findings == 0
    assert result.summary.score == 100.0
    assert result.summary.grade == "A"


def test_engine_severity_filter(vulnerable_python_path):
    ctx = ScanContext(
        targets=[vulnerable_python_path],
        min_severity=Severity.HIGH,
    )
    engine = ScanEngine()
    result = engine.run(ctx, scanner_names=["source"])

    for f in result.findings:
        assert f.severity in (Severity.CRITICAL, Severity.HIGH)


def test_engine_scan_directory(fixtures_dir):
    ctx = ScanContext(targets=[fixtures_dir])
    engine = ScanEngine()
    result = engine.run(ctx, scanner_names=["source"])

    # Should find issues in vulnerable but not in safe
    assert result.summary.total_findings > 0
    vuln_files = {f.location.file_path for f in result.findings}
    assert any("vulnerable" in p for p in vuln_files)
    assert not any("safe_python" in p for p in vuln_files)
