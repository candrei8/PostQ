"""Integration tests — full scan across all scanner types and languages."""

import json
from pathlib import Path

from quant_scan.core.context import ScanContext
from quant_scan.core.engine import ScanEngine
from quant_scan.core.enums import Severity

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def test_scan_all_fixtures():
    """Scan the entire fixtures directory and verify findings from multiple languages."""
    ctx = ScanContext(targets=[FIXTURES_DIR])
    engine = ScanEngine()
    result = engine.run(ctx)

    assert result.summary.total_findings > 10
    assert result.summary.score < 50

    # Should have findings from multiple files
    files_with_findings = {f.location.file_path for f in result.findings}
    assert len(files_with_findings) >= 2


def test_scan_java_fixture():
    """Scan Java fixture file."""
    ctx = ScanContext(targets=[FIXTURES_DIR / "vulnerable_java.java"])
    engine = ScanEngine()
    result = engine.run(ctx, scanner_names=["source"])

    assert result.summary.total_findings >= 5
    algos = {f.algorithm.name for f in result.findings}
    # Should detect at least RSA and MD5
    assert any("RSA" in a for a in algos) or any("MD5" in a for a in algos)


def test_scan_javascript_fixture():
    """Scan JavaScript fixture file."""
    ctx = ScanContext(targets=[FIXTURES_DIR / "vulnerable_javascript.js"])
    engine = ScanEngine()
    result = engine.run(ctx, scanner_names=["source"])

    assert result.summary.total_findings >= 5


def test_scan_go_fixture():
    """Scan Go fixture file."""
    ctx = ScanContext(targets=[FIXTURES_DIR / "vulnerable_go.go"])
    engine = ScanEngine()
    result = engine.run(ctx, scanner_names=["source"])

    assert result.summary.total_findings >= 5


def test_scan_cpp_fixture():
    """Scan C/C++ fixture file."""
    ctx = ScanContext(targets=[FIXTURES_DIR / "vulnerable_cpp.cpp"])
    engine = ScanEngine()
    result = engine.run(ctx, scanner_names=["source"])

    assert result.summary.total_findings >= 5


def test_scan_csharp_fixture():
    """Scan C# fixture file."""
    ctx = ScanContext(targets=[FIXTURES_DIR / "vulnerable_csharp.cs"])
    engine = ScanEngine()
    result = engine.run(ctx, scanner_names=["source"])

    assert result.summary.total_findings >= 5


def test_json_output_valid():
    """Verify JSON report is valid and parseable."""
    ctx = ScanContext(targets=[FIXTURES_DIR])
    engine = ScanEngine()
    result = engine.run(ctx)

    json_str = result.model_dump_json()
    data = json.loads(json_str)
    assert "findings" in data
    assert "summary" in data
    assert data["summary"]["total_findings"] == len(data["findings"])


def test_severity_filter_critical_only():
    """Verify severity filter works across all languages."""
    ctx = ScanContext(
        targets=[FIXTURES_DIR],
        min_severity=Severity.CRITICAL,
    )
    engine = ScanEngine()
    result = engine.run(ctx)

    for f in result.findings:
        assert f.severity == Severity.CRITICAL


def test_scan_nonexistent_path():
    """Verify graceful handling of nonexistent paths."""
    ctx = ScanContext(targets=[Path("/nonexistent/path")])
    engine = ScanEngine()
    result = engine.run(ctx)

    assert result.summary.total_findings == 0
