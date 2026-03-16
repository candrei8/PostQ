"""Tests for scan comparison."""
from __future__ import annotations

from quant_scan.comparison.differ import compare_scans
from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding, ScanResult, ScanSummary


def _finding(rule_id: str, file_path: str = "test.py") -> Finding:
    return Finding(
        rule_id=rule_id, severity=Severity.HIGH, quantum_risk=QuantumRisk.VULNERABLE,
        algorithm=Algorithm(name="RSA", family=AlgorithmFamily.RSA, quantum_risk=QuantumRisk.VULNERABLE),
        location=FileLocation(file_path=file_path, line_number=1), message="Test",
    )


def test_compare_identical():
    f = [_finding("R1"), _finding("R2")]
    a = ScanResult(findings=f, summary=ScanSummary(total_findings=2, score=80.0, grade="B"))
    b = ScanResult(findings=f, summary=ScanSummary(total_findings=2, score=80.0, grade="B"))
    cmp = compare_scans(a, b)
    assert cmp.score_change == 0.0
    assert len(cmp.new_findings) == 0
    assert len(cmp.resolved_findings) == 0
    assert cmp.unchanged_count == 2


def test_compare_new_findings():
    a = ScanResult(findings=[_finding("R1")], summary=ScanSummary(total_findings=1, score=90.0, grade="A"))
    b = ScanResult(findings=[_finding("R1"), _finding("R2")], summary=ScanSummary(total_findings=2, score=80.0, grade="B"))
    cmp = compare_scans(a, b)
    assert len(cmp.new_findings) == 1
    assert cmp.score_change == -10.0


def test_compare_resolved_findings():
    a = ScanResult(findings=[_finding("R1"), _finding("R2")], summary=ScanSummary(total_findings=2, score=80.0, grade="B"))
    b = ScanResult(findings=[_finding("R1")], summary=ScanSummary(total_findings=1, score=90.0, grade="A"))
    cmp = compare_scans(a, b)
    assert len(cmp.resolved_findings) == 1
    assert cmp.score_change == 10.0
