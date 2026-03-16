"""Tests for compliance gap analysis."""

from __future__ import annotations

from quant_scan.compliance.gap_analysis import analyze_compliance_gaps
from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding, ScanResult, ScanSummary


def test_gap_analysis_with_findings():
    findings = [
        Finding(
            rule_id="TEST",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.VULNERABLE,
            algorithm=Algorithm(name="RSA", family=AlgorithmFamily.RSA, quantum_risk=QuantumRisk.VULNERABLE),
            location=FileLocation(file_path="test.py", line_number=1),
            message="RSA",
        ),
    ]
    result = ScanResult(findings=findings, summary=ScanSummary(total_findings=1))
    gaps = analyze_compliance_gaps(result)
    assert len(gaps.frameworks) > 0
    assert gaps.total_gaps > 0


def test_gap_analysis_empty():
    result = ScanResult(findings=[], summary=ScanSummary())
    gaps = analyze_compliance_gaps(result)
    assert gaps.total_gaps == 0
