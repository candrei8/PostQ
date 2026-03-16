"""Tests for CI/CD integration (quality gate, PR comments, SARIF)."""

from __future__ import annotations

from quant_scan.cicd.pr_comment import format_pr_comment
from quant_scan.cicd.quality_gate import QualityGate
from quant_scan.core.models import ScanResult, ScanSummary


def test_quality_gate_passes():
    result = ScanResult(summary=ScanSummary(score=90.0, grade="A", by_severity={"high": 2}))
    gate = QualityGate(min_score=70.0, max_critical=0, max_high=5)
    gr = gate.evaluate(result)
    assert gr.passed is True
    assert gr.reasons == []


def test_quality_gate_fails_score():
    result = ScanResult(summary=ScanSummary(score=50.0, grade="D"))
    gate = QualityGate(min_score=70.0)
    gr = gate.evaluate(result)
    assert gr.passed is False
    assert any("Score" in r for r in gr.reasons)


def test_quality_gate_fails_critical():
    result = ScanResult(summary=ScanSummary(score=80.0, grade="B", by_severity={"critical": 1}))
    gate = QualityGate(max_critical=0)
    gr = gate.evaluate(result)
    assert gr.passed is False


def test_pr_comment_format():
    result = ScanResult(
        summary=ScanSummary(
            score=75.0, grade="B", total_findings=5, files_scanned=10, by_severity={"high": 3, "medium": 2}
        )
    )
    comment = format_pr_comment(result)
    assert "## Quant-Scan" in comment
    assert "75" in comment
    assert "Grade B" in comment


def test_sarif_format():
    import json

    from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
    from quant_scan.core.models import Algorithm, FileLocation, Finding
    from quant_scan.reports.formats.sarif_report import render_sarif

    finding = Finding(
        rule_id="TEST-RSA",
        severity=Severity.HIGH,
        quantum_risk=QuantumRisk.VULNERABLE,
        algorithm=Algorithm(name="RSA", family=AlgorithmFamily.RSA, quantum_risk=QuantumRisk.VULNERABLE),
        location=FileLocation(file_path="test.py", line_number=10, line_content="rsa.generate()"),
        message="RSA detected",
    )
    result = ScanResult(findings=[finding], summary=ScanSummary(total_findings=1))
    sarif = render_sarif(result)
    data = json.loads(sarif)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1
    assert data["runs"][0]["results"][0]["ruleId"] == "TEST-RSA"
