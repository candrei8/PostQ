"""Tests for advanced scoring (QVSS, crypto debt)."""

from __future__ import annotations

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding, ScanResult, ScanSummary
from quant_scan.scoring.crypto_debt import compute_crypto_debt
from quant_scan.scoring.quantum_score import compute_qvss


def _make_finding(family: AlgorithmFamily, risk: QuantumRisk, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id="TEST",
        severity=severity,
        quantum_risk=risk,
        algorithm=Algorithm(name=family.value, family=family, quantum_risk=risk),
        location=FileLocation(file_path="test.py", line_number=1),
        message="Test",
    )


def test_qvss_vulnerable_rsa():
    finding = _make_finding(AlgorithmFamily.RSA, QuantumRisk.VULNERABLE)
    score = compute_qvss(finding)
    assert score.overall_score > 5.0
    assert score.severity_label in ("High", "Critical", "Medium")


def test_qvss_safe_aes256():
    finding = _make_finding(AlgorithmFamily.AES, QuantumRisk.SAFE, Severity.INFO)
    score = compute_qvss(finding)
    assert score.overall_score < 3.0


def test_qvss_environmental_impact():
    finding = _make_finding(AlgorithmFamily.RSA, QuantumRisk.VULNERABLE)
    low = compute_qvss(finding, data_sensitivity=1.0, business_criticality=1.0, exposure_scope=1.0)
    high = compute_qvss(finding, data_sensitivity=9.0, business_criticality=9.0, exposure_scope=9.0)
    assert high.overall_score > low.overall_score


def test_qvss_score_bounds():
    finding = _make_finding(AlgorithmFamily.RSA, QuantumRisk.VULNERABLE, Severity.CRITICAL)
    score = compute_qvss(finding)
    assert 0.0 <= score.overall_score <= 10.0
    assert 0.0 <= score.base_score <= 10.0
    assert 0.0 <= score.temporal_score <= 10.0
    assert 0.0 <= score.environmental_score <= 10.0


def test_crypto_debt_empty():
    result = ScanResult(findings=[], summary=ScanSummary())
    debt = compute_crypto_debt(result)
    assert debt.total_debt_score == 0.0


def test_crypto_debt_with_findings():
    findings = [
        _make_finding(AlgorithmFamily.RSA, QuantumRisk.VULNERABLE, Severity.HIGH),
        _make_finding(AlgorithmFamily.DES, QuantumRisk.VULNERABLE, Severity.CRITICAL),
        _make_finding(AlgorithmFamily.MD5, QuantumRisk.VULNERABLE, Severity.HIGH),
    ]
    result = ScanResult(findings=findings, summary=ScanSummary(total_findings=3))
    debt = compute_crypto_debt(result)
    assert debt.total_debt_score > 0
    assert "asymmetric_vulnerable" in debt.debt_by_category
    assert debt.estimated_remediation_hours > 0
    assert debt.debt_interest_rate > 0
