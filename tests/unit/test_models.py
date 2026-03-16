"""Tests for core data models."""

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import (
    Algorithm,
    FileLocation,
    Finding,
    ScanResult,
    ScanSummary,
)


def test_algorithm_creation():
    algo = Algorithm(
        name="RSA-2048",
        family=AlgorithmFamily.RSA,
        key_size=2048,
        quantum_risk=QuantumRisk.VULNERABLE,
        pqc_replacements=["ML-DSA-65"],
    )
    assert algo.name == "RSA-2048"
    assert algo.quantum_risk == QuantumRisk.VULNERABLE


def test_finding_serialization():
    finding = Finding(
        rule_id="PY-RSA-001",
        severity=Severity.HIGH,
        quantum_risk=QuantumRisk.VULNERABLE,
        algorithm=Algorithm(
            name="RSA-2048",
            family=AlgorithmFamily.RSA,
            quantum_risk=QuantumRisk.VULNERABLE,
        ),
        location=FileLocation(
            file_path="test.py",
            line_number=10,
            line_content="rsa.generate_private_key()",
        ),
        message="RSA key generation detected",
    )
    data = finding.model_dump()
    assert data["rule_id"] == "PY-RSA-001"
    assert data["severity"] == "high"

    json_str = finding.model_dump_json()
    assert "PY-RSA-001" in json_str


def test_scan_summary_grade():
    assert ScanSummary.compute_grade(95) == "A"
    assert ScanSummary.compute_grade(80) == "B"
    assert ScanSummary.compute_grade(65) == "C"
    assert ScanSummary.compute_grade(45) == "D"
    assert ScanSummary.compute_grade(30) == "F"


def test_scan_result_defaults():
    result = ScanResult()
    assert result.findings == []
    assert result.summary.total_findings == 0
    assert result.summary.grade == "A"
