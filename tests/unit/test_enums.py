"""Tests for core enums."""

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity


def test_severity_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.INFO.value == "info"


def test_severity_weight():
    assert Severity.CRITICAL.weight == 10.0
    assert Severity.INFO.weight == 0.0
    assert Severity.HIGH.weight > Severity.MEDIUM.weight


def test_quantum_risk_values():
    assert QuantumRisk.VULNERABLE.value == "vulnerable"
    assert QuantumRisk.SAFE.value == "safe"


def test_algorithm_family_has_pqc():
    assert AlgorithmFamily.ML_KEM.value == "ML-KEM"
    assert AlgorithmFamily.ML_DSA.value == "ML-DSA"
    assert AlgorithmFamily.SLH_DSA.value == "SLH-DSA"
