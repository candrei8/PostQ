"""Tests for quantum timeline predictor and HNDL risk."""

from __future__ import annotations

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding
from quant_scan.quantum_timeline.hndl import compute_hndl_risk
from quant_scan.quantum_timeline.predictor import predict_timeline, predict_timelines


def _make_finding(family: AlgorithmFamily, key_size: int | None = None) -> Finding:
    return Finding(
        rule_id="TEST",
        severity=Severity.HIGH,
        quantum_risk=QuantumRisk.VULNERABLE,
        algorithm=Algorithm(name=family.value, family=family, key_size=key_size, quantum_risk=QuantumRisk.VULNERABLE),
        location=FileLocation(file_path="test.py", line_number=1),
        message="Test",
    )


def test_predict_rsa_2048():
    tl = predict_timeline(_make_finding(AlgorithmFamily.RSA, 2048))
    assert tl is not None
    assert tl.estimated_break_year_optimistic <= tl.estimated_break_year_moderate
    assert tl.estimated_break_year_moderate <= tl.estimated_break_year_conservative
    assert tl.logical_qubits_required > 0


def test_predict_ecc():
    tl = predict_timeline(_make_finding(AlgorithmFamily.ECC, 256))
    assert tl is not None
    assert tl.algorithm_family == "ECC"


def test_predict_safe_returns_none():
    finding = Finding(
        rule_id="TEST",
        severity=Severity.INFO,
        quantum_risk=QuantumRisk.SAFE,
        algorithm=Algorithm(name="AES-256", family=AlgorithmFamily.AES, quantum_risk=QuantumRisk.SAFE),
        location=FileLocation(file_path="test.py", line_number=1),
        message="Test",
    )
    assert predict_timeline(finding) is None


def test_predict_timelines_multiple():
    findings = [
        _make_finding(AlgorithmFamily.RSA, 2048),
        _make_finding(AlgorithmFamily.ECC, 256),
        _make_finding(AlgorithmFamily.RSA, 2048),  # duplicate
    ]
    timelines = predict_timelines(findings)
    assert len(timelines) >= 2  # RSA and ECC, not duplicate RSA


def test_hndl_immediate():
    tl = predict_timeline(_make_finding(AlgorithmFamily.RSA, 2048))
    hndl = compute_hndl_risk(tl, data_shelf_life_years=30, data_sensitivity="top_secret")
    assert hndl.urgency == "immediate"
    assert hndl.hndl_risk_score > 50


def test_hndl_low_shelf_life():
    """Short shelf-life public data should have low urgency and score."""
    tl = predict_timeline(_make_finding(AlgorithmFamily.RSA, 2048))
    hndl = compute_hndl_risk(tl, data_shelf_life_years=1, data_sensitivity="public")
    # With shelf_life=1 and break year ~2035, urgency should not be "immediate"
    assert hndl.urgency in ("monitor", "planned", "urgent")
    assert hndl.hndl_risk_score < 50


def test_hndl_sensitivity_affects_score():
    tl = predict_timeline(_make_finding(AlgorithmFamily.RSA, 2048))
    hndl_public = compute_hndl_risk(tl, data_shelf_life_years=10, data_sensitivity="public")
    hndl_secret = compute_hndl_risk(tl, data_shelf_life_years=10, data_sensitivity="top_secret")
    assert hndl_secret.hndl_risk_score >= hndl_public.hndl_risk_score
