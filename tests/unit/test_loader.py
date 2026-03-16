"""Tests for rule loading."""

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk
from quant_scan.rules.loader import load_algorithms, load_source_rules


def test_load_algorithms():
    db = load_algorithms()
    assert "RSA-2048" in db
    assert db["RSA-2048"].quantum_risk == QuantumRisk.VULNERABLE
    assert db["RSA-2048"].family == AlgorithmFamily.RSA


def test_algorithms_have_pqc_replacements():
    db = load_algorithms()
    rsa = db["RSA-2048"]
    assert len(rsa.pqc_replacements) > 0


def test_safe_algorithms_exist():
    db = load_algorithms()
    assert "AES-256" in db
    assert db["AES-256"].quantum_risk == QuantumRisk.SAFE


def test_load_python_rules():
    rules = load_source_rules("python")
    assert len(rules) > 0
    ids = [r.id for r in rules]
    assert "PY-RSA-GENERATE" in ids
    assert "PY-MD5-USE" in ids


def test_load_nonexistent_language():
    rules = load_source_rules("nonexistent")
    assert rules == []
