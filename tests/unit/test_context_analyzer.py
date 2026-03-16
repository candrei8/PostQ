"""Tests for context analysis — confidence adjustment."""

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding
from quant_scan.scanners.context import ContextAnalyzer


def _make_finding(
    file_path: str = "src/crypto.py",
    line_content: str = "rsa.generate_private_key()",
    line_number: int = 10,
    confidence: float = 1.0,
    context_before: list[str] | None = None,
    context_after: list[str] | None = None,
) -> Finding:
    return Finding(
        rule_id="TEST-001",
        severity=Severity.HIGH,
        quantum_risk=QuantumRisk.VULNERABLE,
        algorithm=Algorithm(
            name="RSA-2048",
            family=AlgorithmFamily.RSA,
            quantum_risk=QuantumRisk.VULNERABLE,
        ),
        location=FileLocation(
            file_path=file_path,
            line_number=line_number,
            line_content=line_content,
            context_before=context_before or [],
            context_after=context_after or [],
        ),
        message="Test finding",
        confidence=confidence,
    )


def test_test_file_reduces_confidence():
    analyzer = ContextAnalyzer()
    finding = _make_finding(file_path="tests/test_crypto.py")
    result = analyzer.analyze([finding])
    assert len(result) == 1
    assert result[0].confidence < 1.0


def test_comment_line_very_low_confidence():
    analyzer = ContextAnalyzer()
    finding = _make_finding(line_content="# Use RSA for encryption")
    result = analyzer.analyze([finding])
    # Should be filtered out or very low confidence
    if result:
        assert result[0].confidence < 0.2


def test_nosec_reduces_confidence():
    analyzer = ContextAnalyzer()
    finding = _make_finding(line_content="rsa.generate_private_key()  # nosec")
    result = analyzer.analyze([finding])
    if result:
        assert result[0].confidence < 0.6


def test_secret_context_increases_confidence():
    analyzer = ContextAnalyzer()
    finding = _make_finding(
        context_before=["private_key = load_key()"],
    )
    result = analyzer.analyze([finding])
    assert len(result) == 1
    # Should not decrease confidence
    assert result[0].confidence >= 1.0


def test_production_code_unchanged():
    analyzer = ContextAnalyzer()
    finding = _make_finding(
        file_path="src/auth/crypto_service.py",
        line_content="key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
    )
    result = analyzer.analyze([finding])
    assert len(result) == 1
    assert result[0].confidence == 1.0
