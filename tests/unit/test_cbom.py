"""Tests for CBOM generation."""

from __future__ import annotations

import json

from quant_scan.cbom.formats.cyclonedx import render_cyclonedx
from quant_scan.cbom.generator import generate_cbom
from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding, ScanResult, ScanSummary


def test_cbom_generation():
    findings = [
        Finding(
            rule_id="T1",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.VULNERABLE,
            algorithm=Algorithm(
                name="RSA-2048", family=AlgorithmFamily.RSA, key_size=2048, quantum_risk=QuantumRisk.VULNERABLE
            ),
            location=FileLocation(file_path="a.py", line_number=1),
            message="RSA",
            scanner_type="source",
        ),
        Finding(
            rule_id="T2",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.VULNERABLE,
            algorithm=Algorithm(
                name="RSA-2048", family=AlgorithmFamily.RSA, key_size=2048, quantum_risk=QuantumRisk.VULNERABLE
            ),
            location=FileLocation(file_path="b.py", line_number=5),
            message="RSA",
            scanner_type="source",
        ),
    ]
    result = ScanResult(findings=findings, summary=ScanSummary(total_findings=2))
    cbom = generate_cbom(result)
    assert cbom.total_algorithms == 1  # Deduplicated
    assert cbom.components[0].occurrence_count == 2
    assert cbom.vulnerable_count == 1


def test_cyclonedx_format():
    findings = [
        Finding(
            rule_id="T1",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.VULNERABLE,
            algorithm=Algorithm(name="RSA", family=AlgorithmFamily.RSA, quantum_risk=QuantumRisk.VULNERABLE),
            location=FileLocation(file_path="test.py", line_number=1),
            message="RSA",
        ),
    ]
    result = ScanResult(findings=findings, summary=ScanSummary(total_findings=1))
    cbom = generate_cbom(result)
    cdx = render_cyclonedx(cbom)
    data = json.loads(cdx)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.6"
    assert len(data["components"]) == 1
    assert data["components"][0]["type"] == "cryptographic-asset"
