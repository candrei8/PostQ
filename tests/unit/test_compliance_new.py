"""Tests for new compliance frameworks."""
from __future__ import annotations

import pytest

from quant_scan.compliance.mapper import ComplianceMapper, ComplianceRef
from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding


def _make_finding(family: AlgorithmFamily, risk: QuantumRisk, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id="TEST-001",
        severity=severity,
        quantum_risk=risk,
        algorithm=Algorithm(name=family.value, family=family, quantum_risk=risk),
        location=FileLocation(file_path="test.py", line_number=1),
        message="Test finding",
    )


def test_mapper_loads_all_frameworks():
    """ComplianceMapper should load all 14 frameworks."""
    mapper = ComplianceMapper()
    assert len(mapper._frameworks) >= 14


@pytest.mark.parametrize("framework_name", [
    "iso27001", "pci_dss", "gdpr", "hipaa", "dora", "nis2",
    "eidas", "soc2", "bsi", "anssi", "cnss",
])
def test_framework_maps_rsa_finding(framework_name):
    """Each framework should produce refs for RSA finding."""
    mapper = ComplianceMapper(enabled_frameworks=[framework_name])
    finding = _make_finding(AlgorithmFamily.RSA, QuantumRisk.VULNERABLE)
    refs = mapper.map_finding(finding)
    assert len(refs) > 0, f"Framework {framework_name} produced no refs for RSA"


@pytest.mark.parametrize("framework_name", [
    "iso27001", "pci_dss", "gdpr", "hipaa", "dora", "nis2",
    "eidas", "soc2", "bsi", "anssi", "cnss",
])
def test_framework_maps_des_finding(framework_name):
    """Each framework should produce refs for DES finding."""
    mapper = ComplianceMapper(enabled_frameworks=[framework_name])
    finding = _make_finding(AlgorithmFamily.DES, QuantumRisk.VULNERABLE, Severity.CRITICAL)
    refs = mapper.map_finding(finding)
    assert len(refs) > 0, f"Framework {framework_name} produced no refs for DES"


def test_selective_framework_loading():
    """ComplianceMapper should load only specified frameworks."""
    mapper = ComplianceMapper(enabled_frameworks=["nist", "gdpr"])
    assert len(mapper._frameworks) == 2


def test_compliance_ref_str():
    """ComplianceRef.__str__ should include framework and description."""
    ref = ComplianceRef(framework="TEST", requirement_id="R1", description="Test ref", status="non_compliant")
    s = str(ref)
    assert "TEST" in s
    assert "R1" in s
