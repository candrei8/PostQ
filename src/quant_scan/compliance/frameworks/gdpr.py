"""GDPR Article 32 compliance mappings.

Maps findings to GDPR requirements for appropriate technical measures.
"""

from __future__ import annotations

from quant_scan.compliance.mapper import ComplianceRef
from quant_scan.core.enums import AlgorithmFamily, QuantumRisk
from quant_scan.core.models import Finding


def map_finding(finding: Finding) -> list[ComplianceRef]:
    """Return GDPR compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family
    q_risk = finding.quantum_risk

    # Art 32.1.a — Encryption as appropriate measure
    # VULNERABLE algorithms require action under "state of the art" requirement
    if q_risk == QuantumRisk.VULNERABLE:
        refs.append(
            ComplianceRef(
                framework="GDPR",
                requirement_id="Art 32.1.a",
                description='Encryption as appropriate measure — algorithm is quantum-vulnerable; "state of the art" requires planning PQC migration',
                status="action_required",
            )
        )

    # Art 32.1.a — Classically broken algorithms are no longer "state of the art"
    if family in (
        AlgorithmFamily.DES,
        AlgorithmFamily.TRIPLE_DES,
        AlgorithmFamily.RC4,
        AlgorithmFamily.MD5,
        AlgorithmFamily.SHA1,
    ):
        refs.append(
            ComplianceRef(
                framework="GDPR",
                requirement_id="Art 32.1.a",
                description=f'Encryption as appropriate measure — {family.value} is no longer "state of the art"',
                status="non_compliant",
            )
        )

    return refs
