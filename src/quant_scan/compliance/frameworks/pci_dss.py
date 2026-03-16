"""PCI DSS v4.0 compliance mappings.

Maps findings to PCI DSS requirements for cryptographic controls.
"""

from __future__ import annotations

from quant_scan.compliance.mapper import ComplianceRef
from quant_scan.core.enums import AlgorithmFamily, QuantumRisk
from quant_scan.core.models import Finding


def map_finding(finding: Finding) -> list[ComplianceRef]:
    """Return PCI DSS v4.0 compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family
    q_risk = finding.quantum_risk

    # Req 4.2.1 — Strong cryptography for data-in-transit
    # Quantum-vulnerable asymmetric algorithms require action
    if family in (
        AlgorithmFamily.RSA,
        AlgorithmFamily.ECC,
        AlgorithmFamily.DSA,
        AlgorithmFamily.DH,
        AlgorithmFamily.ECDH,
        AlgorithmFamily.ECDSA,
    ):
        refs.append(
            ComplianceRef(
                framework="PCI DSS v4.0",
                requirement_id="Req 4.2.1",
                description="Strong cryptography for data-in-transit — asymmetric algorithm is quantum-vulnerable",
                status="action_required",
            )
        )

    # Req 4.2.1 — Classically broken algorithms are non-compliant
    if family in (
        AlgorithmFamily.DES,
        AlgorithmFamily.TRIPLE_DES,
        AlgorithmFamily.RC4,
        AlgorithmFamily.MD5,
        AlgorithmFamily.SHA1,
    ):
        refs.append(
            ComplianceRef(
                framework="PCI DSS v4.0",
                requirement_id="Req 4.2.1",
                description=(
                    f"Strong cryptography for data-in-transit — {family.value} is not considered strong cryptography"
                ),
                status="non_compliant",
            )
        )

    # Req 3.5.1 — Protect stored data: weak symmetric ciphers
    if family in (AlgorithmFamily.DES, AlgorithmFamily.TRIPLE_DES):
        refs.append(
            ComplianceRef(
                framework="PCI DSS v4.0",
                requirement_id="Req 3.5.1",
                description=f"Protect stored data — {family.value} is not acceptable for data protection",
                status="non_compliant",
            )
        )

    if family == AlgorithmFamily.AES and q_risk == QuantumRisk.WEAKENED:
        refs.append(
            ComplianceRef(
                framework="PCI DSS v4.0",
                requirement_id="Req 3.5.1",
                description="Protect stored data — AES with quantum-weakened key size",
                status="non_compliant",
            )
        )

    return refs
