"""ISO 27001:2022 compliance mappings.

Maps findings to Annex A.8.24 cryptographic controls.
"""

from __future__ import annotations

from quant_scan.compliance.mapper import ComplianceRef
from quant_scan.core.enums import AlgorithmFamily, QuantumRisk
from quant_scan.core.models import Finding


def map_finding(finding: Finding) -> list[ComplianceRef]:
    """Return ISO 27001:2022 compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family
    key_size = finding.algorithm.key_size
    q_risk = finding.quantum_risk

    # A.8.24 — Use of cryptography: flag all VULNERABLE/WEAKENED algorithms
    if q_risk in (QuantumRisk.VULNERABLE, QuantumRisk.WEAKENED):
        refs.append(
            ComplianceRef(
                framework="ISO 27001",
                requirement_id="A.8.24",
                description=(
                    "Use of cryptography — algorithm is quantum-vulnerable; documented cryptographic policy required"
                ),
                status="action_required",
            )
        )

    # A.8.24.1 — Key management: flag classically weak algorithms
    if family == AlgorithmFamily.RSA and key_size is not None and key_size < 2048:
        refs.append(
            ComplianceRef(
                framework="ISO 27001",
                requirement_id="A.8.24.1",
                description="Key management — RSA key size below 2048 bits",
                status="non_compliant",
            )
        )

    if family in (
        AlgorithmFamily.DES,
        AlgorithmFamily.TRIPLE_DES,
        AlgorithmFamily.MD5,
        AlgorithmFamily.SHA1,
    ):
        refs.append(
            ComplianceRef(
                framework="ISO 27001",
                requirement_id="A.8.24.1",
                description=f"Key management — {family.value} is no longer considered secure",
                status="non_compliant",
            )
        )

    return refs
