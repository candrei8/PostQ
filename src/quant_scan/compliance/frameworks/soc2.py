"""SOC 2 Type II compliance mappings.

Maps findings to AICPA Trust Services Criteria for security.
"""

from __future__ import annotations

from quant_scan.compliance.mapper import ComplianceRef
from quant_scan.core.enums import AlgorithmFamily, QuantumRisk
from quant_scan.core.models import Finding

_ASYMMETRIC = {
    AlgorithmFamily.RSA,
    AlgorithmFamily.ECC,
    AlgorithmFamily.ECDSA,
    AlgorithmFamily.ECDH,
    AlgorithmFamily.DSA,
    AlgorithmFamily.DH,
}
_BROKEN = {AlgorithmFamily.DES, AlgorithmFamily.TRIPLE_DES, AlgorithmFamily.RC4}
_WEAK_HASH = {AlgorithmFamily.MD5, AlgorithmFamily.SHA1}


def map_finding(finding: Finding) -> list[ComplianceRef]:
    """Return SOC 2 Type II compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family

    # CC6.1 — Logical and physical access controls using weak cryptography
    if family in _BROKEN or family in _WEAK_HASH:
        refs.append(
            ComplianceRef(
                framework="SOC 2",
                requirement_id="CC6.1",
                description=f"Logical access controls using weak cryptography ({family.value})",
                status="non_compliant",
            )
        )

    # CC6.1 — Quantum-vulnerable algorithms in access controls
    if family in _ASYMMETRIC and finding.quantum_risk == QuantumRisk.VULNERABLE:
        refs.append(
            ComplianceRef(
                framework="SOC 2",
                requirement_id="CC6.1",
                description="Logical access controls use quantum-vulnerable cryptography",
                status="action_required",
            )
        )

    # CC6.7 — Data-in-transit protection with vulnerable algorithms
    if finding.quantum_risk == QuantumRisk.VULNERABLE:
        refs.append(
            ComplianceRef(
                framework="SOC 2",
                requirement_id="CC6.7",
                description=f"Data-in-transit protection using quantum-vulnerable algorithm ({finding.algorithm.name})",
                status="action_required",
            )
        )

    # CC6.7 — Broken ciphers for data in transit
    if family in _BROKEN:
        refs.append(
            ComplianceRef(
                framework="SOC 2",
                requirement_id="CC6.7",
                description=f"Data-in-transit protection using broken cipher ({family.value})",
                status="non_compliant",
            )
        )

    return refs
