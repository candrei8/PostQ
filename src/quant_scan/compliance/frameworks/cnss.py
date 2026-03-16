"""CNSS Policy 15 compliance mappings.

Maps findings to Committee on National Security Systems requirements
for cryptographic use in national security systems.
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
    """Return CNSS Policy 15 compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family

    # All quantum-vulnerable asymmetric algorithms — action required for NSS
    if family in _ASYMMETRIC and finding.quantum_risk == QuantumRisk.VULNERABLE:
        refs.append(
            ComplianceRef(
                framework="CNSS",
                requirement_id="CNSSP-15 Sec 7",
                description="Quantum-vulnerable asymmetric algorithm in national security system requires PQC transition",
                status="action_required",
                deadline="2030-12-31",
            )
        )

    # Broken ciphers — non-compliant for NSS
    if family in _BROKEN:
        refs.append(
            ComplianceRef(
                framework="CNSS",
                requirement_id="CNSSP-15 Sec 6",
                description=f"{family.value} is not approved for use in national security systems",
                status="non_compliant",
            )
        )

    # Weak hashes — non-compliant for NSS
    if family in _WEAK_HASH:
        refs.append(
            ComplianceRef(
                framework="CNSS",
                requirement_id="CNSSP-15 Sec 6",
                description=f"{family.value} is not approved for use in national security systems",
                status="non_compliant",
            )
        )

    return refs
