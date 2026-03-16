"""ANSSI compliance mappings.

Maps findings to French National Cybersecurity Agency cryptographic recommendations.
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
    """Return ANSSI compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family
    key_size = finding.algorithm.key_size

    # RSA < 2048 — non-compliant per ANSSI recommendations
    if family == AlgorithmFamily.RSA:
        if key_size is not None and key_size < 2048:
            refs.append(
                ComplianceRef(
                    framework="ANSSI",
                    requirement_id="RGS-B1",
                    description="RSA key size below 2048 bits is non-compliant with ANSSI recommendations",
                    status="non_compliant",
                )
            )

    # ECC quantum-vulnerable — action required
    if family in _ASYMMETRIC and finding.quantum_risk == QuantumRisk.VULNERABLE:
        refs.append(
            ComplianceRef(
                framework="ANSSI",
                requirement_id="ANSSI-PQC-2024",
                description="Quantum-vulnerable asymmetric algorithm requires PQC migration per ANSSI guidance",
                status="action_required",
                deadline="2030-12-31",
            )
        )

    # Broken ciphers — non-compliant
    if family in _BROKEN:
        refs.append(
            ComplianceRef(
                framework="ANSSI",
                requirement_id="RGS-B1",
                description=f"{family.value} is not approved by ANSSI for any security purpose",
                status="non_compliant",
            )
        )

    # Weak hashes — non-compliant
    if family in _WEAK_HASH:
        refs.append(
            ComplianceRef(
                framework="ANSSI",
                requirement_id="RGS-B1",
                description=f"{family.value} is not approved by ANSSI for cryptographic hashing",
                status="non_compliant",
            )
        )

    return refs
