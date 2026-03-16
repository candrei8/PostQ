"""BSI TR-02102 compliance mappings.

Maps findings to German Federal Office for Information Security technical recommendations.
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
    """Return BSI TR-02102 compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family
    key_size = finding.algorithm.key_size

    # RSA key size < 3072 — action required per BSI recommendation
    if family == AlgorithmFamily.RSA:
        if key_size is not None and key_size < 3072:
            refs.append(
                ComplianceRef(
                    framework="BSI",
                    requirement_id="TR-02102-1 Sec 3.5",
                    description="RSA key size below 3072 bits; BSI recommends minimum 3072-bit RSA",
                    status="action_required",
                )
            )

    # DES, 3DES, RC4 — non-compliant
    if family in _BROKEN:
        refs.append(
            ComplianceRef(
                framework="BSI",
                requirement_id="TR-02102-1 Sec 3.2",
                description=f"{family.value} is not recommended by BSI",
                status="non_compliant",
            )
        )

    # MD5 and SHA-1 — non-compliant
    if family in _WEAK_HASH:
        refs.append(
            ComplianceRef(
                framework="BSI",
                requirement_id="TR-02102-1 Sec 4.1",
                description=f"{family.value} is not recommended by BSI for cryptographic purposes",
                status="non_compliant",
            )
        )

    # Quantum-vulnerable asymmetric algorithms — action required
    if family in _ASYMMETRIC and finding.quantum_risk == QuantumRisk.VULNERABLE:
        refs.append(
            ComplianceRef(
                framework="BSI",
                requirement_id="TR-02102-1 Sec 3.6",
                description="Quantum-vulnerable asymmetric algorithm; BSI recommends PQC migration planning",
                status="action_required",
                deadline="2030-12-31",
            )
        )

    return refs
