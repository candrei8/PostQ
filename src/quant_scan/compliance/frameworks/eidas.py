"""eIDAS 2.0 compliance mappings.

Maps findings to eIDAS electronic signature and trust service requirements.
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
    """Return eIDAS 2.0 compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family

    # Art 32 — Qualified electronic signatures must use quantum-safe algorithms
    if family in _ASYMMETRIC and finding.quantum_risk == QuantumRisk.VULNERABLE:
        refs.append(
            ComplianceRef(
                framework="eIDAS 2.0",
                requirement_id="Art 32",
                description=(
                    "Qualified electronic signatures using quantum-vulnerable algorithms require migration plan"
                ),
                status="action_required",
                deadline="2027-12-31",
            )
        )

    # RSA/ECC/DSA signatures are non-compliant for qualified signatures long-term
    if family in {AlgorithmFamily.RSA, AlgorithmFamily.ECC, AlgorithmFamily.DSA, AlgorithmFamily.ECDSA}:
        refs.append(
            ComplianceRef(
                framework="eIDAS 2.0",
                requirement_id="Art 32.1",
                description=f"{family.value} signatures will not meet qualified signature requirements post-quantum",
                status="non_compliant",
                deadline="2027-12-31",
            )
        )

    # Broken ciphers are non-compliant for trust services
    if family in _BROKEN:
        refs.append(
            ComplianceRef(
                framework="eIDAS 2.0",
                requirement_id="Art 24.2",
                description=f"{family.value} is not acceptable for trust service security",
                status="non_compliant",
            )
        )

    # Weak hashes are non-compliant for electronic signatures
    if family in _WEAK_HASH:
        refs.append(
            ComplianceRef(
                framework="eIDAS 2.0",
                requirement_id="Art 32.1",
                description=f"{family.value} is not acceptable for qualified electronic signatures",
                status="non_compliant",
            )
        )

    return refs
