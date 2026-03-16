"""HIPAA Security Rule compliance mappings.

Maps findings to HIPAA technical safeguards for encryption.
"""

from __future__ import annotations

from quant_scan.compliance.mapper import ComplianceRef
from quant_scan.core.enums import AlgorithmFamily
from quant_scan.core.models import Finding


def map_finding(finding: Finding) -> list[ComplianceRef]:
    """Return HIPAA compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family

    # 164.312(a)(2)(iv) — Encryption and decryption (data at rest)
    if family in (
        AlgorithmFamily.DES,
        AlgorithmFamily.TRIPLE_DES,
        AlgorithmFamily.RC4,
    ):
        refs.append(
            ComplianceRef(
                framework="HIPAA",
                requirement_id="164.312(a)(2)(iv)",
                description=(
                    f"Encryption and decryption — {family.value} "
                    "does not meet encryption standard requirements"
                ),
                status="non_compliant",
            )
        )

    # 164.312(e)(2)(ii) — Encryption for data in transit
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
                framework="HIPAA",
                requirement_id="164.312(e)(2)(ii)",
                description="Encryption for data in transit — asymmetric algorithm is quantum-vulnerable",
                status="action_required",
            )
        )

    return refs
