"""Spanish ENS (Esquema Nacional de Seguridad) compliance mappings.

Maps findings to CCN-STIC 807 cryptographic requirements.
"""

from __future__ import annotations

from quant_scan.compliance.mapper import ComplianceRef
from quant_scan.core.enums import AlgorithmFamily
from quant_scan.core.models import Finding


def map_finding(finding: Finding) -> list[ComplianceRef]:
    """Return ENS / CCN-STIC-807 compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family
    key_size = finding.algorithm.key_size

    # RSA with insufficient key size
    if family == AlgorithmFamily.RSA and key_size is not None and key_size < 2048:
        refs.append(
            ComplianceRef(
                framework="ENS",
                requirement_id="CCN-STIC-807",
                description="Requires minimum RSA-2048 (CCN-STIC-807)",
                status="non_compliant",
            )
        )

    # Disallowed hash functions
    if family in (AlgorithmFamily.MD5, AlgorithmFamily.SHA1):
        refs.append(
            ComplianceRef(
                framework="ENS",
                requirement_id="CCN-STIC-807-HASH",
                description="Hash functions MD5 and SHA-1 not approved for nivel alto",
                status="non_compliant",
            )
        )

    # Disallowed ciphers
    if family in (AlgorithmFamily.DES, AlgorithmFamily.TRIPLE_DES, AlgorithmFamily.RC4):
        refs.append(
            ComplianceRef(
                framework="ENS",
                requirement_id="CCN-STIC-807-CIPHER",
                description="Cipher not approved in the cryptographic catalog",
                status="non_compliant",
            )
        )

    return refs
