"""NIST SP 800-131A / SP 800-208 compliance mappings."""

from __future__ import annotations

from quant_scan.compliance.mapper import ComplianceRef
from quant_scan.core.enums import AlgorithmFamily
from quant_scan.core.models import Finding


def map_finding(finding: Finding) -> list[ComplianceRef]:
    """Return NIST compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family
    key_size = finding.algorithm.key_size

    # RSA-specific rules
    if family == AlgorithmFamily.RSA:
        if key_size is not None and key_size < 2048:
            refs.append(
                ComplianceRef(
                    framework="NIST",
                    requirement_id="SP 800-131A",
                    description="RSA key sizes below 2048 bits are disallowed",
                    status="non_compliant",
                )
            )
        refs.append(
            ComplianceRef(
                framework="NIST",
                requirement_id="SP 800-208",
                description="Plan migration to PQC algorithms",
                status="action_required",
            )
        )

    # Other asymmetric algorithms vulnerable to quantum
    if family in (
        AlgorithmFamily.ECC,
        AlgorithmFamily.DSA,
        AlgorithmFamily.DH,
        AlgorithmFamily.ECDH,
        AlgorithmFamily.ECDSA,
    ):
        refs.append(
            ComplianceRef(
                framework="NIST",
                requirement_id="SP 800-208",
                description="Asymmetric algorithms vulnerable to quantum",
                status="action_required",
            )
        )

    # DES / 3DES
    if family in (AlgorithmFamily.DES, AlgorithmFamily.TRIPLE_DES):
        refs.append(
            ComplianceRef(
                framework="NIST",
                requirement_id="SP 800-131A",
                description="DES and 3DES are disallowed",
                status="non_compliant",
            )
        )

    # MD5
    if family == AlgorithmFamily.MD5:
        refs.append(
            ComplianceRef(
                framework="NIST",
                requirement_id="SP 800-131A",
                description="MD5 is not approved for digital signatures",
                status="non_compliant",
            )
        )

    # SHA-1
    if family == AlgorithmFamily.SHA1:
        refs.append(
            ComplianceRef(
                framework="NIST",
                requirement_id="SP 800-131A",
                description="SHA-1 is disallowed for digital signatures",
                status="non_compliant",
            )
        )

    return refs
