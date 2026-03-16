"""DORA (Digital Operational Resilience Act) compliance mappings.

Maps findings to DORA ICT risk management requirements.
"""

from __future__ import annotations

from quant_scan.compliance.mapper import ComplianceRef
from quant_scan.core.enums import AlgorithmFamily, QuantumRisk
from quant_scan.core.models import Finding

# DORA application date
_DORA_DEADLINE = "2025-01-17"


def map_finding(finding: Finding) -> list[ComplianceRef]:
    """Return DORA compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family
    q_risk = finding.quantum_risk

    # Art 6.2 — ICT risk management: VULNERABLE algorithms require action
    if q_risk == QuantumRisk.VULNERABLE:
        refs.append(
            ComplianceRef(
                framework="DORA",
                requirement_id="Art 6.2",
                description="ICT risk management — algorithm is quantum-vulnerable; risk assessment required",
                status="action_required",
                deadline=_DORA_DEADLINE,
            )
        )

    # Art 6.2 — Classically broken algorithms are non-compliant
    if family in (
        AlgorithmFamily.DES,
        AlgorithmFamily.TRIPLE_DES,
        AlgorithmFamily.RC4,
        AlgorithmFamily.MD5,
        AlgorithmFamily.SHA1,
    ):
        refs.append(
            ComplianceRef(
                framework="DORA",
                requirement_id="Art 6.2",
                description=f"ICT risk management — {family.value} is classically broken and non-compliant",
                status="non_compliant",
                deadline=_DORA_DEADLINE,
            )
        )

    return refs
