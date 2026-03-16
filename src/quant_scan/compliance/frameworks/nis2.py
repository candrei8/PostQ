"""NIS2 Directive compliance mappings.

Maps findings to NIS2 cryptographic control requirements.
"""

from __future__ import annotations

from quant_scan.compliance.mapper import ComplianceRef
from quant_scan.core.enums import AlgorithmFamily, QuantumRisk
from quant_scan.core.models import Finding

# NIS2 transposition deadline (already passed)
_NIS2_DEADLINE = "2024-10-17"


def map_finding(finding: Finding) -> list[ComplianceRef]:
    """Return NIS2 Directive compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family
    q_risk = finding.quantum_risk

    # Art 21.2.e — Cryptographic controls: VULNERABLE algorithms require action
    if q_risk == QuantumRisk.VULNERABLE:
        refs.append(
            ComplianceRef(
                framework="NIS2",
                requirement_id="Art 21.2.e",
                description="Cryptographic controls — algorithm is quantum-vulnerable; migration planning required",
                status="action_required",
                deadline=_NIS2_DEADLINE,
            )
        )

    # Art 21.2.e — Classically broken algorithms are non-compliant
    if family in (
        AlgorithmFamily.DES,
        AlgorithmFamily.TRIPLE_DES,
        AlgorithmFamily.RC4,
        AlgorithmFamily.MD5,
        AlgorithmFamily.SHA1,
    ):
        refs.append(
            ComplianceRef(
                framework="NIS2",
                requirement_id="Art 21.2.e",
                description=f"Cryptographic controls — {family.value} is classically broken and non-compliant",
                status="non_compliant",
                deadline=_NIS2_DEADLINE,
            )
        )

    return refs
