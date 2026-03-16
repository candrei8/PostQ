"""EU PQC Roadmap compliance mappings."""

from __future__ import annotations

from quant_scan.compliance.mapper import ComplianceRef
from quant_scan.core.enums import AlgorithmFamily, QuantumRisk
from quant_scan.core.models import Finding


def map_finding(finding: Finding) -> list[ComplianceRef]:
    """Return EU PQC Roadmap compliance references applicable to *finding*."""
    refs: list[ComplianceRef] = []
    family = finding.algorithm.family
    q_risk = finding.quantum_risk

    # All quantum-vulnerable or quantum-weakened algorithms require inventory
    if q_risk in (QuantumRisk.VULNERABLE, QuantumRisk.WEAKENED):
        refs.append(
            ComplianceRef(
                framework="EU PQC Roadmap",
                requirement_id="INV-2026-Q4",
                description="Complete cryptographic inventory by Q4 2026",
                status="action_required",
                deadline="2026-12-31",
            )
        )

    # Asymmetric algorithms require PQC migration by 2030
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
                framework="EU PQC Roadmap",
                requirement_id="MIG-2030",
                description="Migrate critical infrastructure to PQC by 2030",
                status="action_required",
                deadline="2030-12-31",
            )
        )

    return refs
