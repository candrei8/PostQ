"""Crypto debt metric — measures organizational cryptographic technical debt."""

from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, Field

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Finding, ScanResult

# Weight per finding category
_CATEGORY_WEIGHTS: dict[str, float] = {
    "asymmetric_vulnerable": 10.0,  # RSA, ECC, DSA, DH — Shor's attack
    "symmetric_weakened": 3.0,  # AES-128, Blowfish — Grover's attack
    "classically_broken": 8.0,  # DES, 3DES, RC4, MD5, SHA-1
    "hash_deprecated": 5.0,  # MD5, SHA-1
}

_ASYMMETRIC_FAMILIES = {
    AlgorithmFamily.RSA,
    AlgorithmFamily.ECC,
    AlgorithmFamily.ECDSA,
    AlgorithmFamily.ECDH,
    AlgorithmFamily.DSA,
    AlgorithmFamily.DH,
}

_CLASSICALLY_BROKEN = {
    AlgorithmFamily.DES,
    AlgorithmFamily.TRIPLE_DES,
    AlgorithmFamily.RC4,
}

_HASH_DEPRECATED = {AlgorithmFamily.MD5, AlgorithmFamily.SHA1}


class CryptoDebt(BaseModel):
    """Organizational crypto debt measurement."""

    total_debt_score: float = 0.0
    debt_by_category: dict[str, float] = Field(default_factory=dict)
    estimated_remediation_hours: float = 0.0
    debt_interest_rate: float = Field(
        default=0.0,
        description="Annual increase rate due to quantum computing progress",
    )


def _categorize_finding(finding: Finding) -> str:
    """Determine the debt category for a finding."""
    family = finding.algorithm.family

    if family in _CLASSICALLY_BROKEN:
        return "classically_broken"
    if family in _HASH_DEPRECATED:
        return "hash_deprecated"
    if family in _ASYMMETRIC_FAMILIES and finding.quantum_risk == QuantumRisk.VULNERABLE:
        return "asymmetric_vulnerable"
    if finding.quantum_risk == QuantumRisk.WEAKENED:
        return "symmetric_weakened"
    return "other"


def compute_crypto_debt(result: ScanResult) -> CryptoDebt:
    """Compute crypto debt metric from scan results.

    The crypto debt score represents the total "cryptographic technical debt"
    in the codebase. Higher scores indicate more migration work needed.
    Unlike traditional tech debt, crypto debt has an "interest rate" —
    as quantum computing advances, the urgency (and thus cost) increases.
    """
    category_scores: dict[str, float] = defaultdict(float)
    total = 0.0

    for finding in result.findings:
        if finding.quantum_risk == QuantumRisk.SAFE:
            continue

        category = _categorize_finding(finding)
        weight = _CATEGORY_WEIGHTS.get(category, 1.0)

        # Severity multiplier
        sev_mult = {
            Severity.CRITICAL: 2.0,
            Severity.HIGH: 1.5,
            Severity.MEDIUM: 1.0,
            Severity.LOW: 0.5,
            Severity.INFO: 0.1,
        }.get(finding.severity, 1.0)

        score = weight * sev_mult
        category_scores[category] += score
        total += score

    # Interest rate: quantum progress makes asymmetric debt compound
    asymmetric_ratio = category_scores.get("asymmetric_vulnerable", 0) / max(total, 1)
    interest_rate = round(asymmetric_ratio * 15.0, 1)  # Up to 15% per year

    # Rough remediation hours estimate
    remediation_hours = total * 2.0  # ~2 hours per debt point

    return CryptoDebt(
        total_debt_score=round(total, 1),
        debt_by_category=dict(category_scores),
        estimated_remediation_hours=round(remediation_hours, 1),
        debt_interest_rate=interest_rate,
    )
