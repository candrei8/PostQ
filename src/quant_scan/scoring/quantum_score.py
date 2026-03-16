"""QVSS — Quantum Vulnerability Scoring System (CVSS-like for PQC)."""

from __future__ import annotations

from pydantic import BaseModel, Field

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk
from quant_scan.core.models import Finding


class QVSSScore(BaseModel):
    """CVSS-like scoring adapted for quantum cryptographic risk."""

    # Base metrics (0-10)
    algorithm_vulnerability: float = Field(ge=0.0, le=10.0)
    key_strength: float = Field(ge=0.0, le=10.0)

    # Temporal metrics (0-10)
    quantum_timeline_proximity: float = Field(ge=0.0, le=10.0, default=5.0)
    patch_availability: float = Field(ge=0.0, le=10.0, default=5.0)

    # Environmental metrics (0-10)
    data_sensitivity: float = Field(ge=0.0, le=10.0, default=5.0)
    business_criticality: float = Field(ge=0.0, le=10.0, default=5.0)
    exposure_scope: float = Field(ge=0.0, le=10.0, default=5.0)

    # Computed scores
    base_score: float = Field(ge=0.0, le=10.0, default=0.0)
    temporal_score: float = Field(ge=0.0, le=10.0, default=0.0)
    environmental_score: float = Field(ge=0.0, le=10.0, default=0.0)
    overall_score: float = Field(ge=0.0, le=10.0, default=0.0)
    severity_label: str = "None"


# Algorithm vulnerability scores (Shor = max, Grover = medium, Safe = 0)
_ALGO_VULN: dict[QuantumRisk, float] = {
    QuantumRisk.VULNERABLE: 9.0,
    QuantumRisk.WEAKENED: 5.0,
    QuantumRisk.SAFE: 0.0,
    QuantumRisk.UNKNOWN: 3.0,
}

# Key strength impact (smaller keys = higher vulnerability)
_KEY_STRENGTH: dict[AlgorithmFamily, float] = {
    AlgorithmFamily.RSA: 7.0,
    AlgorithmFamily.ECC: 6.5,
    AlgorithmFamily.ECDSA: 6.5,
    AlgorithmFamily.ECDH: 6.5,
    AlgorithmFamily.DSA: 7.5,
    AlgorithmFamily.DH: 7.0,
    AlgorithmFamily.DES: 9.5,
    AlgorithmFamily.TRIPLE_DES: 8.0,
    AlgorithmFamily.RC4: 9.5,
    AlgorithmFamily.BLOWFISH: 7.0,
    AlgorithmFamily.MD5: 9.5,
    AlgorithmFamily.SHA1: 8.0,
    AlgorithmFamily.AES: 3.0,
    AlgorithmFamily.CHACHA20: 2.0,
    AlgorithmFamily.SHA2: 1.0,
    AlgorithmFamily.SHA3: 0.5,
}

# PQC replacement availability (higher = easier to patch)
_PATCH_AVAIL: dict[AlgorithmFamily, float] = {
    AlgorithmFamily.RSA: 6.0,  # ML-DSA/ML-KEM available
    AlgorithmFamily.ECC: 6.0,
    AlgorithmFamily.ECDSA: 6.0,
    AlgorithmFamily.ECDH: 6.0,
    AlgorithmFamily.DSA: 7.0,
    AlgorithmFamily.DH: 6.0,
    AlgorithmFamily.DES: 9.0,  # AES is trivial replacement
    AlgorithmFamily.TRIPLE_DES: 9.0,
    AlgorithmFamily.RC4: 9.0,
    AlgorithmFamily.BLOWFISH: 9.0,
    AlgorithmFamily.MD5: 9.0,  # SHA-256 is trivial
    AlgorithmFamily.SHA1: 9.0,
    AlgorithmFamily.AES: 8.0,  # Just increase key size
}


def compute_qvss(
    finding: Finding,
    data_sensitivity: float = 5.0,
    business_criticality: float = 5.0,
    exposure_scope: float = 5.0,
    timeline_proximity: float | None = None,
) -> QVSSScore:
    """Compute QVSS score for a finding.

    Parameters
    ----------
    finding:
        The vulnerability finding to score.
    data_sensitivity:
        0-10 scale (10 = top secret data).
    business_criticality:
        0-10 scale (10 = core payment system).
    exposure_scope:
        0-10 scale (10 = public-facing, internet-exposed).
    timeline_proximity:
        0-10 scale (10 = algorithm will be broken very soon).
        If None, derived from quantum risk level.
    """
    algo_vuln = _ALGO_VULN.get(finding.quantum_risk, 3.0)
    key_str = _KEY_STRENGTH.get(finding.algorithm.family, 5.0)

    # Adjust for specific key sizes
    if finding.algorithm.key_size:
        if finding.algorithm.family == AlgorithmFamily.RSA:
            if finding.algorithm.key_size <= 1024:
                key_str = 9.5
            elif finding.algorithm.key_size <= 2048:
                key_str = 7.0
            elif finding.algorithm.key_size >= 4096:
                key_str = 5.0

    # Base score
    base = min(10.0, (algo_vuln * 0.6 + key_str * 0.4))

    # Temporal score
    if timeline_proximity is None:
        timeline_proximity = {
            QuantumRisk.VULNERABLE: 7.0,
            QuantumRisk.WEAKENED: 4.0,
            QuantumRisk.SAFE: 0.0,
            QuantumRisk.UNKNOWN: 3.0,
        }.get(finding.quantum_risk, 5.0)

    patch_avail = _PATCH_AVAIL.get(finding.algorithm.family, 5.0)
    temporal = min(10.0, base * (1.0 + (timeline_proximity - patch_avail) * 0.05))

    # Environmental score
    env_factor = (data_sensitivity + business_criticality + exposure_scope) / 30.0
    environmental = min(10.0, temporal * (0.5 + env_factor * 0.5))

    # Overall
    overall = round(min(10.0, environmental), 1)

    # Severity label
    if overall >= 9.0:
        label = "Critical"
    elif overall >= 7.0:
        label = "High"
    elif overall >= 4.0:
        label = "Medium"
    elif overall >= 0.1:
        label = "Low"
    else:
        label = "None"

    return QVSSScore(
        algorithm_vulnerability=algo_vuln,
        key_strength=key_str,
        quantum_timeline_proximity=timeline_proximity,
        patch_availability=patch_avail,
        data_sensitivity=data_sensitivity,
        business_criticality=business_criticality,
        exposure_scope=exposure_scope,
        base_score=round(base, 1),
        temporal_score=round(temporal, 1),
        environmental_score=round(environmental, 1),
        overall_score=overall,
        severity_label=label,
    )
