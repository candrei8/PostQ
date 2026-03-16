"""Quantum timeline predictor — estimates when algorithms become breakable."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk
from quant_scan.core.models import Finding
from quant_scan.quantum_timeline.models import QuantumTimeline

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"

# Map algorithm families to threshold keys
_FAMILY_TO_THRESHOLD: dict[AlgorithmFamily, str] = {
    AlgorithmFamily.RSA: "RSA-2048",
    AlgorithmFamily.ECC: "ECC-256",
    AlgorithmFamily.ECDSA: "ECC-256",
    AlgorithmFamily.ECDH: "ECC-256",
    AlgorithmFamily.DSA: "DSA",
    AlgorithmFamily.DH: "DH",
    AlgorithmFamily.AES: "AES-128",
}

# More specific mapping for key-size-aware lookup
_KEYSIZE_MAP: dict[tuple[AlgorithmFamily, int | None], str] = {
    (AlgorithmFamily.RSA, 1024): "RSA-1024",
    (AlgorithmFamily.RSA, 2048): "RSA-2048",
    (AlgorithmFamily.RSA, 4096): "RSA-4096",
    (AlgorithmFamily.ECC, 256): "ECC-256",
    (AlgorithmFamily.ECC, 384): "ECC-384",
}


def _load_thresholds() -> dict[str, dict]:
    """Load algorithm threshold data from YAML."""
    path = _DATA_DIR / "algorithm_thresholds.yml"
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("thresholds", {})
    except Exception:
        logger.exception("Failed to load quantum thresholds from %s", path)
        return {}


_thresholds: dict[str, dict] | None = None


def _get_thresholds() -> dict[str, dict]:
    global _thresholds
    if _thresholds is None:
        _thresholds = _load_thresholds()
    return _thresholds


def predict_timeline(finding: Finding) -> QuantumTimeline | None:
    """Predict when the algorithm used in a finding becomes breakable.

    Returns None for algorithms that are already broken classically
    or that are post-quantum safe.
    """
    if finding.quantum_risk == QuantumRisk.SAFE:
        return None

    thresholds = _get_thresholds()
    family = finding.algorithm.family
    key_size = finding.algorithm.key_size

    # Try specific key-size match first
    threshold_key = _KEYSIZE_MAP.get((family, key_size))
    if threshold_key is None:
        threshold_key = _FAMILY_TO_THRESHOLD.get(family)

    if threshold_key is None or threshold_key not in thresholds:
        return None

    t = thresholds[threshold_key]
    return QuantumTimeline(
        algorithm_family=family.value,
        key_size=key_size,
        estimated_break_year_optimistic=t["break_year_optimistic"],
        estimated_break_year_moderate=t["break_year_moderate"],
        estimated_break_year_conservative=t["break_year_conservative"],
        logical_qubits_required=t["logical_qubits"],
        attack_type=t.get("attack", ""),
        confidence=t.get("confidence", "medium"),
    )


def predict_timelines(findings: list[Finding]) -> dict[str, QuantumTimeline]:
    """Predict timelines for all unique algorithm families in findings."""
    seen: set[str] = set()
    timelines: dict[str, QuantumTimeline] = {}

    for finding in findings:
        key = f"{finding.algorithm.family.value}-{finding.algorithm.key_size}"
        if key in seen:
            continue
        seen.add(key)

        timeline = predict_timeline(finding)
        if timeline:
            timelines[key] = timeline

    return timelines
