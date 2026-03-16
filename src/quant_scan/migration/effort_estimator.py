"""Effort estimation for PQC migration tasks."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from quant_scan.core.models import Finding

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"
_effort_data: dict | None = None


def _load_effort_data() -> dict:
    global _effort_data
    if _effort_data is None:
        path = _DATA_DIR / "effort_matrix.yml"
        try:
            with open(path, encoding="utf-8") as f:
                _effort_data = yaml.safe_load(f)
        except Exception:
            logger.exception("Failed to load effort matrix")
            _effort_data = {"base_hours": {}, "multipliers": {}, "replacements": {}}
    return _effort_data


def estimate_hours(
    finding: Finding,
    context_type: str = "library_call",
) -> float:
    """Estimate migration hours for a single finding.

    Parameters
    ----------
    finding:
        The vulnerability finding to estimate.
    context_type:
        Type of crypto usage: library_call, tls_config, certificate,
        key_management, custom_implementation.
    """
    data = _load_effort_data()
    base_hours = data.get("base_hours", {})
    family = finding.algorithm.family.value

    family_hours = base_hours.get(family, {})
    hours = family_hours.get(context_type, family_hours.get("library_call", 4))
    return float(hours)


def estimate_cost(hours: float, hourly_rate: float = 150.0) -> float:
    """Calculate cost in EUR from hours."""
    return round(hours * hourly_rate, 2)


def get_complexity(hours: float) -> str:
    """Classify task complexity based on estimated hours."""
    if hours <= 2:
        return "low"
    if hours <= 8:
        return "medium"
    if hours <= 24:
        return "high"
    return "critical"


def get_file_multiplier(file_count: int) -> float:
    """Get effort multiplier based on number of affected files."""
    data = _load_effort_data()
    multipliers = data.get("multipliers", {})
    if file_count <= 5:
        return multipliers.get("files_1_5", 1.0)
    if file_count <= 20:
        return multipliers.get("files_6_20", 1.5)
    if file_count <= 50:
        return multipliers.get("files_21_50", 2.0)
    return multipliers.get("files_50_plus", 3.0)


def get_replacement_recommendation(family: str) -> dict[str, str]:
    """Get PQC replacement recommendations for an algorithm family."""
    data = _load_effort_data()
    replacements = data.get("replacements", {})
    return replacements.get(family, {})
