"""Harvest-Now-Decrypt-Later (HNDL) risk scoring."""

from __future__ import annotations

from datetime import datetime, timezone

from quant_scan.quantum_timeline.models import HNDLRisk, QuantumTimeline

# Sensitivity multipliers for HNDL urgency
_SENSITIVITY_WEIGHT: dict[str, float] = {
    "public": 0.2,
    "internal": 0.5,
    "confidential": 0.8,
    "top_secret": 1.0,
}


def compute_hndl_risk(
    timeline: QuantumTimeline,
    data_shelf_life_years: int = 10,
    data_sensitivity: str = "internal",
) -> HNDLRisk:
    """Compute HNDL risk for a given quantum timeline and data context.

    The core insight: if data must remain confidential for N years,
    and the algorithm protecting it will be broken in M years,
    then if N > M the data is already at risk from harvest-now-decrypt-later
    attacks by nation-state adversaries.

    Parameters
    ----------
    timeline:
        Quantum timeline prediction for the algorithm.
    data_shelf_life_years:
        How many years the data must remain confidential.
    data_sensitivity:
        Classification: public, internal, confidential, top_secret.
    """
    current_year = datetime.now(timezone.utc).year
    break_year = timeline.estimated_break_year_moderate

    # How many years until the algorithm is broken
    years_until_break = break_year - current_year

    # How many years the data outlives algorithm security
    hndl_gap = data_shelf_life_years - years_until_break

    # Compute urgency
    if hndl_gap > 0:
        urgency = "immediate"
        explanation = (
            f"Data must be confidential for {data_shelf_life_years} years, "
            f"but {timeline.algorithm_family} is projected to be broken by {break_year} "
            f"({years_until_break} years from now). Data is ALREADY at risk from "
            f"harvest-now-decrypt-later attacks."
        )
    elif hndl_gap > -5:
        urgency = "urgent"
        explanation = (
            f"Algorithm projected to be broken within {years_until_break} years "
            f"(by {break_year}), close to the {data_shelf_life_years}-year "
            f"data shelf life. Migration should begin immediately."
        )
    elif hndl_gap > -10:
        urgency = "planned"
        explanation = (
            f"Algorithm projected to be broken in {years_until_break} years "
            f"(by {break_year}). Plan migration within the next 5 years."
        )
    else:
        urgency = "monitor"
        explanation = (
            f"Algorithm projected to be broken in {years_until_break} years "
            f"(by {break_year}). Monitor quantum computing progress."
        )

    # Score: 0 (no risk) to 100 (maximum risk)
    sensitivity_weight = _SENSITIVITY_WEIGHT.get(data_sensitivity, 0.5)
    base_score = max(0.0, min(100.0, (hndl_gap + 15) * 5))
    score = min(100.0, base_score * sensitivity_weight * 1.5)

    return HNDLRisk(
        data_shelf_life_years=data_shelf_life_years,
        data_sensitivity=data_sensitivity,
        algorithm_break_year=break_year,
        current_year=current_year,
        hndl_risk_score=round(score, 1),
        urgency=urgency,
        explanation=explanation,
    )
