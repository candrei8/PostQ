"""Quantum timeline data models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class QuantumTimeline(BaseModel):
    """Prediction of when a specific algorithm becomes breakable."""

    algorithm_family: str
    key_size: int | None = None
    estimated_break_year_optimistic: int
    estimated_break_year_moderate: int
    estimated_break_year_conservative: int
    logical_qubits_required: int
    attack_type: str = ""
    confidence: str = "medium"


class HNDLRisk(BaseModel):
    """Harvest-Now-Decrypt-Later risk assessment."""

    data_shelf_life_years: int
    data_sensitivity: str = "internal"
    algorithm_break_year: int
    current_year: int
    hndl_risk_score: float = Field(ge=0.0, le=100.0)
    urgency: str  # "immediate", "urgent", "planned", "monitor"
    explanation: str = ""


class QuantumUrgency(BaseModel):
    """Combined urgency score for a finding."""

    timeline: QuantumTimeline
    hndl_risk: HNDLRisk | None = None
    urgency_score: float = Field(ge=0.0, le=100.0)
    recommended_migration_deadline: str = ""
