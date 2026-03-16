"""Migration planning data models."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class MigrationTask(BaseModel):
    """A single migration action item."""

    id: str
    title: str
    description: str
    from_algorithm: str
    to_algorithm: str
    priority: int = Field(ge=1, le=5, description="1=highest priority")
    risk_level: str  # "critical", "high", "medium", "low"
    estimated_hours: float
    estimated_cost_eur: float
    complexity: str  # "low", "medium", "high", "critical"
    affected_files: list[str] = Field(default_factory=list)
    affected_file_count: int = 0
    dependencies: list[str] = Field(default_factory=list)
    phase: int = 1
    recommended_approach: str = "direct_replacement"
    vendor_recommendation: str | None = None


class MigrationPhase(BaseModel):
    """A group of tasks to execute in a phase."""

    phase_number: int
    name: str
    description: str = ""
    tasks: list[MigrationTask] = Field(default_factory=list)
    total_hours: float = 0.0
    total_cost_eur: float = 0.0


class MigrationPlan(BaseModel):
    """Complete organizational PQC migration plan."""

    organization: str = ""
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    total_findings: int = 0
    total_tasks: int = 0
    phases: list[MigrationPhase] = Field(default_factory=list)
    total_estimated_hours: float = 0.0
    total_estimated_cost_eur: float = 0.0
    overall_timeline_months: int = 0
    risk_summary: str = ""
    executive_summary: str = ""
