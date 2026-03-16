"""Comparison data models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from quant_scan.core.models import Finding


class FindingDiff(BaseModel):
    """Difference for a single finding between two scans."""

    status: str  # "new", "resolved", "unchanged", "changed"
    finding: Finding
    previous_finding: Finding | None = None
    change_description: str = ""


class ScanComparison(BaseModel):
    """Result of comparing two scan results."""

    scan_a_timestamp: datetime
    scan_b_timestamp: datetime
    score_a: float
    score_b: float
    score_change: float
    grade_a: str
    grade_b: str
    new_findings: list[Finding] = Field(default_factory=list)
    resolved_findings: list[Finding] = Field(default_factory=list)
    unchanged_count: int = 0
    summary: str = ""


class TrendPoint(BaseModel):
    """A single point in a trend timeline."""

    timestamp: datetime
    score: float
    grade: str
    total_findings: int
    critical_count: int = 0
    pqc_readiness_pct: float = 0.0


class TrendAnalysis(BaseModel):
    """Analysis of score/findings over time."""

    points: list[TrendPoint] = Field(default_factory=list)
    score_trend: str = "stable"  # "improving", "stable", "degrading"
    average_improvement_per_scan: float = 0.0
    projected_compliance_date: str | None = None
