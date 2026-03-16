"""Pydantic v2 data models — the contract between all components."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity


# ---------------------------------------------------------------------------
# Algorithm metadata
# ---------------------------------------------------------------------------


class Algorithm(BaseModel):
    """A cryptographic algorithm with its quantum-risk profile."""

    name: str
    family: AlgorithmFamily
    key_size: int | None = None
    quantum_risk: QuantumRisk
    pqc_replacements: list[str] = Field(default_factory=list)
    eu_deadline: str | None = None
    description: str = ""


# ---------------------------------------------------------------------------
# Location inside a scanned file
# ---------------------------------------------------------------------------


class FileLocation(BaseModel):
    """Exact position of a finding within a file."""

    file_path: str
    line_number: int
    line_content: str = ""
    context_before: list[str] = Field(default_factory=list)
    context_after: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Individual finding
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A single cryptographic issue detected by a scanner."""

    rule_id: str
    severity: Severity
    quantum_risk: QuantumRisk
    algorithm: Algorithm
    location: FileLocation
    message: str
    recommendation: str = ""
    compliance_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    scanner_type: str = ""


# ---------------------------------------------------------------------------
# Scan summary and result
# ---------------------------------------------------------------------------


class ScanSummary(BaseModel):
    """Aggregated statistics for a scan."""

    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_quantum_risk: dict[str, int] = Field(default_factory=dict)
    files_scanned: int = 0
    score: float = Field(default=100.0, ge=0.0, le=100.0)
    grade: str = "A"
    pqc_readiness_pct: float = Field(default=100.0, ge=0.0, le=100.0)

    @staticmethod
    def compute_grade(score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"


class ScanResult(BaseModel):
    """Complete result of a scan run."""

    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    targets: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    scanner_version: str = "0.1.0"
    duration_seconds: float = 0.0
