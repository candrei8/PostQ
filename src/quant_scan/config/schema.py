"""Configuration schema — Pydantic v2 models for scan configuration."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScanSection(BaseModel):
    """Scan behavior configuration."""

    exclude_patterns: list[str] = Field(default_factory=list)
    min_severity: str = "info"
    languages: list[str] = Field(default_factory=list)


class ScannersSection(BaseModel):
    """Scanner selection and per-scanner configuration."""

    enabled: list[str] = Field(default_factory=list)


class OutputSection(BaseModel):
    """Output and report configuration."""

    format: str = "console"
    file: str | None = None
    no_color: bool = False
    language: str = "en"
    client_name: str = ""
    client_logo: str | None = None
    branding_color: str = "#6c7ee1"


class ComplianceSection(BaseModel):
    """Compliance framework configuration."""

    frameworks: list[str] = Field(default_factory=list)
    data_shelf_life: int = 10
    data_sensitivity: str = "internal"


class PerformanceSection(BaseModel):
    """Performance tuning configuration."""

    max_workers: int = 4
    file_cache: bool = False
    max_file_size_mb: int = 10
    incremental: bool = False


class QualityGateSection(BaseModel):
    """Quality gate thresholds for CI/CD."""

    enabled: bool = False
    min_score: float = 70.0
    max_critical: int = 0
    max_high: int = 5


class ScanConfig(BaseModel):
    """Root configuration model for quant-scan."""

    scan: ScanSection = Field(default_factory=ScanSection)
    scanners: ScannersSection = Field(default_factory=ScannersSection)
    output: OutputSection = Field(default_factory=OutputSection)
    compliance: ComplianceSection = Field(default_factory=ComplianceSection)
    performance: PerformanceSection = Field(default_factory=PerformanceSection)
    quality_gate: QualityGateSection = Field(default_factory=QualityGateSection)
