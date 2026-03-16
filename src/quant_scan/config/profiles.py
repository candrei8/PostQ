"""Built-in scan profiles — pre-configured scanning modes."""

from __future__ import annotations

from quant_scan.config.schema import (
    ComplianceSection,
    PerformanceSection,
    QualityGateSection,
    ScanConfig,
    ScanSection,
    ScannersSection,
)

PROFILES: dict[str, ScanConfig] = {
    "quick": ScanConfig(
        scan=ScanSection(min_severity="high"),
        scanners=ScannersSection(enabled=["source"]),
        performance=PerformanceSection(max_workers=8, max_file_size_mb=1),
    ),
    "standard": ScanConfig(
        scan=ScanSection(min_severity="info"),
        scanners=ScannersSection(enabled=["source", "certificate", "config", "dependency"]),
        performance=PerformanceSection(max_workers=4, max_file_size_mb=10),
    ),
    "deep": ScanConfig(
        scan=ScanSection(min_severity="info"),
        scanners=ScannersSection(
            enabled=["source", "certificate", "config", "dependency", "secrets", "iac"]
        ),
        performance=PerformanceSection(max_workers=4, max_file_size_mb=50),
    ),
    "paranoid": ScanConfig(
        scan=ScanSection(min_severity="info"),
        scanners=ScannersSection(
            enabled=[
                "source", "certificate", "config", "dependency",
                "secrets", "iac", "binary", "network",
            ]
        ),
        performance=PerformanceSection(
            max_workers=4, max_file_size_mb=100, file_cache=False
        ),
    ),
}


def get_profile(name: str) -> ScanConfig | None:
    """Return a built-in scan profile by name."""
    return PROFILES.get(name)
