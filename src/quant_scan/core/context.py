"""Shared scan context — configuration passed through the scan pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from quant_scan.core.enums import Severity


@dataclass
class ScanContext:
    """Immutable-ish bag of settings shared by all scanners in a run."""

    targets: list[Path] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    min_severity: Severity = Severity.INFO
    output_format: str = "console"
    output_file: str | None = None
    languages: list[str] = field(default_factory=list)
    no_color: bool = False
