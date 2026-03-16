"""Scan pipeline events for the event bus."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from quant_scan.core.models import Finding, ScanResult


@dataclass(frozen=True)
class ScanEvent:
    """Base class for all scan events."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class ScanStarted(ScanEvent):
    """Emitted when a scan begins."""

    targets: list[str] = field(default_factory=list)
    scanner_names: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ScannerStarted(ScanEvent):
    """Emitted when an individual scanner begins."""

    scanner_name: str = ""


@dataclass(frozen=True)
class FindingDetected(ScanEvent):
    """Emitted when a scanner produces a finding."""

    finding: Finding | None = None


@dataclass(frozen=True)
class ScannerCompleted(ScanEvent):
    """Emitted when an individual scanner finishes."""

    scanner_name: str = ""
    finding_count: int = 0
    duration_seconds: float = 0.0


@dataclass(frozen=True)
class ScanCompleted(ScanEvent):
    """Emitted when the entire scan finishes."""

    result: ScanResult | None = None


@dataclass(frozen=True)
class ScanError(ScanEvent):
    """Emitted when an error occurs during scanning."""

    error: str = ""
    scanner_name: str = ""
    context: dict[str, Any] = field(default_factory=dict)
