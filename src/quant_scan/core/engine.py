"""Scan engine — orchestrates scanners, aggregates results."""
from __future__ import annotations

import time

from quant_scan.core.context import ScanContext
from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.event_bus import EventBus
from quant_scan.core.events import (
    FindingDetected,
    ScanCompleted,
    ScanError,
    ScannerCompleted,
    ScannerStarted,
    ScanStarted,
)
from quant_scan.core.middleware import (
    ComplianceEnrichmentMiddleware,
    ContextAnalysisMiddleware,
    DeduplicationMiddleware,
    Middleware,
    SeverityFilterMiddleware,
    SortingMiddleware,
)
from quant_scan.core.models import Finding, ScanResult, ScanSummary
from quant_scan.scanners.base import BaseScanner
from quant_scan.scanners.registry import get_all_scanners, get_scanner

# Import scanner modules so their @register decorators execute
import quant_scan.scanners.source.scanner  # noqa: F401

# Try importing optional scanner modules
for _mod in (
    "quant_scan.scanners.certificate.scanner",
    "quant_scan.scanners.config.scanner",
    "quant_scan.scanners.dependency.scanner",
    "quant_scan.scanners.secrets.scanner",
    "quant_scan.scanners.network.scanner",
    "quant_scan.scanners.binary.scanner",
    "quant_scan.scanners.iac.scanner",
    "quant_scan.scanners.cloud.scanner",
    "quant_scan.scanners.container.scanner",
):
    try:
        __import__(_mod)
    except ImportError:
        pass


def default_middleware() -> list[Middleware]:
    """Return the standard middleware chain."""
    return [
        ContextAnalysisMiddleware(),
        ComplianceEnrichmentMiddleware(),
        DeduplicationMiddleware(),
        SeverityFilterMiddleware(),
        SortingMiddleware(),
    ]


class ScanEngine:
    """Orchestrates scanners and builds a ScanResult."""

    def __init__(
        self,
        *,
        scanners: list[BaseScanner] | None = None,
        event_bus: EventBus | None = None,
        middleware: list[Middleware] | None = None,
    ) -> None:
        self._scanners = scanners
        self._event_bus = event_bus or EventBus()
        self._middleware = middleware if middleware is not None else default_middleware()

    @property
    def event_bus(self) -> EventBus:
        return self._event_bus

    def run(
        self,
        context: ScanContext,
        scanner_names: list[str] | None = None,
    ) -> ScanResult:
        """Execute the scan pipeline and return aggregated results."""
        start = time.monotonic()

        # Pick scanners
        if self._scanners:
            scanners = self._scanners
        elif scanner_names:
            scanners = [get_scanner(n) for n in scanner_names]
        else:
            scanners = get_all_scanners()

        self._event_bus.emit(ScanStarted(
            targets=[str(t) for t in context.targets],
            scanner_names=[s.name for s in scanners],
        ))

        # Run scanners
        all_findings: list[Finding] = []
        for scanner in scanners:
            scanner_start = time.monotonic()
            self._event_bus.emit(ScannerStarted(scanner_name=scanner.name))

            try:
                findings = scanner.scan(context)
                for f in findings:
                    self._event_bus.emit(FindingDetected(finding=f))
                all_findings.extend(findings)
                scanner_finding_count = len(findings)
            except Exception as exc:
                self._event_bus.emit(ScanError(
                    error=str(exc),
                    scanner_name=scanner.name,
                ))
                scanner_finding_count = 0

            scanner_elapsed = time.monotonic() - scanner_start
            self._event_bus.emit(ScannerCompleted(
                scanner_name=scanner.name,
                finding_count=scanner_finding_count,
                duration_seconds=round(scanner_elapsed, 3),
            ))

        # Apply middleware chain
        for mw in self._middleware:
            all_findings = mw.process(all_findings, context)

        # Build summary
        summary = self._build_summary(all_findings)

        elapsed = time.monotonic() - start
        result = ScanResult(
            findings=all_findings,
            summary=summary,
            targets=[str(t) for t in context.targets],
            duration_seconds=round(elapsed, 2),
        )

        self._event_bus.emit(ScanCompleted(result=result))
        return result

    @staticmethod
    def _build_summary(findings: list[Finding]) -> ScanSummary:
        by_severity: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        files_seen: set[str] = set()

        for f in findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            by_risk[f.quantum_risk.value] = by_risk.get(f.quantum_risk.value, 0) + 1
            files_seen.add(f.location.file_path)

        # Score: start at 100, deduct by severity weight
        penalty = sum(f.severity.weight for f in findings)
        score = max(0.0, min(100.0, 100.0 - penalty))

        # PQC readiness: % of findings that are safe
        total = len(findings) if findings else 1
        safe_count = sum(
            1 for f in findings if f.quantum_risk == QuantumRisk.SAFE
        )
        pqc_pct = (safe_count / total) * 100 if findings else 100.0

        return ScanSummary(
            total_findings=len(findings),
            by_severity=by_severity,
            by_quantum_risk=by_risk,
            files_scanned=len(files_seen),
            score=round(score, 1),
            grade=ScanSummary.compute_grade(score),
            pqc_readiness_pct=round(pqc_pct, 1),
        )
