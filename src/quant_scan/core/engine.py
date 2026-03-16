"""Scan engine — orchestrates scanners, aggregates results."""

from __future__ import annotations

import time

from quant_scan.core.context import ScanContext
from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.models import Finding, ScanResult, ScanSummary
from quant_scan.scanners.base import BaseScanner
from quant_scan.scanners.registry import get_all_scanners, get_scanner

# Import scanner modules so their @register decorators execute
import quant_scan.scanners.source.scanner  # noqa: F401


class ScanEngine:
    """Orchestrates scanners and builds a ScanResult."""

    def run(
        self,
        context: ScanContext,
        scanner_names: list[str] | None = None,
    ) -> ScanResult:
        """Execute the scan pipeline and return aggregated results."""
        start = time.monotonic()

        # Pick scanners
        if scanner_names:
            scanners: list[BaseScanner] = [
                get_scanner(n) for n in scanner_names
            ]
        else:
            scanners = get_all_scanners()

        # Run scanners
        all_findings: list[Finding] = []
        for scanner in scanners:
            findings = scanner.scan(context)
            all_findings.extend(findings)

        # Filter by severity
        all_findings = self._filter_severity(all_findings, context.min_severity)

        # Build summary
        summary = self._build_summary(all_findings)

        elapsed = time.monotonic() - start
        return ScanResult(
            findings=all_findings,
            summary=summary,
            targets=[str(t) for t in context.targets],
            duration_seconds=round(elapsed, 2),
        )

    @staticmethod
    def _filter_severity(
        findings: list[Finding], min_severity: Severity
    ) -> list[Finding]:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        min_idx = order.index(min_severity)
        allowed = set(order[: min_idx + 1])
        return [f for f in findings if f.severity in allowed]

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
