"""Middleware chain — composable post-processing for scan findings."""
from __future__ import annotations

from typing import Protocol

from quant_scan.core.context import ScanContext
from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.models import Finding


class Middleware(Protocol):
    """Protocol for finding post-processors."""

    def process(self, findings: list[Finding], context: ScanContext) -> list[Finding]:
        """Process findings and return the (possibly modified) list."""
        ...


class ContextAnalysisMiddleware:
    """Adjusts finding confidence based on code context clues."""

    def process(self, findings: list[Finding], context: ScanContext) -> list[Finding]:
        try:
            from quant_scan.scanners.context import ContextAnalyzer
            return ContextAnalyzer().analyze(findings)
        except ImportError:
            return findings


class ComplianceEnrichmentMiddleware:
    """Enriches findings with compliance framework references."""

    def process(self, findings: list[Finding], context: ScanContext) -> list[Finding]:
        try:
            from quant_scan.compliance.mapper import enrich_findings_with_compliance
            return enrich_findings_with_compliance(findings)
        except ImportError:
            return findings


class SeverityFilterMiddleware:
    """Filters findings below minimum severity threshold."""

    def process(self, findings: list[Finding], context: ScanContext) -> list[Finding]:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        min_idx = order.index(context.min_severity)
        allowed = set(order[: min_idx + 1])
        return [f for f in findings if f.severity in allowed]


class DeduplicationMiddleware:
    """Removes duplicate findings based on rule_id + file + line."""

    def process(self, findings: list[Finding], context: ScanContext) -> list[Finding]:
        seen: set[tuple[str, str, int]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.rule_id, f.location.file_path, f.location.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


class SortingMiddleware:
    """Sorts findings by severity (most severe first)."""

    _ORDER = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }

    def process(self, findings: list[Finding], context: ScanContext) -> list[Finding]:
        return sorted(findings, key=lambda f: self._ORDER.get(f.severity, 5))
