"""Scoring algorithm — 0-100 score with A-F grade."""

from __future__ import annotations

from quant_scan.core.enums import Severity
from quant_scan.core.models import Finding, ScanSummary


def format_score_display(summary: ScanSummary) -> str:
    """Human-readable score string."""
    return f"{summary.score:.0f}/100 (Grade {summary.grade})"


def format_readiness_display(summary: ScanSummary) -> str:
    """Human-readable PQC readiness string."""
    return f"{summary.pqc_readiness_pct:.0f}%"


def compute_advanced_score(findings: list[Finding], files_scanned: int) -> float:
    """Compute a weighted security score from 0 to 100.

    The algorithm applies heavier penalties for critical findings and
    accounts for how many distinct files are affected relative to the
    total files scanned.

    Scoring logic:
      1. Each finding carries a *weighted penalty* derived from
         ``Severity.weight`` with an extra multiplier for CRITICAL.
      2. A *file spread factor* (ratio of affected files to total files)
         amplifies the penalty — widespread issues are worse.
      3. The raw penalty is subtracted from 100 and clamped to [0, 100].
    """
    if not findings or files_scanned == 0:
        return 100.0

    # Severity multipliers (on top of Severity.weight)
    _SEVERITY_MULTIPLIER: dict[Severity, float] = {
        Severity.CRITICAL: 3.0,
        Severity.HIGH: 1.5,
        Severity.MEDIUM: 1.0,
        Severity.LOW: 0.5,
        Severity.INFO: 0.0,
    }

    # Sum weighted penalties
    total_penalty = 0.0
    affected_files: set[str] = set()

    for f in findings:
        weight = f.severity.weight * _SEVERITY_MULTIPLIER.get(f.severity, 1.0)
        total_penalty += weight
        affected_files.add(f.location.file_path)

    # File spread factor: 1.0 when only one file, up to 2.0 when all files affected
    spread = len(affected_files) / files_scanned
    spread_factor = 1.0 + spread  # range [1.0, 2.0]

    adjusted_penalty = total_penalty * spread_factor

    # Normalize: cap the maximum effective penalty at 100
    score = max(0.0, min(100.0, 100.0 - adjusted_penalty))
    return round(score, 1)
