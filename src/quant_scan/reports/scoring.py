"""Scoring algorithm — 0-100 score with A-F grade."""

from quant_scan.core.models import ScanSummary


def format_score_display(summary: ScanSummary) -> str:
    """Human-readable score string."""
    return f"{summary.score:.0f}/100 (Grade {summary.grade})"


def format_readiness_display(summary: ScanSummary) -> str:
    """Human-readable PQC readiness string."""
    return f"{summary.pqc_readiness_pct:.0f}%"
