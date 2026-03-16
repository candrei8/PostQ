"""Scan result differ — compares two scan results."""

from __future__ import annotations

from quant_scan.comparison.models import ScanComparison
from quant_scan.core.models import Finding, ScanResult


def _finding_key(finding: Finding) -> tuple[str, str, str]:
    """Generate a composite key for matching findings across scans."""
    return (
        finding.rule_id,
        finding.location.file_path,
        finding.algorithm.name,
    )


def compare_scans(scan_a: ScanResult, scan_b: ScanResult) -> ScanComparison:
    """Compare two scan results to identify new, resolved, and unchanged findings.

    Parameters
    ----------
    scan_a:
        The earlier (baseline) scan result.
    scan_b:
        The later (current) scan result.

    Returns
    -------
    ScanComparison:
        Detailed comparison with new findings, resolved findings, and metrics.
    """
    # Build lookup sets
    keys_a = {_finding_key(f): f for f in scan_a.findings}
    keys_b = {_finding_key(f): f for f in scan_b.findings}

    set_a = set(keys_a.keys())
    set_b = set(keys_b.keys())

    # New findings: in B but not in A
    new_keys = set_b - set_a
    new_findings = [keys_b[k] for k in new_keys]

    # Resolved findings: in A but not in B
    resolved_keys = set_a - set_b
    resolved_findings = [keys_a[k] for k in resolved_keys]

    # Unchanged: in both
    unchanged_count = len(set_a & set_b)

    # Score change
    score_change = round(scan_b.summary.score - scan_a.summary.score, 1)

    # Build summary text
    parts: list[str] = []
    if score_change > 0:
        parts.append(f"Score improved by {score_change} points")
    elif score_change < 0:
        parts.append(f"Score decreased by {abs(score_change)} points")
    else:
        parts.append("Score unchanged")

    parts.append(f"({scan_a.summary.grade} -> {scan_b.summary.grade})")

    if new_findings:
        parts.append(f"{len(new_findings)} new findings")
    if resolved_findings:
        parts.append(f"{len(resolved_findings)} resolved findings")
    parts.append(f"{unchanged_count} unchanged")

    return ScanComparison(
        scan_a_timestamp=scan_a.timestamp,
        scan_b_timestamp=scan_b.timestamp,
        score_a=scan_a.summary.score,
        score_b=scan_b.summary.score,
        score_change=score_change,
        grade_a=scan_a.summary.grade,
        grade_b=scan_b.summary.grade,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        unchanged_count=unchanged_count,
        summary=". ".join(parts),
    )
