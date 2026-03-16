"""Compliance gap analysis — evaluates compliance posture per framework."""
from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, Field

from quant_scan.compliance.mapper import ComplianceMapper
from quant_scan.core.models import ScanResult


class FrameworkGap(BaseModel):
    """Gap analysis for a single compliance framework."""

    framework: str
    total_findings_checked: int = 0
    compliant_count: int = 0
    non_compliant_count: int = 0
    action_required_count: int = 0
    compliance_percentage: float = 0.0
    critical_gaps: list[str] = Field(default_factory=list)
    earliest_deadline: str | None = None


class GapAnalysisReport(BaseModel):
    """Complete compliance gap analysis across all frameworks."""

    frameworks: list[FrameworkGap] = Field(default_factory=list)
    overall_compliance_pct: float = 0.0
    total_gaps: int = 0
    most_critical_framework: str = ""


def analyze_compliance_gaps(result: ScanResult) -> GapAnalysisReport:
    """Perform compliance gap analysis on scan results.

    Evaluates each finding against all compliance frameworks and
    produces a per-framework compliance assessment.
    """
    mapper = ComplianceMapper()

    # Collect refs per framework
    by_framework: dict[str, dict] = defaultdict(
        lambda: {
            "compliant": 0,
            "non_compliant": 0,
            "action_required": 0,
            "total": 0,
            "critical_gaps": [],
            "deadlines": [],
        }
    )

    for finding in result.findings:
        refs = mapper.map_finding(finding)
        for ref in refs:
            fw_data = by_framework[ref.framework]
            fw_data["total"] += 1
            if ref.status == "compliant":
                fw_data["compliant"] += 1
            elif ref.status == "non_compliant":
                fw_data["non_compliant"] += 1
                fw_data["critical_gaps"].append(
                    f"{ref.requirement_id}: {ref.description}"
                )
            elif ref.status == "action_required":
                fw_data["action_required"] += 1
            if ref.deadline:
                fw_data["deadlines"].append(ref.deadline)

    # Build framework gaps
    frameworks: list[FrameworkGap] = []
    total_gaps = 0

    for fw_name, data in sorted(by_framework.items()):
        total = data["total"]
        non_compliant = data["non_compliant"]
        action_required = data["action_required"]
        compliant = data["compliant"]

        compliant_total = compliant + non_compliant + action_required
        pct = (compliant / compliant_total * 100) if compliant_total > 0 else 100.0

        deadlines = sorted(set(data["deadlines"]))
        earliest = deadlines[0] if deadlines else None

        # Deduplicate critical gaps
        unique_gaps = sorted(set(data["critical_gaps"]))

        frameworks.append(
            FrameworkGap(
                framework=fw_name,
                total_findings_checked=total,
                compliant_count=compliant,
                non_compliant_count=non_compliant,
                action_required_count=action_required,
                compliance_percentage=round(pct, 1),
                critical_gaps=unique_gaps[:20],  # Cap
                earliest_deadline=earliest,
            )
        )

        total_gaps += non_compliant

    # Overall compliance
    overall_pct = 0.0
    if frameworks:
        overall_pct = round(
            sum(f.compliance_percentage for f in frameworks) / len(frameworks), 1
        )

    # Most critical framework (lowest compliance %)
    most_critical = ""
    if frameworks:
        worst = min(frameworks, key=lambda f: f.compliance_percentage)
        most_critical = worst.framework

    return GapAnalysisReport(
        frameworks=frameworks,
        overall_compliance_pct=overall_pct,
        total_gaps=total_gaps,
        most_critical_framework=most_critical,
    )
