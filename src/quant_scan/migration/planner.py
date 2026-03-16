"""Migration planner — generates PQC migration roadmaps from scan results."""

from __future__ import annotations

import logging
from collections import defaultdict

from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.models import Finding, ScanResult
from quant_scan.migration.effort_estimator import (
    estimate_cost,
    estimate_hours,
    get_complexity,
    get_file_multiplier,
    get_replacement_recommendation,
)
from quant_scan.migration.models import MigrationPhase, MigrationPlan, MigrationTask
from quant_scan.migration.vendor_recommender import recommend_vendor

logger = logging.getLogger(__name__)

# Phase definitions
_PHASES = [
    (1, "Critical Infrastructure", "Migrate classically broken and critical quantum-vulnerable algorithms"),
    (2, "Core Business Systems", "Migrate high-priority quantum-vulnerable algorithms"),
    (3, "Supporting Systems", "Migrate remaining quantum-vulnerable algorithms"),
    (4, "Optimization", "Upgrade quantum-weakened algorithms and optimize"),
]

# Priority mapping: (severity, quantum_risk) -> priority (1=highest)
_PRIORITY_MAP: dict[tuple[Severity, QuantumRisk], int] = {
    (Severity.CRITICAL, QuantumRisk.VULNERABLE): 1,
    (Severity.HIGH, QuantumRisk.VULNERABLE): 1,
    (Severity.CRITICAL, QuantumRisk.WEAKENED): 2,
    (Severity.MEDIUM, QuantumRisk.VULNERABLE): 2,
    (Severity.HIGH, QuantumRisk.WEAKENED): 2,
    (Severity.LOW, QuantumRisk.VULNERABLE): 3,
    (Severity.MEDIUM, QuantumRisk.WEAKENED): 3,
    (Severity.LOW, QuantumRisk.WEAKENED): 4,
    (Severity.INFO, QuantumRisk.VULNERABLE): 4,
    (Severity.INFO, QuantumRisk.WEAKENED): 5,
}

# Phase assignment based on priority
_PRIORITY_TO_PHASE: dict[int, int] = {1: 1, 2: 2, 3: 3, 4: 4, 5: 4}


def generate_migration_plan(
    result: ScanResult,
    organization: str = "",
    hourly_rate: float = 150.0,
) -> MigrationPlan:
    """Generate a PQC migration plan from scan results.

    Groups findings by algorithm family, creates migration tasks,
    assigns priorities and phases, and estimates effort/cost.
    """
    # Group findings by algorithm family
    by_family: dict[str, list[Finding]] = defaultdict(list)
    for finding in result.findings:
        if finding.quantum_risk in (QuantumRisk.VULNERABLE, QuantumRisk.WEAKENED):
            by_family[finding.algorithm.family.value].append(finding)

    # Generate tasks
    tasks: list[MigrationTask] = []
    task_id = 0

    for family, findings in sorted(by_family.items()):
        task_id += 1
        family_files = list({f.location.file_path for f in findings})
        file_count = len(family_files)

        # Use the worst severity/risk from the group
        worst_severity = max(findings, key=lambda f: f.severity.weight).severity
        worst_risk = (
            QuantumRisk.VULNERABLE
            if any(f.quantum_risk == QuantumRisk.VULNERABLE for f in findings)
            else QuantumRisk.WEAKENED
        )

        priority = _PRIORITY_MAP.get(
            (worst_severity, worst_risk), 3
        )
        phase = _PRIORITY_TO_PHASE.get(priority, 3)

        # Estimate effort
        base_hours_val = estimate_hours(findings[0])
        multiplier = get_file_multiplier(file_count)
        total_hours = round(base_hours_val * multiplier, 1)
        cost = estimate_cost(total_hours, hourly_rate)

        # Get replacement
        replacements = get_replacement_recommendation(family)
        to_algo = next(iter(replacements.values()), "PQC equivalent")

        # Vendor recommendation
        vendor = recommend_vendor(
            context_type="library_call",
            is_critical=(priority <= 2),
        )

        tasks.append(MigrationTask(
            id=f"MIG-{task_id:03d}",
            title=f"Migrate {family} to {to_algo}",
            description=(
                f"Replace {len(findings)} instances of {family} across "
                f"{file_count} files with post-quantum safe alternative"
            ),
            from_algorithm=family,
            to_algorithm=to_algo,
            priority=priority,
            risk_level=worst_severity.value,
            estimated_hours=total_hours,
            estimated_cost_eur=cost,
            complexity=get_complexity(total_hours),
            affected_files=family_files[:20],  # Cap display
            affected_file_count=file_count,
            phase=phase,
            recommended_approach=(
                "hybrid_transition" if priority <= 2 else "direct_replacement"
            ),
            vendor_recommendation=vendor,
        ))

    # Organize into phases
    phases: list[MigrationPhase] = []
    for phase_num, phase_name, phase_desc in _PHASES:
        phase_tasks = [t for t in tasks if t.phase == phase_num]
        if not phase_tasks:
            continue
        phases.append(MigrationPhase(
            phase_number=phase_num,
            name=phase_name,
            description=phase_desc,
            tasks=phase_tasks,
            total_hours=sum(t.estimated_hours for t in phase_tasks),
            total_cost_eur=sum(t.estimated_cost_eur for t in phase_tasks),
        ))

    total_hours = sum(p.total_hours for p in phases)
    total_cost = sum(p.total_cost_eur for p in phases)
    timeline_months = max(1, int(total_hours / 160) + 1)  # ~160 hours/month

    # Generate executive summary
    critical_count = sum(1 for t in tasks if t.priority == 1)
    high_count = sum(1 for t in tasks if t.priority == 2)

    executive_summary = (
        f"The PQC vulnerability assessment identified {result.summary.total_findings} "
        f"cryptographic findings across {result.summary.files_scanned} files. "
        f"The migration plan contains {len(tasks)} tasks organized in "
        f"{len(phases)} phases, with an estimated effort of {total_hours:.0f} hours "
        f"({total_cost:,.0f} EUR). "
    )
    if critical_count > 0:
        executive_summary += (
            f"{critical_count} critical tasks require immediate attention. "
        )
    if high_count > 0:
        executive_summary += f"{high_count} high-priority tasks should begin within 6 months. "

    risk_summary = (
        f"Score: {result.summary.score}/100 (Grade {result.summary.grade}). "
        f"PQC Readiness: {result.summary.pqc_readiness_pct}%. "
        f"Critical migrations: {critical_count}. "
        f"Estimated timeline: {timeline_months} months."
    )

    return MigrationPlan(
        organization=organization,
        total_findings=result.summary.total_findings,
        total_tasks=len(tasks),
        phases=phases,
        total_estimated_hours=total_hours,
        total_estimated_cost_eur=total_cost,
        overall_timeline_months=timeline_months,
        risk_summary=risk_summary,
        executive_summary=executive_summary,
    )
