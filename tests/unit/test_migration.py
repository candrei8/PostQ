"""Tests for migration planner."""
from __future__ import annotations

import pytest

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding, ScanResult, ScanSummary
from quant_scan.migration.planner import generate_migration_plan
from quant_scan.migration.effort_estimator import estimate_hours, get_complexity, get_replacement_recommendation
from quant_scan.migration.vendor_recommender import recommend_vendor


def _make_result(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        findings=findings,
        summary=ScanSummary(total_findings=len(findings), files_scanned=1, score=50.0, grade="D"),
    )


def _make_finding(family: AlgorithmFamily) -> Finding:
    return Finding(
        rule_id="TEST", severity=Severity.HIGH, quantum_risk=QuantumRisk.VULNERABLE,
        algorithm=Algorithm(name=family.value, family=family, quantum_risk=QuantumRisk.VULNERABLE),
        location=FileLocation(file_path="test.py", line_number=1), message="Test",
    )


def test_generate_plan_empty():
    result = _make_result([])
    plan = generate_migration_plan(result)
    assert plan.total_tasks == 0
    assert plan.phases == []


def test_generate_plan_with_findings():
    findings = [_make_finding(AlgorithmFamily.RSA), _make_finding(AlgorithmFamily.DES)]
    result = _make_result(findings)
    plan = generate_migration_plan(result, organization="Test Corp", hourly_rate=200.0)
    assert plan.total_tasks > 0
    assert plan.organization == "Test Corp"
    assert plan.total_estimated_cost_eur > 0
    assert len(plan.phases) > 0
    assert plan.executive_summary != ""


def test_effort_estimation():
    finding = _make_finding(AlgorithmFamily.RSA)
    hours = estimate_hours(finding)
    assert hours > 0


def test_complexity_levels():
    assert get_complexity(1) == "low"
    assert get_complexity(5) == "medium"
    assert get_complexity(16) == "high"
    assert get_complexity(30) == "critical"


def test_replacement_recommendations():
    recs = get_replacement_recommendation("RSA")
    assert "signatures" in recs or "key_exchange" in recs


def test_vendor_recommender():
    assert recommend_vendor("tls_config") == "QuSecure"
    assert recommend_vendor("hsm") == "PQShield"
    assert recommend_vendor("library_call") == "OpenSource"
    assert recommend_vendor("embedded") == "PQShield"
    assert recommend_vendor("library_call", requires_fips=True) == "PQShield"
