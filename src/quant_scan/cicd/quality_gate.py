"""Quality gate — pass/fail evaluation for CI/CD pipelines."""

from __future__ import annotations

from pydantic import BaseModel, Field

from quant_scan.core.models import ScanResult


class QualityGateResult(BaseModel):
    """Result of a quality gate evaluation."""

    passed: bool
    score: float
    grade: str
    reasons: list[str] = Field(default_factory=list)


class QualityGate:
    """Configurable quality gate for scan results.

    Evaluates whether a scan result meets defined thresholds.
    Used by CI/CD integrations to determine exit codes.
    """

    def __init__(
        self,
        min_score: float = 70.0,
        max_critical: int = 0,
        max_high: int = 5,
    ) -> None:
        self.min_score = min_score
        self.max_critical = max_critical
        self.max_high = max_high

    def evaluate(self, result: ScanResult) -> QualityGateResult:
        """Evaluate whether the scan result passes the quality gate."""
        reasons: list[str] = []

        score = result.summary.score
        grade = result.summary.grade
        critical_count = result.summary.by_severity.get("critical", 0)
        high_count = result.summary.by_severity.get("high", 0)

        if score < self.min_score:
            reasons.append(
                f"Score {score} is below minimum {self.min_score}"
            )

        if critical_count > self.max_critical:
            reasons.append(
                f"Critical findings: {critical_count} (max allowed: {self.max_critical})"
            )

        if high_count > self.max_high:
            reasons.append(
                f"High findings: {high_count} (max allowed: {self.max_high})"
            )

        return QualityGateResult(
            passed=len(reasons) == 0,
            score=score,
            grade=grade,
            reasons=reasons,
        )
