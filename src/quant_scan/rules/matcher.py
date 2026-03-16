"""Pattern-matching engine — compiles YAML regex rules and runs them."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding
from quant_scan.rules.loader import SourceRule, load_algorithms


@dataclass
class CompiledRule:
    """A rule with its regex pre-compiled for fast scanning."""

    rule: SourceRule
    regex: re.Pattern[str]


class RuleMatcher:
    """Compiles rules once and matches them against source lines."""

    def __init__(self, rules: list[SourceRule]) -> None:
        self._algorithms = load_algorithms()
        self._compiled: list[CompiledRule] = []
        for r in rules:
            try:
                self._compiled.append(
                    CompiledRule(rule=r, regex=re.compile(r.pattern))
                )
            except re.error:
                pass  # skip malformed regex

    def match_line(
        self,
        line: str,
        file_path: str,
        line_number: int,
        *,
        context_before: list[str] | None = None,
        context_after: list[str] | None = None,
    ) -> list[Finding]:
        """Return all findings that match this line."""
        findings: list[Finding] = []
        for cr in self._compiled:
            if cr.regex.search(line):
                algo = self._resolve_algorithm(cr.rule)
                severity = cr.rule.severity_override or self._algo_severity(
                    cr.rule.algorithm_key
                )
                qr = cr.rule.quantum_risk_override or algo.quantum_risk

                findings.append(
                    Finding(
                        rule_id=cr.rule.id,
                        severity=severity,
                        quantum_risk=qr,
                        algorithm=algo,
                        location=FileLocation(
                            file_path=file_path,
                            line_number=line_number,
                            line_content=line.rstrip(),
                            context_before=context_before or [],
                            context_after=context_after or [],
                        ),
                        message=cr.rule.message,
                        recommendation=cr.rule.recommendation,
                    )
                )
        return findings

    def match_file(self, file_path: str, content: str) -> list[Finding]:
        """Scan all lines in a file and return findings."""
        lines = content.splitlines()
        findings: list[Finding] = []
        for i, line in enumerate(lines, start=1):
            ctx_before = lines[max(0, i - 3) : i - 1]
            ctx_after = lines[i : i + 2]
            findings.extend(
                self.match_line(
                    line,
                    file_path,
                    i,
                    context_before=ctx_before,
                    context_after=ctx_after,
                )
            )
        return findings

    # -- helpers --

    def _resolve_algorithm(self, rule: SourceRule) -> Algorithm:
        algo = self._algorithms.get(rule.algorithm_key)
        if algo:
            return algo
        return Algorithm(
            name=rule.algorithm_key,
            family="Unknown",
            quantum_risk=QuantumRisk.UNKNOWN,
        )

    def _algo_severity(self, key: str) -> Severity:
        raw = self._algorithms.get(key)
        if not raw:
            return Severity.MEDIUM
        risk = raw.quantum_risk
        return {
            QuantumRisk.VULNERABLE: Severity.HIGH,
            QuantumRisk.WEAKENED: Severity.MEDIUM,
            QuantumRisk.SAFE: Severity.INFO,
            QuantumRisk.UNKNOWN: Severity.LOW,
        }.get(risk, Severity.MEDIUM)
