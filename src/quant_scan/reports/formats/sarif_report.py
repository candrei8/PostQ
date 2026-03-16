"""SARIF v2.1.0 report generator — for GitHub Security tab integration."""

from __future__ import annotations

import json
from typing import Any

from quant_scan.core.enums import Severity
from quant_scan.core.models import ScanResult

# Map quant-scan severity to SARIF level
_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Map severity to SARIF security-severity (numeric)
_SEVERITY_TO_SCORE: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.5",
    Severity.INFO: "1.0",
}


def render_sarif(result: ScanResult) -> str:
    """Render scan results as SARIF v2.1.0 JSON.

    The SARIF format integrates directly with GitHub's Security tab,
    allowing findings to appear as code scanning alerts.
    """
    # Build rules array from unique rule IDs
    rules_map: dict[str, dict[str, Any]] = {}
    for finding in result.findings:
        if finding.rule_id not in rules_map:
            rules_map[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.message},
                "fullDescription": {
                    "text": f"{finding.message}. {finding.recommendation}"
                },
                "help": {
                    "text": finding.recommendation,
                    "markdown": (
                        f"**Algorithm:** {finding.algorithm.name}\n\n"
                        f"**Quantum Risk:** {finding.quantum_risk.value}\n\n"
                        f"**Recommendation:** {finding.recommendation}"
                    ),
                },
                "properties": {
                    "security-severity": _SEVERITY_TO_SCORE.get(
                        finding.severity, "5.0"
                    ),
                    "tags": [
                        "security",
                        "cryptography",
                        "post-quantum",
                        finding.quantum_risk.value,
                    ],
                },
            }

    # Build results array
    results: list[dict[str, Any]] = []
    for finding in result.findings:
        sarif_result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": list(rules_map.keys()).index(finding.rule_id),
            "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
            "message": {
                "text": (
                    f"{finding.message}. Algorithm: {finding.algorithm.name} "
                    f"(Quantum Risk: {finding.quantum_risk.value}). "
                    f"{finding.recommendation}"
                ),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location.file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.location.line_number,
                            "startColumn": 1,
                        },
                    },
                }
            ],
        }

        # Add code flow context if available
        if finding.location.line_content:
            sarif_result["locations"][0]["physicalLocation"]["region"][
                "snippet"
            ] = {"text": finding.location.line_content}

        results.append(sarif_result)

    # Build SARIF document
    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "quant-scan",
                        "informationUri": "https://github.com/eyd-company/quant-scan",
                        "version": result.scanner_version,
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": result.timestamp.isoformat(),
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)
