"""CloudFormation parser — detects crypto configurations in CFN templates."""
from __future__ import annotations

import re

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding

_PATTERNS = [
    # AWS::KMS::Key with RSA KeySpec
    (
        re.compile(r"KeySpec\s*:\s*RSA_\d+", re.IGNORECASE),
        "IAC-CFN-KMS-RSA",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "AWS-KMS-RSA",
        "CloudFormation KMS key uses RSA — quantum vulnerable",
        "Plan migration to PQC KMS key types when AWS supports them",
    ),
    # AWS::KMS::Key with ECC KeySpec
    (
        re.compile(r"KeySpec\s*:\s*ECC_", re.IGNORECASE),
        "IAC-CFN-KMS-ECC",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.ECC,
        "AWS-KMS-ECC",
        "CloudFormation KMS key uses ECC — quantum vulnerable",
        "Plan migration to PQC KMS key types",
    ),
    # AWS::CertificateManager::Certificate
    (
        re.compile(r"AWS::CertificateManager::Certificate"),
        "IAC-CFN-ACM-CERT",
        Severity.MEDIUM,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "ACM-Certificate",
        "CloudFormation ACM certificate — likely uses RSA/ECDSA",
        "Audit certificate key algorithm; plan PQC migration",
    ),
    # Weak TLS policy on ELBv2
    (
        re.compile(r"SslPolicy\s*:\s*ELBSecurityPolicy-2016-08"),
        "IAC-CFN-ALB-WEAK-TLS",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "Weak-TLS-Policy",
        "CloudFormation ALB uses outdated TLS policy",
        "Update to ELBSecurityPolicy-TLS13-1-2-2021-06 or newer",
    ),
    # CloudFront MinimumProtocolVersion
    (
        re.compile(
            r"MinimumProtocolVersion\s*:\s*(TLSv1|TLSv1_2016|SSLv3)", re.IGNORECASE
        ),
        "IAC-CFN-CF-WEAK-TLS",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "Weak-CloudFront-TLS",
        "CloudFormation CloudFront allows deprecated TLS versions",
        "Set MinimumProtocolVersion to TLSv1.2_2021",
    ),
    # Generic RSA reference in KeyAlgorithm
    (
        re.compile(r"KeyAlgorithm\s*:\s*RSA_\d+", re.IGNORECASE),
        "IAC-CFN-KEY-RSA",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "CFN-RSA-Key",
        "CloudFormation resource uses RSA key algorithm — quantum vulnerable",
        "Plan migration to PQC algorithms",
    ),
    # Generic ECC reference in KeyAlgorithm
    (
        re.compile(r"KeyAlgorithm\s*:\s*EC_", re.IGNORECASE),
        "IAC-CFN-KEY-ECC",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.ECC,
        "CFN-ECC-Key",
        "CloudFormation resource uses ECC key algorithm — quantum vulnerable",
        "Plan migration to PQC algorithms",
    ),
]


def parse_cloudformation(file_path: str, content: str) -> list[Finding]:
    """Parse CloudFormation templates for crypto-related configurations."""
    findings: list[Finding] = []
    lines = content.splitlines()

    for (
        pattern,
        rule_id,
        severity,
        risk,
        family,
        algo_name,
        message,
        recommendation,
    ) in _PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            line_content = lines[line_num - 1] if line_num <= len(lines) else ""
            context_before = lines[max(0, line_num - 4) : line_num - 1]
            context_after = lines[line_num : min(len(lines), line_num + 3)]

            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    quantum_risk=risk,
                    algorithm=Algorithm(
                        name=algo_name,
                        family=family,
                        quantum_risk=risk,
                        description=message,
                    ),
                    location=FileLocation(
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line_content.strip(),
                        context_before=context_before,
                        context_after=context_after,
                    ),
                    message=message,
                    recommendation=recommendation,
                )
            )

    return findings
