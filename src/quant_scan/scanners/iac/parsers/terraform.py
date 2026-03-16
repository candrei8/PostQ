"""Terraform parser — detects crypto configurations in .tf files."""

from __future__ import annotations

import re

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding

# Patterns for Terraform resources with crypto configurations
_PATTERNS = [
    # tls_private_key with RSA
    (
        re.compile(r'resource\s+"tls_private_key".*?algorithm\s*=\s*"RSA"', re.DOTALL),
        "IAC-TF-TLS-RSA",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "RSA-TLS-Key",
        "Terraform tls_private_key uses RSA",
        "Migrate to post-quantum key types when Terraform provider supports ML-DSA",
    ),
    # tls_private_key with ECDSA
    (
        re.compile(r'resource\s+"tls_private_key".*?algorithm\s*=\s*"ECDSA"', re.DOTALL),
        "IAC-TF-TLS-ECDSA",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.ECDSA,
        "ECDSA-TLS-Key",
        "Terraform tls_private_key uses ECDSA",
        "Plan migration to ML-DSA when available",
    ),
    # Small RSA key size
    (
        re.compile(r"rsa_bits\s*=\s*1024"),
        "IAC-TF-RSA-1024",
        Severity.CRITICAL,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "RSA-1024",
        "Terraform RSA key with 1024 bits — critically weak",
        "Increase to minimum 2048 bits immediately, plan PQC migration",
    ),
    (
        re.compile(r"rsa_bits\s*=\s*2048"),
        "IAC-TF-RSA-2048",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "RSA-2048",
        "Terraform RSA key with 2048 bits — quantum vulnerable",
        "Plan migration to ML-DSA",
    ),
    # AWS KMS RSA keys
    (
        re.compile(r'customer_master_key_spec\s*=\s*"RSA_\d+"'),
        "IAC-TF-KMS-RSA",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "AWS-KMS-RSA",
        "AWS KMS key uses RSA — quantum vulnerable",
        "Plan migration to PQC KMS key types when AWS supports them",
    ),
    # AWS KMS ECC keys
    (
        re.compile(r'customer_master_key_spec\s*=\s*"ECC_'),
        "IAC-TF-KMS-ECC",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.ECC,
        "AWS-KMS-ECC",
        "AWS KMS key uses ECC — quantum vulnerable",
        "Plan migration to PQC KMS key types",
    ),
    # Weak TLS policies on AWS ALB/NLB
    (
        re.compile(r'ssl_policy\s*=\s*"ELBSecurityPolicy-2016-08"'),
        "IAC-TF-ALB-WEAK-TLS",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "Weak-TLS-Policy",
        "AWS load balancer uses outdated TLS policy",
        "Update to ELBSecurityPolicy-TLS13-1-2-2021-06 or newer",
    ),
    # CloudFront weak protocol
    (
        re.compile(r'minimum_protocol_version\s*=\s*"(TLSv1|TLSv1_2016|SSLv3)"'),
        "IAC-TF-CF-WEAK-TLS",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "Weak-CloudFront-TLS",
        "CloudFront distribution allows deprecated TLS versions",
        "Set minimum_protocol_version to TLSv1.2_2021",
    ),
    # Azure Key Vault RSA
    (
        re.compile(r'key_type\s*=\s*"RSA"'),
        "IAC-TF-AKV-RSA",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "Azure-KV-RSA",
        "Azure Key Vault key uses RSA — quantum vulnerable",
        "Plan migration to PQC key types when Azure supports them",
    ),
    # Azure Key Vault EC
    (
        re.compile(r'key_type\s*=\s*"EC"'),
        "IAC-TF-AKV-EC",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.ECC,
        "Azure-KV-EC",
        "Azure Key Vault key uses EC — quantum vulnerable",
        "Plan migration to PQC key types",
    ),
    # GCP KMS RSA
    (
        re.compile(r'algorithm\s*=\s*"RSA_'),
        "IAC-TF-GCP-KMS-RSA",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "GCP-KMS-RSA",
        "GCP KMS crypto key uses RSA — quantum vulnerable",
        "Plan migration to PQC algorithms",
    ),
    # GCP KMS EC
    (
        re.compile(r'algorithm\s*=\s*"EC_SIGN_'),
        "IAC-TF-GCP-KMS-EC",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.ECC,
        "GCP-KMS-EC",
        "GCP KMS crypto key uses EC — quantum vulnerable",
        "Plan migration to PQC algorithms",
    ),
]


def parse_terraform(file_path: str, content: str) -> list[Finding]:
    """Parse Terraform files for crypto-related configurations."""
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
            # Find line number
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
