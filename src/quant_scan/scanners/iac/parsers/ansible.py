"""Ansible parser — detects crypto configurations in Ansible playbooks."""

from __future__ import annotations

import re

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding

_PATTERNS = [
    # openssl_privatekey with RSA type
    (
        re.compile(
            r"community\.crypto\.openssl_privatekey.*?type\s*:\s*RSA",
            re.DOTALL | re.IGNORECASE,
        ),
        "IAC-ANS-PRIVKEY-RSA",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "Ansible-RSA-PrivKey",
        "Ansible openssl_privatekey generates RSA key — quantum vulnerable",
        "Plan migration to PQC key types when community.crypto supports them",
    ),
    # openssl_privatekey with DSA type
    (
        re.compile(
            r"community\.crypto\.openssl_privatekey.*?type\s*:\s*DSA",
            re.DOTALL | re.IGNORECASE,
        ),
        "IAC-ANS-PRIVKEY-DSA",
        Severity.CRITICAL,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.DSA,
        "Ansible-DSA-PrivKey",
        "Ansible openssl_privatekey generates DSA key — weak and quantum vulnerable",
        "Stop using DSA immediately; migrate to PQC algorithms",
    ),
    # openssl_privatekey with ECC type
    (
        re.compile(
            r"community\.crypto\.openssl_privatekey.*?type\s*:\s*ECC",
            re.DOTALL | re.IGNORECASE,
        ),
        "IAC-ANS-PRIVKEY-ECC",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.ECC,
        "Ansible-ECC-PrivKey",
        "Ansible openssl_privatekey generates ECC key — quantum vulnerable",
        "Plan migration to PQC key types",
    ),
    # Simpler pattern: openssl_privatekey module usage (without dotall)
    (
        re.compile(r"openssl_privatekey\s*:", re.IGNORECASE),
        "IAC-ANS-PRIVKEY",
        Severity.MEDIUM,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "Ansible-PrivKey",
        "Ansible uses openssl_privatekey — audit key type for PQC readiness",
        "Verify key algorithm and plan PQC migration",
    ),
    # x509_certificate module
    (
        re.compile(r"community\.crypto\.x509_certificate", re.IGNORECASE),
        "IAC-ANS-X509",
        Severity.MEDIUM,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "Ansible-X509-Cert",
        "Ansible generates x509 certificate — likely uses classical crypto",
        "Audit certificate key algorithm; plan PQC migration",
    ),
    # openssl_csr with privatekey_size (small keys)
    (
        re.compile(r"privatekey_size\s*:\s*1024"),
        "IAC-ANS-CSR-1024",
        Severity.CRITICAL,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "Ansible-RSA-1024",
        "Ansible CSR with 1024-bit key — critically weak",
        "Increase to minimum 2048 bits immediately; plan PQC migration",
    ),
    (
        re.compile(r"privatekey_size\s*:\s*2048"),
        "IAC-ANS-CSR-2048",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "Ansible-RSA-2048",
        "Ansible CSR with 2048-bit key — quantum vulnerable",
        "Plan migration to PQC algorithms",
    ),
    # uri module with validate_certs: false
    (
        re.compile(r"validate_certs\s*:\s*(false|no)\b", re.IGNORECASE),
        "IAC-ANS-NO-CERT-VALID",
        Severity.HIGH,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "Ansible-No-CertValidation",
        "Ansible disables certificate validation — weakens TLS security",
        "Enable certificate validation; use proper CA trust chain",
    ),
]


def parse_ansible(file_path: str, content: str) -> list[Finding]:
    """Parse Ansible playbooks for crypto-related configurations."""
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
