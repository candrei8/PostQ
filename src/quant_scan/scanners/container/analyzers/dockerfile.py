"""Dockerfile parser — detects crypto issues in Dockerfiles."""

from __future__ import annotations

import re

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding

_PATTERNS = [
    # openssl genrsa — RSA key generation in build
    (
        re.compile(r"RUN\s+.*openssl\s+genrsa", re.IGNORECASE),
        "CTR-DOCKER-GENRSA",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "Docker-OpenSSL-GenRSA",
        "Dockerfile generates RSA key with openssl genrsa — quantum vulnerable",
        "Avoid baking keys into images; use runtime secret injection with PQC keys",
    ),
    # openssl genrsa with small key size
    (
        re.compile(r"RUN\s+.*openssl\s+genrsa\s+.*\b1024\b", re.IGNORECASE),
        "CTR-DOCKER-GENRSA-1024",
        Severity.CRITICAL,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "Docker-RSA-1024",
        "Dockerfile generates 1024-bit RSA key — critically weak",
        "Stop using 1024-bit RSA; use minimum 2048 bits and plan PQC migration",
    ),
    # openssl ecparam — ECC key generation
    (
        re.compile(r"RUN\s+.*openssl\s+ecparam", re.IGNORECASE),
        "CTR-DOCKER-ECPARAM",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.ECC,
        "Docker-OpenSSL-ECParam",
        "Dockerfile generates ECC key with openssl ecparam — quantum vulnerable",
        "Plan migration to PQC key types",
    ),
    # openssl req -newkey rsa
    (
        re.compile(r"RUN\s+.*openssl\s+req\s+.*-newkey\s+rsa:", re.IGNORECASE),
        "CTR-DOCKER-REQ-RSA",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "Docker-OpenSSL-Req-RSA",
        "Dockerfile creates RSA CSR via openssl req — quantum vulnerable",
        "Use PQC-capable certificate tools when available",
    ),
    # openssl req (generic — likely RSA)
    (
        re.compile(r"RUN\s+.*openssl\s+req\b", re.IGNORECASE),
        "CTR-DOCKER-REQ",
        Severity.MEDIUM,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "Docker-OpenSSL-Req",
        "Dockerfile runs openssl req — audit key algorithm for PQC readiness",
        "Verify key algorithm used; plan PQC migration",
    ),
    # COPY *.pem or *.key — embedding certs/keys in image
    (
        re.compile(r"COPY\s+.*\*?\.(pem|key|crt|cert)\b", re.IGNORECASE),
        "CTR-DOCKER-EMBED-CERTS",
        Severity.MEDIUM,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "Docker-Embedded-Certs",
        "Dockerfile copies certificate/key files into image",
        "Use runtime secret injection instead of embedding keys in images",
    ),
    # pip install pycryptodome
    (
        re.compile(r"RUN\s+.*pip\s+install\s+.*pycryptodome", re.IGNORECASE),
        "CTR-DOCKER-PIP-PYCRYPTODOME",
        Severity.MEDIUM,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "Docker-PyCryptodome",
        "Dockerfile installs pycryptodome — may use quantum-vulnerable algorithms",
        "Audit pycryptodome usage for RSA/ECC; consider PQC-ready alternatives",
    ),
    # pip install cryptography
    (
        re.compile(r"RUN\s+.*pip\s+install\s+.*cryptography\b", re.IGNORECASE),
        "CTR-DOCKER-PIP-CRYPTOGRAPHY",
        Severity.LOW,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "Docker-Cryptography",
        "Dockerfile installs cryptography library — audit for PQC readiness",
        "Audit cryptography usage for quantum-vulnerable algorithms",
    ),
    # npm install crypto-js
    (
        re.compile(r"RUN\s+.*npm\s+install\s+.*crypto-js", re.IGNORECASE),
        "CTR-DOCKER-NPM-CRYPTOJS",
        Severity.MEDIUM,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "Docker-CryptoJS",
        "Dockerfile installs crypto-js — may use quantum-vulnerable algorithms",
        "Audit crypto-js usage; consider PQC-ready alternatives",
    ),
    # npm install node-forge
    (
        re.compile(r"RUN\s+.*npm\s+install\s+.*node-forge", re.IGNORECASE),
        "CTR-DOCKER-NPM-NODEFORGE",
        Severity.MEDIUM,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "Docker-NodeForge",
        "Dockerfile installs node-forge — may use quantum-vulnerable algorithms",
        "Audit node-forge usage for RSA/ECC; consider PQC-ready alternatives",
    ),
]


def parse_dockerfile(file_path: str, content: str) -> list[Finding]:
    """Parse Dockerfiles for crypto-related instructions."""
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
