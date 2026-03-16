"""Kubernetes manifest parser — detects crypto issues in K8s YAML."""

from __future__ import annotations

import re

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding

_PATTERNS = [
    # TLS Secret
    (
        re.compile(r"type\s*:\s*kubernetes\.io/tls"),
        "CTR-K8S-TLS-SECRET",
        Severity.MEDIUM,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "K8s-TLS-Secret",
        "Kubernetes TLS secret — audit underlying certificate algorithm",
        "Verify TLS certificate uses PQC-ready algorithms; plan migration",
    ),
    # Ingress TLS section
    (
        re.compile(r"kind\s*:\s*Ingress.*?tls\s*:", re.DOTALL),
        "CTR-K8S-INGRESS-TLS",
        Severity.MEDIUM,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "K8s-Ingress-TLS",
        "Kubernetes Ingress with TLS — audit certificate algorithm",
        "Verify Ingress TLS certificates use PQC-ready algorithms",
    ),
    # cert-manager Certificate with RSA algorithm
    (
        re.compile(
            r"kind\s*:\s*Certificate.*?algorithm\s*:\s*RSA",
            re.DOTALL | re.IGNORECASE,
        ),
        "CTR-K8S-CERTMGR-RSA",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "K8s-CertManager-RSA",
        "cert-manager Certificate uses RSA — quantum vulnerable",
        "Plan migration to PQC certificate algorithms",
    ),
    # cert-manager Certificate with ECDSA algorithm
    (
        re.compile(
            r"kind\s*:\s*Certificate.*?algorithm\s*:\s*ECDSA",
            re.DOTALL | re.IGNORECASE,
        ),
        "CTR-K8S-CERTMGR-ECDSA",
        Severity.HIGH,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.ECDSA,
        "K8s-CertManager-ECDSA",
        "cert-manager Certificate uses ECDSA — quantum vulnerable",
        "Plan migration to PQC certificate algorithms",
    ),
    # cert-manager Certificate with small key size
    (
        re.compile(r"kind\s*:\s*Certificate.*?size\s*:\s*1024", re.DOTALL),
        "CTR-K8S-CERTMGR-1024",
        Severity.CRITICAL,
        QuantumRisk.VULNERABLE,
        AlgorithmFamily.RSA,
        "K8s-CertManager-1024",
        "cert-manager Certificate with 1024-bit key — critically weak",
        "Increase to minimum 2048 bits; plan PQC migration",
    ),
    # Istio PeerAuthentication with permissive/disable mTLS
    (
        re.compile(
            r"kind\s*:\s*PeerAuthentication.*?mode\s*:\s*(PERMISSIVE|DISABLE)",
            re.DOTALL | re.IGNORECASE,
        ),
        "CTR-K8S-ISTIO-MTLS-WEAK",
        Severity.HIGH,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "Istio-Weak-mTLS",
        "Istio PeerAuthentication allows weak/no mTLS",
        "Set mTLS mode to STRICT; plan PQC certificate migration",
    ),
    # Istio DestinationRule with SIMPLE TLS (no mTLS)
    (
        re.compile(
            r"kind\s*:\s*DestinationRule.*?mode\s*:\s*SIMPLE",
            re.DOTALL | re.IGNORECASE,
        ),
        "CTR-K8S-ISTIO-TLS-SIMPLE",
        Severity.MEDIUM,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "Istio-Simple-TLS",
        "Istio DestinationRule uses SIMPLE TLS — no mutual authentication",
        "Use ISTIO_MUTUAL mode for mTLS; audit certificate algorithms",
    ),
    # Generic cert-manager Certificate resource
    (
        re.compile(r"kind\s*:\s*Certificate\s*\n", re.IGNORECASE),
        "CTR-K8S-CERTMGR",
        Severity.LOW,
        QuantumRisk.WEAKENED,
        AlgorithmFamily.RSA,
        "K8s-CertManager",
        "cert-manager Certificate resource — audit key algorithm for PQC readiness",
        "Verify certificate key algorithm; plan PQC migration",
    ),
]


def parse_kubernetes(file_path: str, content: str) -> list[Finding]:
    """Parse Kubernetes manifests for crypto-related configurations."""
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
