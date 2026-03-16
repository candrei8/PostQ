"""Secrets scanner — detects hardcoded cryptographic secrets and keys."""

from __future__ import annotations

import math
import re

from quant_scan.core.context import ScanContext
from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding
from quant_scan.scanners.base import BaseScanner
from quant_scan.scanners.registry import register

# PEM private key headers
_PEM_PATTERNS = [
    (re.compile(r"-----BEGIN RSA PRIVATE KEY-----"), "RSA", AlgorithmFamily.RSA, Severity.CRITICAL),
    (re.compile(r"-----BEGIN DSA PRIVATE KEY-----"), "DSA", AlgorithmFamily.DSA, Severity.CRITICAL),
    (re.compile(r"-----BEGIN EC PRIVATE KEY-----"), "ECC", AlgorithmFamily.ECC, Severity.CRITICAL),
    (re.compile(r"-----BEGIN PRIVATE KEY-----"), "PKCS#8", AlgorithmFamily.RSA, Severity.CRITICAL),
    (re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), "OpenSSH", AlgorithmFamily.RSA, Severity.CRITICAL),
    (re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"), "Encrypted-PKCS#8", AlgorithmFamily.RSA, Severity.HIGH),
    (re.compile(r"-----BEGIN CERTIFICATE-----"), "X.509-Embedded", AlgorithmFamily.RSA, Severity.MEDIUM),
]

# Cloud crypto service API keys/URLs
_API_KEY_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS-Access-Key", Severity.CRITICAL),
    (re.compile(r"https://[a-zA-Z0-9-]+\.vault\.azure\.net/keys/"), "Azure-Key-Vault-URL", Severity.HIGH),
    (
        re.compile(r"projects/[a-zA-Z0-9-]+/locations/[a-zA-Z0-9-]+/keyRings/[a-zA-Z0-9-]+/cryptoKeys/"),
        "GCP-KMS-Key",
        Severity.HIGH,
    ),
    (re.compile(r"hvs\.[a-zA-Z0-9]{24,}"), "HashiCorp-Vault-Token", Severity.CRITICAL),
]

# Weak key generation patterns
_WEAK_KEYGEN_PATTERNS = [
    (re.compile(r"""(?:key|secret|password|token)\s*=\s*['"][^'"]{4,}['"]"""), "Hardcoded-Secret", Severity.HIGH),
    (re.compile(r"iv\s*=\s*(?:b)?['\"]\\x00|iv\s*=\s*bytes\(\s*16\s*\)"), "Static-IV", Severity.HIGH),
    (re.compile(r"random\.seed\(\s*\d+\s*\)|srand\(\s*\d+\s*\)|srand\(time\("), "Weak-Seed", Severity.HIGH),
]

# File extensions to skip (binary, media, etc.)
_SKIP_EXTENSIONS = {
    ".pem",
    ".crt",
    ".cer",
    ".der",
    ".p12",
    ".pfx",
    ".key",  # cert/key files handled by cert scanner
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".bmp",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".o",
    ".a",
    ".pyc",
    ".pyo",
    ".class",
    ".jar",
    ".war",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".wav",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
}

# Source code extensions to scan
_SOURCE_EXTENSIONS = {
    ".py",
    ".java",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".go",
    ".c",
    ".cpp",
    ".cc",
    ".h",
    ".hpp",
    ".cs",
    ".rs",
    ".swift",
    ".kt",
    ".kts",
    ".php",
    ".rb",
    ".scala",
    ".sc",
    ".dart",
    ".yaml",
    ".yml",
    ".json",
    ".xml",
    ".toml",
    ".ini",
    ".cfg",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".env",
    ".properties",
    ".conf",
    ".tf",
    ".hcl",
    ".dockerfile",
    ".docker-compose.yml",
}


def _shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


@register("secrets")
class SecretScanner(BaseScanner):
    """Detects hardcoded cryptographic secrets, keys, and credentials."""

    name = "secrets"

    def scan(self, context: ScanContext) -> list[Finding]:
        # Scan all text files, not just specific extensions
        all_exts = _SOURCE_EXTENSIONS
        files = self.collect_files(context, all_exts)
        findings: list[Finding] = []

        for file_path in files:
            if file_path.suffix.lower() in _SKIP_EXTENSIONS:
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            lines = content.splitlines()
            for line_num, line in enumerate(lines, start=1):
                # Check PEM patterns
                for pattern, key_type, family, severity in _PEM_PATTERNS:
                    if pattern.search(line):
                        context_before = lines[max(0, line_num - 4) : line_num - 1]
                        context_after = lines[line_num : min(len(lines), line_num + 3)]
                        findings.append(
                            Finding(
                                rule_id=f"SEC-PEM-{key_type.upper().replace('#', '').replace('.', '')}",
                                severity=severity,
                                quantum_risk=QuantumRisk.VULNERABLE,
                                algorithm=Algorithm(
                                    name=f"{key_type}-PrivateKey",
                                    family=family,
                                    quantum_risk=QuantumRisk.VULNERABLE,
                                    description=f"Hardcoded {key_type} private key in source code",
                                ),
                                location=FileLocation(
                                    file_path=str(file_path),
                                    line_number=line_num,
                                    line_content=line.strip(),
                                    context_before=context_before,
                                    context_after=context_after,
                                ),
                                message=f"Hardcoded {key_type} private key detected in source code",
                                recommendation=(
                                    "Remove private keys from source code. "
                                    "Use secure key management "
                                    "(HSM, vault, environment variables)"
                                ),
                                scanner_type=self.name,
                            )
                        )

                # Check API key patterns
                for pattern, service, severity in _API_KEY_PATTERNS:
                    if pattern.search(line):
                        context_before = lines[max(0, line_num - 4) : line_num - 1]
                        context_after = lines[line_num : min(len(lines), line_num + 3)]
                        findings.append(
                            Finding(
                                rule_id=f"SEC-APIKEY-{service.upper().replace('-', '')}",
                                severity=severity,
                                quantum_risk=QuantumRisk.UNKNOWN,
                                algorithm=Algorithm(
                                    name=f"{service}-Credential",
                                    family=AlgorithmFamily.UNKNOWN,
                                    quantum_risk=QuantumRisk.UNKNOWN,
                                    description=f"Hardcoded {service} credential",
                                ),
                                location=FileLocation(
                                    file_path=str(file_path),
                                    line_number=line_num,
                                    line_content=line.strip(),
                                    context_before=context_before,
                                    context_after=context_after,
                                ),
                                message=f"Hardcoded {service} credential detected",
                                recommendation="Use environment variables or secret management services",
                                scanner_type=self.name,
                            )
                        )

                # Check weak key generation patterns
                for pattern, issue_type, severity in _WEAK_KEYGEN_PATTERNS:
                    if pattern.search(line):
                        context_before = lines[max(0, line_num - 4) : line_num - 1]
                        context_after = lines[line_num : min(len(lines), line_num + 3)]
                        findings.append(
                            Finding(
                                rule_id=f"SEC-WEAK-{issue_type.upper().replace('-', '')}",
                                severity=severity,
                                quantum_risk=QuantumRisk.UNKNOWN,
                                algorithm=Algorithm(
                                    name=issue_type,
                                    family=AlgorithmFamily.RANDOM,
                                    quantum_risk=QuantumRisk.UNKNOWN,
                                    description=f"Weak cryptographic practice: {issue_type}",
                                ),
                                location=FileLocation(
                                    file_path=str(file_path),
                                    line_number=line_num,
                                    line_content=line.strip(),
                                    context_before=context_before,
                                    context_after=context_after,
                                ),
                                message=f"Weak cryptographic practice detected: {issue_type.replace('-', ' ').lower()}",
                                recommendation=(
                                    "Use cryptographically secure random "
                                    "number generators and proper key management"
                                ),
                                scanner_type=self.name,
                            )
                        )

        return findings
