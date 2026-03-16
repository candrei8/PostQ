"""String analysis — extracts and matches crypto strings in binaries."""
from __future__ import annotations

import re

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding

# Minimum string length to extract
_MIN_STRING_LEN = 6

# Crypto-related string patterns to match
_STRING_PATTERNS = [
    # PEM headers
    (re.compile(rb"-----BEGIN RSA PRIVATE KEY-----"), "BIN-PEM-RSA", Severity.CRITICAL, QuantumRisk.VULNERABLE, AlgorithmFamily.RSA, "Embedded RSA private key in binary"),
    (re.compile(rb"-----BEGIN EC PRIVATE KEY-----"), "BIN-PEM-EC", Severity.CRITICAL, QuantumRisk.VULNERABLE, AlgorithmFamily.ECC, "Embedded EC private key in binary"),
    (re.compile(rb"-----BEGIN DSA PRIVATE KEY-----"), "BIN-PEM-DSA", Severity.CRITICAL, QuantumRisk.VULNERABLE, AlgorithmFamily.DSA, "Embedded DSA private key in binary"),
    (re.compile(rb"-----BEGIN PRIVATE KEY-----"), "BIN-PEM-PKCS8", Severity.CRITICAL, QuantumRisk.VULNERABLE, AlgorithmFamily.RSA, "Embedded PKCS#8 private key in binary"),
    (re.compile(rb"-----BEGIN CERTIFICATE-----"), "BIN-PEM-CERT", Severity.MEDIUM, QuantumRisk.UNKNOWN, AlgorithmFamily.RSA, "Embedded certificate in binary"),

    # Algorithm name strings
    (re.compile(rb"RSA_generate_key"), "BIN-STR-RSA-KEYGEN", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.RSA, "RSA key generation function reference"),
    (re.compile(rb"EC_KEY_generate_key"), "BIN-STR-EC-KEYGEN", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.ECC, "EC key generation function reference"),
    (re.compile(rb"DSA_generate_key"), "BIN-STR-DSA-KEYGEN", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.DSA, "DSA key generation function reference"),
    (re.compile(rb"DH_generate_key"), "BIN-STR-DH-KEYGEN", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.DH, "DH key generation function reference"),

    # OpenSSL EVP function names
    (re.compile(rb"EVP_des_"), "BIN-STR-EVP-DES", Severity.CRITICAL, QuantumRisk.VULNERABLE, AlgorithmFamily.DES, "DES cipher usage via OpenSSL EVP"),
    (re.compile(rb"EVP_rc4"), "BIN-STR-EVP-RC4", Severity.CRITICAL, QuantumRisk.VULNERABLE, AlgorithmFamily.RC4, "RC4 cipher usage via OpenSSL EVP"),
    (re.compile(rb"EVP_md5"), "BIN-STR-EVP-MD5", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.MD5, "MD5 hash usage via OpenSSL EVP"),
    (re.compile(rb"EVP_sha1\b"), "BIN-STR-EVP-SHA1", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.SHA1, "SHA-1 hash usage via OpenSSL EVP"),

    # Library identifiers
    (re.compile(rb"OpenSSL\s+\d+\.\d+"), "BIN-STR-OPENSSL", Severity.INFO, QuantumRisk.UNKNOWN, AlgorithmFamily.UNKNOWN, "OpenSSL library linked"),
    (re.compile(rb"mbedTLS"), "BIN-STR-MBEDTLS", Severity.INFO, QuantumRisk.UNKNOWN, AlgorithmFamily.UNKNOWN, "mbedTLS library linked"),
    (re.compile(rb"BoringSSL"), "BIN-STR-BORINGSSL", Severity.INFO, QuantumRisk.UNKNOWN, AlgorithmFamily.UNKNOWN, "BoringSSL library linked"),
    (re.compile(rb"wolfSSL"), "BIN-STR-WOLFSSL", Severity.INFO, QuantumRisk.UNKNOWN, AlgorithmFamily.UNKNOWN, "wolfSSL library linked"),

    # OID strings (ASN.1 object identifiers)
    (re.compile(rb"1\.2\.840\.113549\.1\.1\.1"), "BIN-OID-RSA", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.RSA, "RSA OID found in binary (1.2.840.113549.1.1.1)"),
    (re.compile(rb"1\.2\.840\.10045\.2\.1"), "BIN-OID-EC", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.ECC, "EC OID found in binary (1.2.840.10045.2.1)"),
    (re.compile(rb"1\.2\.840\.10040\.4\.1"), "BIN-OID-DSA", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.DSA, "DSA OID found in binary (1.2.840.10040.4.1)"),
]


def analyze_strings(file_path: str, data: bytes) -> list[Finding]:
    """Analyze binary data for crypto-related strings."""
    findings: list[Finding] = []
    seen_rules: set[str] = set()

    for pattern, rule_id, severity, risk, family, message in _STRING_PATTERNS:
        if rule_id in seen_rules:
            continue

        match = pattern.search(data)
        if match:
            seen_rules.add(rule_id)
            offset = match.start()
            matched_text = match.group(0).decode("ascii", errors="replace")

            findings.append(Finding(
                rule_id=rule_id,
                severity=severity,
                quantum_risk=risk,
                algorithm=Algorithm(
                    name=family.value if family != AlgorithmFamily.UNKNOWN else "Unknown",
                    family=family,
                    quantum_risk=risk,
                    description=message,
                ),
                location=FileLocation(
                    file_path=file_path,
                    line_number=offset,  # Use byte offset as "line number"
                    line_content=f"offset 0x{offset:x}: {matched_text}",
                ),
                message=message,
                recommendation="Review binary for quantum-vulnerable cryptography. Consider recompiling with PQC-safe libraries",
            ))

    return findings
