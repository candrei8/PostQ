"""Symbol table analysis — scans binary symbol tables for crypto functions."""
from __future__ import annotations

import logging

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding

logger = logging.getLogger(__name__)

# Known crypto function patterns to look for in symbol names
_CRYPTO_SYMBOLS: dict[str, tuple[str, Severity, QuantumRisk, AlgorithmFamily, str]] = {
    # OpenSSL RSA
    "RSA_generate_key_ex": ("BIN-SYM-RSA-KEYGEN", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.RSA, "RSA key generation (OpenSSL)"),
    "RSA_new": ("BIN-SYM-RSA-NEW", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.RSA, "RSA usage (OpenSSL)"),
    "RSA_sign": ("BIN-SYM-RSA-SIGN", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.RSA, "RSA signing (OpenSSL)"),
    "RSA_public_encrypt": ("BIN-SYM-RSA-ENC", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.RSA, "RSA encryption (OpenSSL)"),
    # OpenSSL EC
    "EC_KEY_generate_key": ("BIN-SYM-EC-KEYGEN", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.ECC, "EC key generation (OpenSSL)"),
    "ECDSA_sign": ("BIN-SYM-ECDSA-SIGN", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.ECDSA, "ECDSA signing (OpenSSL)"),
    "ECDH_compute_key": ("BIN-SYM-ECDH", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.ECDH, "ECDH key agreement (OpenSSL)"),
    # OpenSSL DSA/DH
    "DSA_generate_key": ("BIN-SYM-DSA-KEYGEN", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.DSA, "DSA key generation (OpenSSL)"),
    "DH_generate_key": ("BIN-SYM-DH-KEYGEN", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.DH, "DH key generation (OpenSSL)"),
    # OpenSSL weak ciphers
    "DES_set_key": ("BIN-SYM-DES", Severity.CRITICAL, QuantumRisk.VULNERABLE, AlgorithmFamily.DES, "DES cipher usage (OpenSSL)"),
    "DES_ecb_encrypt": ("BIN-SYM-DES-ECB", Severity.CRITICAL, QuantumRisk.VULNERABLE, AlgorithmFamily.DES, "DES-ECB encryption (OpenSSL)"),
    "BF_set_key": ("BIN-SYM-BF", Severity.HIGH, QuantumRisk.WEAKENED, AlgorithmFamily.BLOWFISH, "Blowfish cipher usage (OpenSSL)"),
    "RC4_set_key": ("BIN-SYM-RC4", Severity.CRITICAL, QuantumRisk.VULNERABLE, AlgorithmFamily.RC4, "RC4 cipher usage (OpenSSL)"),
    # OpenSSL weak hashes
    "MD5_Init": ("BIN-SYM-MD5", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.MD5, "MD5 hash usage (OpenSSL)"),
    "MD5_Update": ("BIN-SYM-MD5-UPD", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.MD5, "MD5 hash usage (OpenSSL)"),
    "SHA1_Init": ("BIN-SYM-SHA1", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.SHA1, "SHA-1 hash usage (OpenSSL)"),
    # mbedTLS
    "mbedtls_rsa_gen_key": ("BIN-SYM-MBED-RSA", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.RSA, "RSA key generation (mbedTLS)"),
    "mbedtls_ecdsa_write_signature": ("BIN-SYM-MBED-ECDSA", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.ECDSA, "ECDSA signing (mbedTLS)"),
    "mbedtls_des_setkey_enc": ("BIN-SYM-MBED-DES", Severity.CRITICAL, QuantumRisk.VULNERABLE, AlgorithmFamily.DES, "DES usage (mbedTLS)"),
    "mbedtls_md5_starts": ("BIN-SYM-MBED-MD5", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.MD5, "MD5 usage (mbedTLS)"),
    # WolfSSL
    "wc_RsaKeyGen": ("BIN-SYM-WOLF-RSA", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.RSA, "RSA key generation (wolfSSL)"),
    "wc_ecc_make_key": ("BIN-SYM-WOLF-ECC", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.ECC, "ECC key generation (wolfSSL)"),
    "wc_Des3_SetKey": ("BIN-SYM-WOLF-3DES", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.TRIPLE_DES, "3DES usage (wolfSSL)"),
    "wc_Md5Update": ("BIN-SYM-WOLF-MD5", Severity.HIGH, QuantumRisk.VULNERABLE, AlgorithmFamily.MD5, "MD5 usage (wolfSSL)"),
}


def _extract_strings_from_data(data: bytes, min_len: int = 4) -> list[str]:
    """Extract ASCII strings from binary data."""
    strings = []
    current: list[str] = []
    for byte in data:
        if 32 <= byte <= 126:  # printable ASCII
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))
    return strings


def analyze_symbols(file_path: str, data: bytes) -> list[Finding]:
    """Analyze binary for known crypto function symbols."""
    findings: list[Finding] = []
    seen_rules: set[str] = set()

    # Extract all strings and check against known symbols
    strings = _extract_strings_from_data(data)

    for s in strings:
        for sym_name, (rule_id, severity, risk, family, message) in _CRYPTO_SYMBOLS.items():
            if rule_id in seen_rules:
                continue
            if sym_name in s:
                seen_rules.add(rule_id)
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    quantum_risk=risk,
                    algorithm=Algorithm(
                        name=family.value,
                        family=family,
                        quantum_risk=risk,
                        description=message,
                    ),
                    location=FileLocation(
                        file_path=file_path,
                        line_number=0,
                        line_content=f"Symbol: {sym_name}",
                    ),
                    message=message,
                    recommendation="Recompile with PQC-safe cryptographic libraries (liboqs, Open Quantum Safe)",
                ))

    return findings
