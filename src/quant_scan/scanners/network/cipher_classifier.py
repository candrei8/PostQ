"""Cipher suite classifier — risk scoring for TLS cipher suites."""
from __future__ import annotations

from dataclasses import dataclass

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk


@dataclass
class CipherSuiteInfo:
    """Classification of a TLS cipher suite."""

    name: str
    key_exchange: str
    authentication: str
    cipher: str
    mac: str
    pfs: bool
    quantum_risk: QuantumRisk
    risk_score: float  # 0.0 (safe) to 10.0 (broken)


# Common cipher suite classifications
CIPHER_DB: dict[str, CipherSuiteInfo] = {
    "TLS_RSA_WITH_AES_128_CBC_SHA": CipherSuiteInfo(
        name="TLS_RSA_WITH_AES_128_CBC_SHA",
        key_exchange="RSA", authentication="RSA", cipher="AES-128-CBC", mac="SHA1",
        pfs=False, quantum_risk=QuantumRisk.VULNERABLE, risk_score=7.0,
    ),
    "TLS_RSA_WITH_AES_256_CBC_SHA": CipherSuiteInfo(
        name="TLS_RSA_WITH_AES_256_CBC_SHA",
        key_exchange="RSA", authentication="RSA", cipher="AES-256-CBC", mac="SHA1",
        pfs=False, quantum_risk=QuantumRisk.VULNERABLE, risk_score=6.5,
    ),
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": CipherSuiteInfo(
        name="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        key_exchange="ECDHE", authentication="RSA", cipher="AES-256-GCM", mac="AEAD",
        pfs=True, quantum_risk=QuantumRisk.VULNERABLE, risk_score=4.0,
    ),
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": CipherSuiteInfo(
        name="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        key_exchange="ECDHE", authentication="ECDSA", cipher="AES-256-GCM", mac="AEAD",
        pfs=True, quantum_risk=QuantumRisk.VULNERABLE, risk_score=3.5,
    ),
    "TLS_AES_256_GCM_SHA384": CipherSuiteInfo(
        name="TLS_AES_256_GCM_SHA384",
        key_exchange="TLS1.3", authentication="TLS1.3", cipher="AES-256-GCM", mac="AEAD",
        pfs=True, quantum_risk=QuantumRisk.VULNERABLE, risk_score=3.0,
    ),
    "TLS_CHACHA20_POLY1305_SHA256": CipherSuiteInfo(
        name="TLS_CHACHA20_POLY1305_SHA256",
        key_exchange="TLS1.3", authentication="TLS1.3", cipher="ChaCha20-Poly1305", mac="AEAD",
        pfs=True, quantum_risk=QuantumRisk.VULNERABLE, risk_score=3.0,
    ),
    "TLS_RSA_WITH_RC4_128_SHA": CipherSuiteInfo(
        name="TLS_RSA_WITH_RC4_128_SHA",
        key_exchange="RSA", authentication="RSA", cipher="RC4", mac="SHA1",
        pfs=False, quantum_risk=QuantumRisk.VULNERABLE, risk_score=9.5,
    ),
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": CipherSuiteInfo(
        name="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        key_exchange="RSA", authentication="RSA", cipher="3DES", mac="SHA1",
        pfs=False, quantum_risk=QuantumRisk.VULNERABLE, risk_score=8.5,
    ),
}


def classify_cipher(cipher_name: str) -> CipherSuiteInfo | None:
    """Look up a cipher suite by name."""
    return CIPHER_DB.get(cipher_name)


def is_pfs_cipher(cipher_name: str) -> bool:
    """Check if a cipher suite provides Perfect Forward Secrecy."""
    return any(pfs in cipher_name.upper() for pfs in ("ECDHE", "DHE"))


def is_quantum_safe(cipher_name: str) -> bool:
    """Check if a cipher suite is quantum-safe (currently none are without PQC KEM)."""
    return False  # No currently deployed TLS cipher suites are quantum-safe
