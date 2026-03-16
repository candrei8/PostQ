"""Enumerations for severity, quantum risk, and algorithm families."""

from enum import Enum


class Severity(str, Enum):
    """Finding severity level."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        return {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.5,
            Severity.INFO: 0.0,
        }[self]


class QuantumRisk(str, Enum):
    """Risk level under quantum computing threat."""

    VULNERABLE = "vulnerable"
    WEAKENED = "weakened"
    SAFE = "safe"
    UNKNOWN = "unknown"


class AlgorithmFamily(str, Enum):
    """Cryptographic algorithm families."""

    # Asymmetric — quantum vulnerable
    RSA = "RSA"
    ECC = "ECC"
    DSA = "DSA"
    DH = "DH"
    ECDH = "ECDH"
    ECDSA = "ECDSA"

    # Symmetric — quantum weakened (Grover)
    AES = "AES"
    DES = "DES"
    TRIPLE_DES = "3DES"
    CHACHA20 = "ChaCha20"
    BLOWFISH = "Blowfish"
    RC4 = "RC4"

    # Hashes — quantum weakened or broken
    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA2 = "SHA-2"
    SHA3 = "SHA-3"

    # Post-quantum safe
    ML_KEM = "ML-KEM"
    ML_DSA = "ML-DSA"
    SLH_DSA = "SLH-DSA"
    XMSS = "XMSS"
    BIKE = "BIKE"
    HQC = "HQC"

    # Misc
    RANDOM = "Random"
    UNKNOWN = "Unknown"
