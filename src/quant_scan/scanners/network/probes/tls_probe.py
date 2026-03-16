"""TLS endpoint probe — analyzes TLS configuration of remote servers."""
from __future__ import annotations

import logging
import socket
import ssl
from typing import Any

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding

logger = logging.getLogger(__name__)

_TIMEOUT = 5

# TLS versions to probe
_TLS_VERSIONS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1, Severity.HIGH),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, Severity.HIGH),
]

# Weak cipher patterns
_WEAK_CIPHERS = {
    "RC4": (Severity.CRITICAL, AlgorithmFamily.RC4, "RC4"),
    "DES": (Severity.CRITICAL, AlgorithmFamily.DES, "DES"),
    "3DES": (Severity.HIGH, AlgorithmFamily.TRIPLE_DES, "3DES"),
    "NULL": (Severity.CRITICAL, AlgorithmFamily.UNKNOWN, "NULL"),
    "EXPORT": (Severity.CRITICAL, AlgorithmFamily.UNKNOWN, "EXPORT"),
    "anon": (Severity.CRITICAL, AlgorithmFamily.UNKNOWN, "Anonymous"),
}


def _make_location(host: str, port: int, detail: str) -> FileLocation:
    return FileLocation(
        file_path=f"{host}:{port}",
        line_number=0,
        line_content=detail,
    )


def probe_tls(host: str, port: int = 443) -> list[Finding]:
    """Probe a TLS endpoint and return findings."""
    findings: list[Finding] = []

    # 1. Test deprecated TLS versions
    for version_name, version_enum, severity in _TLS_VERSIONS:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version_enum
            ctx.maximum_version = version_enum
            with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    findings.append(Finding(
                        rule_id=f"NET-TLS-{version_name.replace('.', '')}",
                        severity=severity,
                        quantum_risk=QuantumRisk.VULNERABLE,
                        algorithm=Algorithm(
                            name=version_name,
                            family=AlgorithmFamily.DH,
                            quantum_risk=QuantumRisk.VULNERABLE,
                            description=f"Server supports deprecated {version_name}",
                        ),
                        location=_make_location(host, port, f"Supports {version_name}"),
                        message=f"Server supports deprecated {version_name} — vulnerable to known attacks",
                        recommendation=f"Disable {version_name}. Use TLS 1.2+ with strong cipher suites",
                    ))
        except (ssl.SSLError, socket.error, OSError):
            pass  # Version not supported — good

    # 2. Connect with best available TLS and analyze
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                # Get certificate info
                cert_bin = tls.getpeercert(binary_form=True)
                cipher = tls.cipher()  # (name, version, bits)
                version = tls.version()

                if cipher:
                    cipher_name, cipher_version, cipher_bits = cipher

                    # Check for weak ciphers
                    for weak_pattern, (sev, family, algo_name) in _WEAK_CIPHERS.items():
                        if weak_pattern.upper() in cipher_name.upper():
                            findings.append(Finding(
                                rule_id=f"NET-CIPHER-{algo_name.upper()}",
                                severity=sev,
                                quantum_risk=QuantumRisk.VULNERABLE,
                                algorithm=Algorithm(
                                    name=algo_name,
                                    family=family,
                                    quantum_risk=QuantumRisk.VULNERABLE,
                                    description=f"Weak cipher: {cipher_name}",
                                ),
                                location=_make_location(host, port, f"Cipher: {cipher_name}"),
                                message=f"Weak cipher suite negotiated: {cipher_name}",
                                recommendation="Configure server to use strong cipher suites (AES-256-GCM, ChaCha20-Poly1305)",
                            ))

                    # Check for non-PFS ciphers
                    if not any(pfs in cipher_name for pfs in ("ECDHE", "DHE", "ECDH")):
                        findings.append(Finding(
                            rule_id="NET-NO-PFS",
                            severity=Severity.MEDIUM,
                            quantum_risk=QuantumRisk.VULNERABLE,
                            algorithm=Algorithm(
                                name="No-PFS",
                                family=AlgorithmFamily.RSA,
                                quantum_risk=QuantumRisk.VULNERABLE,
                                description="No Perfect Forward Secrecy",
                            ),
                            location=_make_location(host, port, f"Cipher: {cipher_name}"),
                            message=f"Cipher suite without PFS: {cipher_name}",
                            recommendation="Use ECDHE or DHE key exchange for Perfect Forward Secrecy",
                        ))

                    # Check RSA key exchange (quantum vulnerable)
                    if "RSA" in cipher_name and "ECDHE" not in cipher_name and "DHE" not in cipher_name:
                        findings.append(Finding(
                            rule_id="NET-RSA-KEX",
                            severity=Severity.HIGH,
                            quantum_risk=QuantumRisk.VULNERABLE,
                            algorithm=Algorithm(
                                name="RSA-KeyExchange",
                                family=AlgorithmFamily.RSA,
                                quantum_risk=QuantumRisk.VULNERABLE,
                                description="RSA key exchange — quantum vulnerable",
                            ),
                            location=_make_location(host, port, f"Cipher: {cipher_name}"),
                            message="RSA key exchange is quantum-vulnerable (Shor's algorithm)",
                            recommendation="Migrate to ECDHE key exchange, then to ML-KEM when available",
                        ))

                # Analyze certificate
                if cert_bin:
                    _analyze_certificate(host, port, cert_bin, findings)

    except (ssl.SSLError, socket.error, OSError) as e:
        logger.info("TLS connection to %s:%d failed: %s", host, port, e)

    return findings


def _analyze_certificate(
    host: str, port: int, cert_der: bytes, findings: list[Finding]
) -> None:
    """Analyze a DER-encoded certificate for quantum vulnerabilities."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

        cert = x509.load_der_x509_certificate(cert_der)
        pub_key = cert.public_key()
        sig_algo = cert.signature_algorithm_oid.dotted_string

        # Check public key type
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_size = pub_key.key_size
            severity = Severity.CRITICAL if key_size < 2048 else Severity.HIGH
            findings.append(Finding(
                rule_id="NET-CERT-RSA",
                severity=severity,
                quantum_risk=QuantumRisk.VULNERABLE,
                algorithm=Algorithm(
                    name=f"RSA-{key_size}",
                    family=AlgorithmFamily.RSA,
                    key_size=key_size,
                    quantum_risk=QuantumRisk.VULNERABLE,
                    description=f"RSA {key_size}-bit certificate",
                    pqc_replacements=["ML-DSA-65", "ML-DSA-87"],
                ),
                location=_make_location(host, port, f"Certificate: RSA-{key_size}"),
                message=f"Certificate uses RSA-{key_size} — quantum vulnerable (Shor's algorithm)",
                recommendation="Plan migration to ML-DSA certificates when CA support is available",
            ))

        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            curve = pub_key.curve.name
            key_size = pub_key.key_size
            findings.append(Finding(
                rule_id="NET-CERT-ECC",
                severity=Severity.HIGH,
                quantum_risk=QuantumRisk.VULNERABLE,
                algorithm=Algorithm(
                    name=f"ECC-{curve}",
                    family=AlgorithmFamily.ECC,
                    key_size=key_size,
                    quantum_risk=QuantumRisk.VULNERABLE,
                    description=f"ECDSA certificate (curve: {curve})",
                    pqc_replacements=["ML-DSA-44", "ML-DSA-65"],
                ),
                location=_make_location(host, port, f"Certificate: ECC-{curve}"),
                message=f"Certificate uses ECDSA ({curve}) — quantum vulnerable",
                recommendation="Plan migration to ML-DSA certificates",
            ))

        elif isinstance(pub_key, dsa.DSAPublicKey):
            findings.append(Finding(
                rule_id="NET-CERT-DSA",
                severity=Severity.CRITICAL,
                quantum_risk=QuantumRisk.VULNERABLE,
                algorithm=Algorithm(
                    name="DSA",
                    family=AlgorithmFamily.DSA,
                    quantum_risk=QuantumRisk.VULNERABLE,
                    description="DSA certificate — deprecated and quantum vulnerable",
                ),
                location=_make_location(host, port, "Certificate: DSA"),
                message="Certificate uses DSA — deprecated and quantum vulnerable",
                recommendation="Immediately replace with RSA-2048+ or ECDSA, then plan PQC migration",
            ))

        # Check signature algorithm
        sig_name = cert.signature_hash_algorithm
        if sig_name and sig_name.name.lower() in ("md5", "sha1"):
            findings.append(Finding(
                rule_id=f"NET-CERT-SIG-{sig_name.name.upper()}",
                severity=Severity.CRITICAL,
                quantum_risk=QuantumRisk.VULNERABLE,
                algorithm=Algorithm(
                    name=sig_name.name.upper(),
                    family=AlgorithmFamily.MD5 if "md5" in sig_name.name.lower() else AlgorithmFamily.SHA1,
                    quantum_risk=QuantumRisk.VULNERABLE,
                    description=f"Certificate signed with {sig_name.name}",
                ),
                location=_make_location(host, port, f"Signature: {sig_name.name}"),
                message=f"Certificate signed with broken hash: {sig_name.name}",
                recommendation="Reissue certificate with SHA-256 or SHA-384 signature",
            ))

    except ImportError:
        logger.debug("cryptography library not available for certificate analysis")
    except Exception as e:
        logger.warning("Certificate analysis failed for %s:%d: %s", host, port, e)
