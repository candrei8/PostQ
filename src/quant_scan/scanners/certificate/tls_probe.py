"""Probe live TLS endpoints and produce quantum-risk findings."""

from __future__ import annotations

import logging
import socket
import ssl

from cryptography import x509

from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding
from quant_scan.rules.loader import load_algorithms
from quant_scan.scanners.certificate.cert_parser import (
    _parse_single_cert,
)

logger = logging.getLogger(__name__)

# Default connection timeout in seconds
_DEFAULT_TIMEOUT = 10

# TLS version display names
_TLS_VERSION_NAMES: dict[int, str] = {
    ssl.TLSVersion.TLSv1: "TLSv1.0",
    ssl.TLSVersion.TLSv1_1: "TLSv1.1",
    ssl.TLSVersion.TLSv1_2: "TLSv1.2",
    ssl.TLSVersion.TLSv1_3: "TLSv1.3",
}

# Deprecated TLS versions that should be flagged
_DEPRECATED_TLS: set[str] = {"TLSv1.0", "TLSv1.1"}

# Cipher-suite substrings that indicate weak crypto
_WEAK_CIPHER_KEYWORDS: dict[str, str] = {
    "RC4": "RC4",
    "DES": "DES",
    "3DES": "3DES",
    "MD5": "MD5",
    "NULL": "NULL",
    "EXPORT": "EXPORT",
}


def _make_tls_location(host: str, port: int, detail: str = "") -> FileLocation:
    """Build a FileLocation representing a network endpoint."""
    return FileLocation(
        file_path=f"{host}:{port}",
        line_number=0,
        line_content=detail,
    )


def probe_tls_endpoint(
    host: str,
    port: int = 443,
    timeout: float = _DEFAULT_TIMEOUT,
) -> list[Finding]:
    """Connect to a TLS endpoint and return quantum-risk findings.

    Extracts the server certificate and analyses:
    - Public key algorithm and size
    - Signature hash algorithm
    - TLS protocol version
    - Negotiated cipher suite

    Returns an empty list on connection failure (does not raise).
    """
    algo_db = load_algorithms()
    findings: list[Finding] = []
    endpoint = f"{host}:{port}"

    # Build an SSL context that accepts any cert (we're scanning, not verifying trust)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                # --- Grab certificate ---
                der_bytes = tls_sock.getpeercert(binary_form=True)
                cipher_info = tls_sock.cipher()  # (name, version, bits)
                tls_version_str = tls_sock.version()  # e.g. "TLSv1.3"

    except socket.timeout:
        logger.warning("TLS probe timed out connecting to %s", endpoint)
        return []
    except ConnectionRefusedError:
        logger.warning("Connection refused by %s", endpoint)
        return []
    except OSError as exc:
        logger.warning("TLS probe failed for %s: %s", endpoint, exc)
        return []
    except Exception as exc:
        logger.warning("Unexpected error probing %s: %s", endpoint, exc)
        return []

    # --- Parse the server certificate ---
    if der_bytes:
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
            cert_findings = _parse_single_cert(cert, endpoint, 0, algo_db)
            findings.extend(cert_findings)
        except Exception as exc:
            logger.warning("Could not parse server certificate from %s: %s", endpoint, exc)

    # --- TLS version check ---
    if tls_version_str:
        if tls_version_str in _DEPRECATED_TLS:
            findings.append(
                Finding(
                    rule_id="TLS-VERSION-DEPRECATED",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.VULNERABLE,
                    algorithm=Algorithm(
                        name=tls_version_str,
                        family=_get_tls_family(),
                        quantum_risk=QuantumRisk.VULNERABLE,
                        description=f"Deprecated TLS version: {tls_version_str}",
                    ),
                    location=_make_tls_location(host, port, tls_version_str),
                    message=(f"Endpoint {endpoint} uses deprecated {tls_version_str}"),
                    recommendation=("Upgrade to TLS 1.2 or TLS 1.3. TLS 1.0/1.1 are deprecated by IETF RFC 8996."),
                    confidence=1.0,
                )
            )

    # --- Cipher suite check ---
    if cipher_info:
        cipher_name = cipher_info[0]  # e.g. "ECDHE-RSA-AES256-GCM-SHA384"
        for keyword, algo_key in _WEAK_CIPHER_KEYWORDS.items():
            if keyword in cipher_name.upper():
                algo = algo_db.get(algo_key)
                if algo is None:
                    # Build a minimal Algorithm for cipher weaknesses not in DB
                    algo = Algorithm(
                        name=algo_key,
                        family=_get_tls_family(),
                        quantum_risk=QuantumRisk.VULNERABLE,
                        description=f"Weak cipher component: {algo_key}",
                    )
                findings.append(
                    Finding(
                        rule_id=f"TLS-CIPHER-{algo_key}",
                        severity=Severity.HIGH,
                        quantum_risk=algo.quantum_risk,
                        algorithm=algo,
                        location=_make_tls_location(host, port, f"cipher={cipher_name}"),
                        message=(
                            f"Endpoint {endpoint} negotiated cipher suite "
                            f"'{cipher_name}' containing weak component "
                            f"'{keyword}'"
                        ),
                        recommendation=(
                            f"Disable cipher suites using {keyword}. Use AEAD ciphers (AES-GCM, ChaCha20-Poly1305)."
                        ),
                        confidence=1.0,
                    )
                )

    return findings


def _get_tls_family():
    """Return a safe AlgorithmFamily for TLS-level findings."""
    from quant_scan.core.enums import AlgorithmFamily

    return AlgorithmFamily.UNKNOWN
