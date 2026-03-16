"""Parse X.509 certificate files and produce quantum-risk findings."""

from __future__ import annotations

import logging
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from quant_scan.core.enums import Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding
from quant_scan.rules.loader import load_algorithms

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signature OID to hash-algorithm mapping
# ---------------------------------------------------------------------------

_SIG_HASH_MAP: dict[str, str] = {
    # RSA signatures
    "1.2.840.113549.1.1.4": "MD5",  # md5WithRSAEncryption
    "1.2.840.113549.1.1.5": "SHA-1",  # sha1WithRSAEncryption
    "1.2.840.113549.1.1.11": "SHA-256",  # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": "SHA-384",  # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13": "SHA-512",  # sha512WithRSAEncryption
    # ECDSA signatures
    "1.2.840.10045.4.1": "SHA-1",  # ecdsa-with-SHA1
    "1.2.840.10045.4.3.2": "SHA-256",  # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3": "SHA-384",  # ecdsa-with-SHA384
    "1.2.840.10045.4.3.4": "SHA-512",  # ecdsa-with-SHA512
    # DSA signatures
    "2.16.840.1.101.3.4.3.1": "SHA-1",  # id-dsa-with-sha1
    "2.16.840.1.101.3.4.3.2": "SHA-256",  # dsa-with-sha256
}

# Reverse lookup from algorithm name in the signature OID description
_SIG_NAME_HASH: dict[str, str] = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha224": "SHA-256",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
}

# EC curve name to algorithm-db key
_EC_CURVE_MAP: dict[str, str] = {
    "secp256r1": "ECC-P256",
    "prime256v1": "ECC-P256",
    "secp384r1": "ECC-P384",
    "secp521r1": "ECC-generic",
}


def _identify_hash_algorithm(cert: x509.Certificate) -> str | None:
    """Return the algorithm-DB key for the hash used in the signature."""
    oid = cert.signature_algorithm_oid.dotted_string
    if oid in _SIG_HASH_MAP:
        return _SIG_HASH_MAP[oid]

    # Fallback: try parsing the OID name
    try:
        sig_name = cert.signature_hash_algorithm
        if sig_name is not None:
            name_lower = sig_name.name.lower()
            for token, algo_key in _SIG_NAME_HASH.items():
                if token in name_lower:
                    return algo_key
    except Exception:
        pass

    return None


def _identify_public_key(cert: x509.Certificate) -> str | None:
    """Return the algorithm-DB key for the certificate's public key."""
    pub = cert.public_key()

    if isinstance(pub, rsa.RSAPublicKey):
        size = pub.key_size
        if size <= 1024:
            return "RSA-1024"
        if size <= 2048:
            return "RSA-2048"
        if size <= 4096:
            return "RSA-4096"
        return "RSA-generic"

    if isinstance(pub, ec.EllipticCurvePublicKey):
        curve_name = pub.curve.name
        return _EC_CURVE_MAP.get(curve_name, "ECC-generic")

    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA-generic"

    return None


def _cert_subject_str(cert: x509.Certificate) -> str:
    """Human-readable one-line subject."""
    try:
        attrs = cert.subject
        cn = attrs.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn:
            return cn[0].value
        return attrs.rfc4514_string()
    except Exception:
        return "<unknown subject>"


def _cert_description(cert: x509.Certificate) -> str:
    """Build a short description string for the certificate."""
    subject = _cert_subject_str(cert)
    try:
        not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d")
    except Exception:
        not_after = "?"
    return f"Certificate subject={subject}, expires={not_after}"


def _make_finding(
    algo: Algorithm,
    file_path: str,
    cert_index: int,
    cert: x509.Certificate,
    detail: str,
    rule_id: str,
    recommendation: str = "",
) -> Finding:
    """Construct a Finding from an algorithm match."""
    desc = _cert_description(cert)
    severity_map: dict[str, Severity] = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    severity = severity_map.get(algo.quantum_risk.value, Severity.MEDIUM)
    # Override severity for well-known cases
    if algo.name == "MD5":
        severity = Severity.CRITICAL
    elif algo.name == "SHA-1":
        severity = Severity.HIGH
    elif algo.name in ("SHA-256", "SHA-384"):
        severity = Severity.LOW
    elif algo.name in ("SHA-512",):
        severity = Severity.INFO
    elif algo.name == "RSA-1024":
        severity = Severity.CRITICAL
    elif algo.name in ("RSA-2048", "RSA-4096", "RSA-generic"):
        severity = Severity.HIGH
    elif algo.name.startswith("ECC-"):
        severity = Severity.HIGH
    elif algo.name == "DSA-generic":
        severity = Severity.HIGH

    if not recommendation:
        if algo.pqc_replacements:
            recommendation = f"Migrate to post-quantum alternative: {', '.join(algo.pqc_replacements)}"
        else:
            recommendation = "No action required — algorithm is quantum-safe."

    return Finding(
        rule_id=rule_id,
        severity=severity,
        quantum_risk=algo.quantum_risk,
        algorithm=algo,
        location=FileLocation(
            file_path=file_path,
            line_number=cert_index + 1,
            line_content=desc,
        ),
        message=f"{detail} | {desc}",
        recommendation=recommendation,
        confidence=1.0,
    )


def _parse_single_cert(
    cert: x509.Certificate,
    file_path: str,
    cert_index: int,
    algo_db: dict[str, Algorithm],
) -> list[Finding]:
    """Extract findings from a single parsed certificate."""
    findings: list[Finding] = []

    # --- Public key algorithm ---
    pk_key = _identify_public_key(cert)
    if pk_key and pk_key in algo_db:
        algo = algo_db[pk_key]
        pub = cert.public_key()
        key_size = getattr(pub, "key_size", None)
        detail = f"Public key: {pk_key}"
        if key_size:
            detail += f" ({key_size}-bit)"
        findings.append(
            _make_finding(
                algo=algo,
                file_path=file_path,
                cert_index=cert_index,
                cert=cert,
                detail=detail,
                rule_id=f"CERT-PK-{pk_key}",
            )
        )

    # --- Signature hash algorithm ---
    hash_key = _identify_hash_algorithm(cert)
    if hash_key and hash_key in algo_db:
        algo = algo_db[hash_key]
        findings.append(
            _make_finding(
                algo=algo,
                file_path=file_path,
                cert_index=cert_index,
                cert=cert,
                detail=f"Signature hash: {hash_key}",
                rule_id=f"CERT-SIG-{hash_key}",
            )
        )

    return findings


def _load_pem_certs(data: bytes) -> list[x509.Certificate]:
    """Load all certificates from a PEM byte string (handles chains)."""
    certs: list[x509.Certificate] = []
    # Split on PEM boundaries to handle cert chains
    pem_marker = b"-----BEGIN CERTIFICATE-----"
    parts = data.split(pem_marker)
    for part in parts[1:]:  # skip anything before the first marker
        pem_block = pem_marker + part
        # Ensure it has an end marker
        end_marker = b"-----END CERTIFICATE-----"
        end_idx = pem_block.find(end_marker)
        if end_idx == -1:
            continue
        pem_block = pem_block[: end_idx + len(end_marker)]
        try:
            cert = x509.load_pem_x509_certificate(pem_block)
            certs.append(cert)
        except Exception as exc:
            logger.debug("Skipping malformed PEM certificate block: %s", exc)
    return certs


def parse_certificate_file(file_path: str) -> list[Finding]:
    """Parse an X.509 certificate file and return quantum-risk findings.

    Supports .pem, .crt, .cer, and .der formats.  PEM files may contain
    certificate chains (multiple certs).
    """
    algo_db = load_algorithms()
    path = Path(file_path)

    try:
        raw = path.read_bytes()
    except OSError as exc:
        logger.warning("Cannot read certificate file %s: %s", file_path, exc)
        return []

    if not raw:
        return []

    certs: list[x509.Certificate] = []
    suffix = path.suffix.lower()

    if suffix in (".pem", ".crt", ".cer"):
        # Try PEM first (most common for .crt/.cer too)
        if b"-----BEGIN CERTIFICATE-----" in raw:
            certs = _load_pem_certs(raw)
        else:
            # Might be DER-encoded despite the extension
            try:
                certs = [x509.load_der_x509_certificate(raw)]
            except Exception as exc:
                logger.debug("File %s is neither valid PEM nor DER: %s", file_path, exc)
    elif suffix == ".der":
        try:
            certs = [x509.load_der_x509_certificate(raw)]
        except Exception as exc:
            logger.debug("Cannot parse DER certificate %s: %s", file_path, exc)
    else:
        # Unknown extension — try PEM then DER
        if b"-----BEGIN CERTIFICATE-----" in raw:
            certs = _load_pem_certs(raw)
        else:
            try:
                certs = [x509.load_der_x509_certificate(raw)]
            except Exception:
                pass

    if not certs:
        logger.info("No valid certificates found in %s", file_path)
        return []

    findings: list[Finding] = []
    for idx, cert in enumerate(certs):
        try:
            findings.extend(_parse_single_cert(cert, file_path, idx, algo_db))
        except Exception as exc:
            logger.warning("Error analysing certificate #%d in %s: %s", idx, file_path, exc)

    return findings
