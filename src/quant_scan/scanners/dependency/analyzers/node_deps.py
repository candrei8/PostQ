"""Node.js dependency analyzer — detect crypto libraries in package.json."""

from __future__ import annotations

import json
from typing import Any

from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding
from quant_scan.rules.loader import load_algorithms

# ---------------------------------------------------------------------------
# Known Node.js crypto libraries and their quantum risk profiles
# ---------------------------------------------------------------------------

_NODE_CRYPTO_LIBS: list[dict[str, Any]] = [
    {
        "names": ["crypto-js"],
        "rule_id": "DEP-NODE-CRYPTOJS",
        "severity": Severity.HIGH,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "algorithm_key": "RSA-generic",
        "message": (
            "Node.js dependency 'crypto-js' detected. This library provides "
            "MD5, DES, 3DES, AES, and other cryptographic primitives, several "
            "of which are quantum-vulnerable or already broken."
        ),
        "recommendation": (
            "Audit usage for MD5/DES/3DES operations and replace with AES-256. "
            "For any asymmetric operations, plan migration to PQC algorithms "
            "(ML-DSA, ML-KEM)."
        ),
    },
    {
        "names": ["node-forge"],
        "rule_id": "DEP-NODE-NODEFORGE",
        "severity": Severity.HIGH,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "algorithm_key": "RSA-generic",
        "message": (
            "Node.js dependency 'node-forge' detected. Provides RSA, DES, and "
            "other quantum-vulnerable algorithms in pure JavaScript."
        ),
        "recommendation": (
            "Audit usage for RSA/DES operations. Migrate RSA to ML-DSA/ML-KEM "
            "and DES to AES-256."
        ),
    },
    {
        "names": ["bcrypt", "bcryptjs"],
        "rule_id": "DEP-NODE-BCRYPT",
        "severity": Severity.LOW,
        "quantum_risk": QuantumRisk.WEAKENED,
        "algorithm_key": "SHA-256",
        "message": (
            "Node.js dependency '{lib}' detected. Password hashing is not "
            "directly threatened by quantum computing, but Grover's algorithm "
            "provides a quadratic speedup on brute-force attacks."
        ),
        "recommendation": (
            "bcrypt remains acceptable for password hashing. Consider increasing "
            "work factor. No immediate PQC migration needed for password hashing."
        ),
    },
    {
        "names": ["jsonwebtoken"],
        "rule_id": "DEP-NODE-JSONWEBTOKEN",
        "severity": Severity.MEDIUM,
        "quantum_risk": QuantumRisk.WEAKENED,
        "algorithm_key": "RSA-generic",
        "message": (
            "Node.js dependency 'jsonwebtoken' detected. JWT libraries commonly "
            "use RSA or ECDSA for token signatures, both quantum-vulnerable."
        ),
        "recommendation": (
            "Audit JWT signing algorithms in use. Plan migration from RS256/"
            "ES256 to PQC-safe signature schemes when standardized JWT PQC "
            "algorithms become available."
        ),
    },
    {
        "names": ["jose"],
        "rule_id": "DEP-NODE-JOSE",
        "severity": Severity.MEDIUM,
        "quantum_risk": QuantumRisk.WEAKENED,
        "algorithm_key": "RSA-generic",
        "message": (
            "Node.js dependency 'jose' detected. JOSE/JWT/JWE library that "
            "supports RSA and ECDSA algorithms, both quantum-vulnerable."
        ),
        "recommendation": (
            "Audit JOSE/JWT operations for RSA/ECDSA usage. Monitor the library "
            "for PQC algorithm support and plan migration."
        ),
    },
    {
        "names": ["node-rsa"],
        "rule_id": "DEP-NODE-NODERSA",
        "severity": Severity.HIGH,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "algorithm_key": "RSA-generic",
        "message": (
            "Node.js dependency 'node-rsa' detected. Pure RSA library — all "
            "usage is quantum-vulnerable."
        ),
        "recommendation": (
            "Migrate all RSA operations to PQC algorithms. Replace RSA "
            "signatures with ML-DSA and RSA key exchange with ML-KEM."
        ),
    },
    {
        "names": ["elliptic"],
        "rule_id": "DEP-NODE-ELLIPTIC",
        "severity": Severity.HIGH,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "algorithm_key": "ECDSA-generic",
        "message": (
            "Node.js dependency 'elliptic' detected. Elliptic curve "
            "cryptography library — all ECC operations are quantum-vulnerable."
        ),
        "recommendation": (
            "Migrate all ECDSA/ECDH operations to PQC algorithms such as "
            "ML-DSA for signatures and ML-KEM for key exchange."
        ),
    },
]


def _find_line_for_key(lines: list[str], key: str) -> int:
    """Find the line number where a JSON key appears (best effort)."""
    needle = f'"{key}"'
    for idx, line in enumerate(lines):
        if needle in line:
            return idx + 1
    return 1


def analyze_node_deps(file_path: str, content: str) -> list[Finding]:
    """Analyze a package.json file for cryptographic library usage."""
    algorithms = load_algorithms()
    findings: list[Finding] = []
    lines = content.splitlines()

    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        # Malformed package.json — skip gracefully
        return []

    if not isinstance(data, dict):
        return []

    # Collect all dependencies from relevant sections
    dep_sections = ["dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies"]
    all_deps: dict[str, str] = {}
    for section in dep_sections:
        section_deps = data.get(section)
        if isinstance(section_deps, dict):
            all_deps.update(section_deps)

    for dep_name in all_deps:
        for lib_info in _NODE_CRYPTO_LIBS:
            if dep_name in lib_info["names"]:
                algo_key = lib_info["algorithm_key"]
                algo = algorithms.get(algo_key)
                if algo is None:
                    continue

                line_no = _find_line_for_key(lines, dep_name)
                line_content = lines[line_no - 1] if line_no <= len(lines) else ""
                message = lib_info["message"].format(lib=dep_name)

                findings.append(
                    Finding(
                        rule_id=lib_info["rule_id"],
                        severity=lib_info["severity"],
                        quantum_risk=lib_info["quantum_risk"],
                        algorithm=algo,
                        location=FileLocation(
                            file_path=file_path,
                            line_number=line_no,
                            line_content=line_content.strip(),
                        ),
                        message=message,
                        recommendation=lib_info["recommendation"],
                        confidence=0.7,
                    )
                )
                break  # one match per package

    return findings
