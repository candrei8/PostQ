"""Go dependency analyzer — detect crypto modules in go.mod."""

from __future__ import annotations

import re
from typing import Any

from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.models import FileLocation, Finding
from quant_scan.rules.loader import load_algorithms

# ---------------------------------------------------------------------------
# Known Go crypto modules and their quantum risk profiles
# ---------------------------------------------------------------------------

_GO_CRYPTO_LIBS: list[dict[str, Any]] = [
    {
        "module": "golang.org/x/crypto",
        "rule_id": "DEP-GO-XCRYPTO",
        "severity": Severity.MEDIUM,
        "quantum_risk": QuantumRisk.WEAKENED,
        "algorithm_key": "RSA-generic",
        "message": (
            "Go dependency 'golang.org/x/crypto' detected. This supplementary "
            "crypto package includes SSH, NaCl, and other modules that may use "
            "quantum-vulnerable algorithms (RSA, ECC, curve25519)."
        ),
        "recommendation": (
            "Audit usage for RSA/ECC operations. Monitor the Go team's PQC "
            "roadmap and migrate asymmetric operations to PQC algorithms when "
            "support is added to the standard library."
        ),
    },
    {
        "module": "github.com/dgrijalva/jwt-go",
        "rule_id": "DEP-GO-JWTGO-DEPRECATED",
        "severity": Severity.HIGH,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "algorithm_key": "RSA-generic",
        "message": (
            "Go dependency 'github.com/dgrijalva/jwt-go' detected. This is a "
            "DEPRECATED JWT library with known vulnerabilities. It uses RSA and "
            "ECDSA for token signatures, both quantum-vulnerable."
        ),
        "recommendation": (
            "Immediately migrate to 'github.com/golang-jwt/jwt/v5' (the "
            "maintained fork). Then audit JWT signing algorithms and plan "
            "migration from RS256/ES256 to PQC-safe signature schemes."
        ),
    },
    {
        "module": "github.com/golang-jwt/jwt",
        "rule_id": "DEP-GO-GOLANGJWT",
        "severity": Severity.MEDIUM,
        "quantum_risk": QuantumRisk.WEAKENED,
        "algorithm_key": "RSA-generic",
        "message": (
            "Go dependency 'github.com/golang-jwt/jwt' detected. JWT library "
            "commonly using RSA or ECDSA for token signatures, both "
            "quantum-vulnerable."
        ),
        "recommendation": (
            "Audit JWT signing algorithms in use. Plan migration from RS256/"
            "ES256 to PQC-safe signature schemes when standardized JWT PQC "
            "algorithms become available."
        ),
    },
]


def _parse_go_mod(content: str) -> list[tuple[str, int]]:
    """Extract module paths and line numbers from go.mod."""
    modules: list[tuple[str, int]] = []
    lines = content.splitlines()
    in_require_block = False

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Handle require block: require ( ... )
        if stripped.startswith("require") and "(" in stripped:
            in_require_block = True
            continue

        if in_require_block:
            if stripped == ")":
                in_require_block = False
                continue
            # Lines inside require block: module/path v1.2.3
            if stripped and not stripped.startswith("//"):
                parts = stripped.split()
                if parts:
                    modules.append((parts[0], line_no))
            continue

        # Single-line require: require module/path v1.2.3
        match = re.match(r"^require\s+(\S+)\s+", stripped)
        if match:
            modules.append((match.group(1), line_no))

    return modules


def analyze_go_deps(file_path: str, content: str) -> list[Finding]:
    """Analyze a go.mod file for cryptographic module usage."""
    algorithms = load_algorithms()
    findings: list[Finding] = []
    lines = content.splitlines()

    try:
        modules = _parse_go_mod(content)
    except Exception:
        # Malformed file — return empty
        return []

    for mod_path, line_no in modules:
        for lib_info in _GO_CRYPTO_LIBS:
            # Use startswith to handle versioned paths like
            # github.com/golang-jwt/jwt/v5
            if mod_path.startswith(lib_info["module"]) or mod_path == lib_info["module"]:
                algo_key = lib_info["algorithm_key"]
                algo = algorithms.get(algo_key)
                if algo is None:
                    continue

                line_content = lines[line_no - 1] if line_no <= len(lines) else ""

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
                        message=lib_info["message"],
                        recommendation=lib_info["recommendation"],
                        confidence=0.7,
                    )
                )
                break  # one match per module

    return findings
