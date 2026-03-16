"""Java dependency analyzer — detect crypto libraries in pom.xml and build.gradle."""

from __future__ import annotations

import re
from typing import Any

from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.models import FileLocation, Finding
from quant_scan.rules.loader import load_algorithms

# ---------------------------------------------------------------------------
# Known Java crypto libraries and their quantum risk profiles
# ---------------------------------------------------------------------------

_JAVA_CRYPTO_LIBS: list[dict[str, Any]] = [
    {
        "identifiers": ["org.bouncycastle"],
        "rule_id": "DEP-JAVA-BOUNCYCASTLE",
        "severity": Severity.MEDIUM,
        "quantum_risk": QuantumRisk.WEAKENED,
        "algorithm_key": "RSA-generic",
        "message": (
            "Java dependency 'Bouncy Castle' (org.bouncycastle) detected. "
            "This library supports both quantum-vulnerable algorithms (RSA, "
            "ECC, DSA) and has experimental PQC support."
        ),
        "recommendation": (
            "Audit Bouncy Castle usage for RSA/ECC/DSA operations. Bouncy "
            "Castle provides PQC algorithm implementations — plan migration "
            "to use its ML-DSA, ML-KEM, or SLH-DSA providers."
        ),
    },
    {
        "identifiers": ["org.jasypt", "jasypt"],
        "rule_id": "DEP-JAVA-JASYPT",
        "severity": Severity.HIGH,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "algorithm_key": "RSA-generic",
        "message": (
            "Java dependency 'Jasypt' detected. Simplified encryption library "
            "that often defaults to PBE with MD5/DES, which are "
            "quantum-vulnerable and classically weak."
        ),
        "recommendation": (
            "Replace Jasypt with modern encryption using AES-256-GCM. For "
            "asymmetric operations, migrate to PQC algorithms (ML-DSA, ML-KEM). "
            "Avoid PBE schemes based on MD5 or DES."
        ),
    },
    {
        "identifiers": ["com.auth0:java-jwt", "java-jwt"],
        "rule_id": "DEP-JAVA-JWT",
        "severity": Severity.MEDIUM,
        "quantum_risk": QuantumRisk.WEAKENED,
        "algorithm_key": "RSA-generic",
        "message": (
            "Java dependency 'java-jwt' detected. JWT library commonly using "
            "RSA or ECDSA for token signatures, both quantum-vulnerable."
        ),
        "recommendation": (
            "Audit JWT signing algorithms in use. Plan migration from RS256/"
            "ES256 to PQC-safe signature schemes when standardized JWT PQC "
            "algorithms become available."
        ),
    },
    {
        "identifiers": ["com.nimbusds:nimbus-jose-jwt", "nimbus-jose-jwt"],
        "rule_id": "DEP-JAVA-NIMBUS",
        "severity": Severity.MEDIUM,
        "quantum_risk": QuantumRisk.WEAKENED,
        "algorithm_key": "RSA-generic",
        "message": (
            "Java dependency 'nimbus-jose-jwt' detected. JOSE/JWT library "
            "supporting RSA and ECDSA algorithms, both quantum-vulnerable."
        ),
        "recommendation": (
            "Audit JOSE/JWT operations for RSA/ECDSA usage. Monitor the "
            "library for PQC algorithm support and plan migration."
        ),
    },
]


def _parse_pom_xml(content: str) -> list[tuple[str, int]]:
    """Extract groupId:artifactId pairs from pom.xml with line numbers."""
    deps: list[tuple[str, int]] = []
    lines = content.splitlines()

    # Find <dependency> blocks and extract groupId + artifactId
    in_dependency = False
    group_id = ""
    artifact_id = ""
    dep_start_line = 1

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()

        if "<dependency>" in stripped:
            in_dependency = True
            group_id = ""
            artifact_id = ""
            dep_start_line = line_no
            continue

        if "</dependency>" in stripped:
            if in_dependency and (group_id or artifact_id):
                identifier = f"{group_id}:{artifact_id}" if group_id else artifact_id
                deps.append((identifier, dep_start_line))
                # Also add group_id alone for matching
                if group_id:
                    deps.append((group_id, dep_start_line))
            in_dependency = False
            continue

        if in_dependency:
            gid_match = re.search(r"<groupId>\s*(.+?)\s*</groupId>", stripped)
            if gid_match:
                group_id = gid_match.group(1)
            aid_match = re.search(r"<artifactId>\s*(.+?)\s*</artifactId>", stripped)
            if aid_match:
                artifact_id = aid_match.group(1)

    return deps


def _parse_build_gradle(content: str) -> list[tuple[str, int]]:
    """Extract dependency identifiers from build.gradle with line numbers."""
    deps: list[tuple[str, int]] = []
    lines = content.splitlines()

    # Match patterns like:
    #   implementation 'org.bouncycastle:bcprov-jdk15on:1.70'
    #   compile "com.auth0:java-jwt:3.18.2"
    #   api group: 'org.bouncycastle', name: 'bcprov-jdk15on', version: '1.70'
    dep_pattern = re.compile(
        r"""(?:implementation|compile|api|runtimeOnly|testImplementation|compileOnly)"""
        r"""\s+['"]([^'"]+)['"]""",
    )
    group_pattern = re.compile(
        r"""(?:implementation|compile|api|runtimeOnly|testImplementation|compileOnly)"""
        r"""\s+group:\s*['"]([^'"]+)['"]""",
    )

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()

        match = dep_pattern.search(stripped)
        if match:
            dep_str = match.group(1)
            # dep_str is like "org.bouncycastle:bcprov-jdk15on:1.70"
            deps.append((dep_str, line_no))
            parts = dep_str.split(":")
            if len(parts) >= 1:
                deps.append((parts[0], line_no))  # group id
            if len(parts) >= 2:
                deps.append((f"{parts[0]}:{parts[1]}", line_no))  # group:artifact
            continue

        match = group_pattern.search(stripped)
        if match:
            group_id = match.group(1)
            deps.append((group_id, line_no))

    return deps


def analyze_java_deps(file_path: str, content: str) -> list[Finding]:
    """Analyze a Java dependency file for cryptographic library usage.

    Supports: pom.xml and build.gradle.
    """
    algorithms = load_algorithms()
    findings: list[Finding] = []
    lines = content.splitlines()

    fname = file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    try:
        if fname == "pom.xml":
            deps = _parse_pom_xml(content)
        elif fname in ("build.gradle", "build.gradle.kts"):
            deps = _parse_build_gradle(content)
        else:
            return []
    except Exception:
        # Malformed file — return empty
        return []

    matched_rules: set[str] = set()

    for dep_identifier, line_no in deps:
        dep_lower = dep_identifier.lower()
        for lib_info in _JAVA_CRYPTO_LIBS:
            if lib_info["rule_id"] in matched_rules:
                continue
            for known_id in lib_info["identifiers"]:
                if known_id.lower() in dep_lower:
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
                    matched_rules.add(lib_info["rule_id"])
                    break

    return findings
