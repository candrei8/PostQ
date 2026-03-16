"""Python dependency analyzer — detect crypto libraries in Python dependency files."""

from __future__ import annotations

import re
from typing import Any

from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.models import FileLocation, Finding
from quant_scan.rules.loader import load_algorithms

# ---------------------------------------------------------------------------
# Known Python crypto libraries and their quantum risk profiles
# ---------------------------------------------------------------------------

_PYTHON_CRYPTO_LIBS: list[dict[str, Any]] = [
    {
        "names": ["pycryptodome", "pycryptodomex", "pycrypto"],
        "rule_id": "DEP-PY-PYCRYPTODOME",
        "severity": Severity.HIGH,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "algorithm_key": "RSA-generic",
        "message": (
            "Python dependency '{lib}' detected. This library provides RSA, DES, "
            "3DES, and other quantum-vulnerable cryptographic primitives."
        ),
        "recommendation": (
            "Audit usage for RSA/DES/3DES operations. Migrate asymmetric "
            "operations to PQC algorithms (ML-DSA, ML-KEM) and replace DES/3DES "
            "with AES-256."
        ),
    },
    {
        "names": ["cryptography"],
        "rule_id": "DEP-PY-CRYPTOGRAPHY",
        "severity": Severity.MEDIUM,
        "quantum_risk": QuantumRisk.WEAKENED,
        "algorithm_key": "RSA-generic",
        "message": (
            "Python dependency 'cryptography' detected. This library supports "
            "both quantum-vulnerable (RSA, ECC) and modern algorithms."
        ),
        "recommendation": (
            "Audit code for RSA/ECC usage via this library. The 'cryptography' "
            "package may add PQC support in future versions; monitor releases "
            "and migrate asymmetric operations to ML-DSA/ML-KEM."
        ),
    },
    {
        "names": ["paramiko"],
        "rule_id": "DEP-PY-PARAMIKO",
        "severity": Severity.HIGH,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "algorithm_key": "RSA-generic",
        "message": (
            "Python dependency 'paramiko' detected. SSH library that typically "
            "uses RSA and DSA key exchange, both quantum-vulnerable."
        ),
        "recommendation": (
            "Plan migration to PQC-capable SSH implementations. Monitor OpenSSH "
            "PQC support and update paramiko configuration to use hybrid "
            "key exchange when available."
        ),
    },
    {
        "names": ["pyopenssl", "pyOpenSSL"],
        "rule_id": "DEP-PY-PYOPENSSL",
        "severity": Severity.MEDIUM,
        "quantum_risk": QuantumRisk.WEAKENED,
        "algorithm_key": "RSA-generic",
        "message": (
            "Python dependency 'pyOpenSSL' detected. OpenSSL wrapper that "
            "exposes both quantum-vulnerable and quantum-safe algorithms."
        ),
        "recommendation": (
            "Audit TLS configuration for RSA/ECC usage. Plan migration to "
            "PQC-enabled TLS (hybrid key exchange with ML-KEM) when OpenSSL "
            "PQC support is stable."
        ),
    },
    {
        "names": ["python-jose", "jose", "pyjwt", "PyJWT"],
        "rule_id": "DEP-PY-JWT",
        "severity": Severity.MEDIUM,
        "quantum_risk": QuantumRisk.WEAKENED,
        "algorithm_key": "RSA-generic",
        "message": (
            "Python dependency '{lib}' detected. JWT libraries commonly use "
            "RSA or ECDSA for token signatures, both quantum-vulnerable."
        ),
        "recommendation": (
            "Audit JWT signing algorithms in use. Plan migration from RS256/"
            "ES256 to PQC-safe signature schemes when standardized JWT PQC "
            "algorithms become available."
        ),
    },
    {
        "names": ["bcrypt"],
        "rule_id": "DEP-PY-BCRYPT",
        "severity": Severity.LOW,
        "quantum_risk": QuantumRisk.WEAKENED,
        "algorithm_key": "SHA-256",
        "message": (
            "Python dependency 'bcrypt' detected. Password hashing is not "
            "directly threatened by quantum computing, but Grover's algorithm "
            "provides a quadratic speedup on brute-force attacks."
        ),
        "recommendation": (
            "bcrypt remains acceptable for password hashing. Consider increasing "
            "work factor. No immediate PQC migration needed for password hashing."
        ),
    },
    {
        "names": ["rsa"],
        "rule_id": "DEP-PY-RSA",
        "severity": Severity.HIGH,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "algorithm_key": "RSA-generic",
        "message": ("Python dependency 'rsa' detected. Pure-Python RSA library — all usage is quantum-vulnerable."),
        "recommendation": (
            "Migrate all RSA operations to PQC algorithms. Replace RSA "
            "signatures with ML-DSA and RSA key exchange with ML-KEM."
        ),
    },
    {
        "names": ["ecdsa"],
        "rule_id": "DEP-PY-ECDSA",
        "severity": Severity.HIGH,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "algorithm_key": "ECDSA-generic",
        "message": ("Python dependency 'ecdsa' detected. Pure-Python ECDSA library — all usage is quantum-vulnerable."),
        "recommendation": ("Migrate all ECDSA operations to PQC signature algorithms such as ML-DSA-44 or ML-DSA-65."),
    },
]


def _normalize_package_name(name: str) -> str:
    """Normalize a Python package name for comparison (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def _extract_packages_requirements(content: str) -> list[tuple[str, int]]:
    """Extract package names and line numbers from requirements.txt format."""
    packages: list[tuple[str, int]] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip extras, version specifiers, environment markers
        match = re.match(r"^([A-Za-z0-9][-A-Za-z0-9_.]*)", line)
        if match:
            packages.append((match.group(1), line_no))
    return packages


def _extract_packages_pipfile(content: str) -> list[tuple[str, int]]:
    """Extract package names from a Pipfile (TOML-like INI format)."""
    packages: list[tuple[str, int]] = []
    in_packages = False
    for line_no, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped.strip("[]").strip().lower()
            in_packages = section in ("packages", "dev-packages")
            continue
        if in_packages and "=" in stripped:
            pkg_name = stripped.split("=", 1)[0].strip().strip('"').strip("'")
            if pkg_name and not pkg_name.startswith("#"):
                packages.append((pkg_name, line_no))
    return packages


def _extract_packages_pyproject(content: str) -> list[tuple[str, int]]:
    """Extract package names from pyproject.toml dependency lists."""
    packages: list[tuple[str, int]] = []
    in_deps = False
    for line_no, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        # Detect dependency list sections
        if re.match(r"^(dependencies|optional-dependencies\.\w+)\s*=\s*\[", stripped) or stripped in (
            "dependencies = [",
        ):
            in_deps = True
            continue
        if stripped.startswith("["):
            # New section — stop collecting
            in_deps = False
            continue
        if in_deps:
            if stripped == "]":
                in_deps = False
                continue
            # Each line is like: "requests>=2.0",
            match = re.match(r'^["\']([A-Za-z0-9][-A-Za-z0-9_.]*)', stripped)
            if match:
                packages.append((match.group(1), line_no))
    return packages


def _extract_packages_setup_cfg(content: str) -> list[tuple[str, int]]:
    """Extract package names from setup.cfg install_requires."""
    packages: list[tuple[str, int]] = []
    in_install_requires = False
    for line_no, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("["):
            in_install_requires = False
            continue
        if re.match(r"^install_requires\s*=", stripped):
            in_install_requires = True
            # Check for inline values
            after_eq = stripped.split("=", 1)[1].strip()
            if after_eq:
                match = re.match(r"^([A-Za-z0-9][-A-Za-z0-9_.]*)", after_eq)
                if match:
                    packages.append((match.group(1), line_no))
            continue
        if in_install_requires:
            if not stripped or "=" in stripped and not stripped[0].isspace():
                in_install_requires = False
                continue
            match = re.match(r"^([A-Za-z0-9][-A-Za-z0-9_.]*)", stripped)
            if match:
                packages.append((match.group(1), line_no))
    return packages


def analyze_python_deps(file_path: str, content: str) -> list[Finding]:
    """Analyze a Python dependency file for cryptographic library usage.

    Supports: requirements.txt, Pipfile, pyproject.toml, setup.cfg.
    """
    algorithms = load_algorithms()
    findings: list[Finding] = []
    lines = content.splitlines()

    # Determine file type and extract packages
    fname = file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    try:
        if fname == "pipfile":
            packages = _extract_packages_pipfile(content)
        elif fname == "pyproject.toml":
            packages = _extract_packages_pyproject(content)
        elif fname == "setup.cfg":
            packages = _extract_packages_setup_cfg(content)
        else:
            # Default: requirements.txt format
            packages = _extract_packages_requirements(content)
    except Exception:
        # Malformed file — return empty
        return []

    for pkg_name, line_no in packages:
        normalized = _normalize_package_name(pkg_name)
        for lib_info in _PYTHON_CRYPTO_LIBS:
            normalized_known = [_normalize_package_name(n) for n in lib_info["names"]]
            if normalized in normalized_known:
                algo_key = lib_info["algorithm_key"]
                algo = algorithms.get(algo_key)
                if algo is None:
                    continue

                line_content = lines[line_no - 1] if line_no <= len(lines) else ""
                message = lib_info["message"].format(lib=pkg_name)

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
