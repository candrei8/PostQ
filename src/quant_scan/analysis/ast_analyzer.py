"""AST-based analysis — reduces false positives by understanding code structure."""

from __future__ import annotations

import ast
import logging
from typing import Any

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding

logger = logging.getLogger(__name__)


class PythonCryptoVisitor(ast.NodeVisitor):
    """AST visitor that detects cryptographic API usage in Python code.

    This provides higher-confidence detection than regex by understanding
    the code structure (imports, function calls, argument values).
    """

    def __init__(self, file_path: str, source_lines: list[str]) -> None:
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: list[Finding] = []
        self._imports: dict[str, str] = {}  # alias -> full module path

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name
            self._imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            self._imports[name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_call_name(node)
        if func_name:
            self._check_crypto_call(node, func_name)
        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> str | None:
        """Extract the full dotted name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current: Any = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None

    def _get_keyword_value(self, node: ast.Call, keyword: str) -> int | str | None:
        """Extract the value of a keyword argument from a call."""
        for kw in node.keywords:
            if kw.arg == keyword:
                if isinstance(kw.value, ast.Constant):
                    return kw.value.value
                if isinstance(kw.value, ast.Name):
                    return kw.value.id
        return None

    def _get_line_content(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _get_context(self, lineno: int) -> tuple[list[str], list[str]]:
        before = self.source_lines[max(0, lineno - 4) : lineno - 1]
        after = self.source_lines[lineno : min(len(self.source_lines), lineno + 3)]
        return before, after

    def _add_finding(
        self,
        node: ast.AST,
        rule_id: str,
        severity: Severity,
        risk: QuantumRisk,
        family: AlgorithmFamily,
        algo_name: str,
        message: str,
        recommendation: str,
        key_size: int | None = None,
    ) -> None:
        lineno = getattr(node, "lineno", 0)
        before, after = self._get_context(lineno)
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                quantum_risk=risk,
                algorithm=Algorithm(
                    name=algo_name,
                    family=family,
                    key_size=key_size,
                    quantum_risk=risk,
                    description=message,
                ),
                location=FileLocation(
                    file_path=self.file_path,
                    line_number=lineno,
                    line_content=self._get_line_content(lineno),
                    context_before=before,
                    context_after=after,
                ),
                message=message,
                recommendation=recommendation,
                confidence=0.95,  # High confidence from AST analysis
            )
        )

    def _check_crypto_call(self, node: ast.Call, func_name: str) -> None:
        """Check if a function call is crypto-related."""
        # RSA key generation with key size detection
        if "generate_private_key" in func_name and "rsa" in func_name.lower():
            key_size = self._get_keyword_value(node, "key_size")
            if isinstance(key_size, int):
                severity = Severity.CRITICAL if key_size < 2048 else Severity.HIGH
                self._add_finding(
                    node,
                    f"AST-PY-RSA-{key_size}",
                    severity,
                    QuantumRisk.VULNERABLE,
                    AlgorithmFamily.RSA,
                    f"RSA-{key_size}",
                    f"RSA key generation with {key_size}-bit key (confirmed by AST)",
                    "Migrate to ML-DSA (FIPS 204)",
                    key_size=key_size,
                )
            else:
                self._add_finding(
                    node,
                    "AST-PY-RSA-GEN",
                    Severity.HIGH,
                    QuantumRisk.VULNERABLE,
                    AlgorithmFamily.RSA,
                    "RSA-generic",
                    "RSA key generation detected (confirmed by AST)",
                    "Migrate to ML-DSA (FIPS 204)",
                )

        # EC key generation
        elif "generate_private_key" in func_name and "ec" in func_name.lower():
            self._add_finding(
                node,
                "AST-PY-ECC-GEN",
                Severity.HIGH,
                QuantumRisk.VULNERABLE,
                AlgorithmFamily.ECC,
                "ECC-generic",
                "EC key generation detected (confirmed by AST)",
                "Migrate to ML-KEM (FIPS 203)",
            )

        # hashlib.md5()
        elif func_name in ("hashlib.md5", "md5"):
            self._add_finding(
                node,
                "AST-PY-MD5",
                Severity.HIGH,
                QuantumRisk.VULNERABLE,
                AlgorithmFamily.MD5,
                "MD5",
                "MD5 hash usage detected (confirmed by AST)",
                "Replace with SHA-256 or SHA-3",
            )

        # hashlib.sha1()
        elif func_name in ("hashlib.sha1", "sha1"):
            self._add_finding(
                node,
                "AST-PY-SHA1",
                Severity.HIGH,
                QuantumRisk.VULNERABLE,
                AlgorithmFamily.SHA1,
                "SHA-1",
                "SHA-1 hash usage detected (confirmed by AST)",
                "Replace with SHA-256 or SHA-3",
            )

        # random.random() / random.randint() — insecure PRNG
        elif func_name.startswith("random.") and func_name in (
            "random.random",
            "random.randint",
            "random.choice",
            "random.seed",
        ):
            self._add_finding(
                node,
                "AST-PY-WEAK-RANDOM",
                Severity.MEDIUM,
                QuantumRisk.UNKNOWN,
                AlgorithmFamily.RANDOM,
                "WeakRandom",
                "Non-cryptographic PRNG used (confirmed by AST)",
                "Use secrets module or os.urandom() for cryptographic randomness",
            )


def analyze_python_ast(file_path: str, content: str) -> list[Finding]:
    """Run AST-based analysis on Python source code.

    Returns high-confidence findings based on code structure analysis.
    This is meant to complement regex-based scanning, not replace it.
    """
    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError:
        logger.debug("Failed to parse %s as Python AST", file_path)
        return []

    lines = content.splitlines()
    visitor = PythonCryptoVisitor(file_path, lines)
    visitor.visit(tree)
    return visitor.findings
