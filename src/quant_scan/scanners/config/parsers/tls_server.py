"""TLS server configuration parser — detects weak protocols and cipher suites.

Supports nginx, Apache httpd, and HAProxy configuration formats.
"""

from __future__ import annotations

import re

from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding
from quant_scan.rules.loader import load_algorithms

# ---------------------------------------------------------------------------
# Weak protocol detection
# ---------------------------------------------------------------------------

_WEAK_PROTOCOLS: dict[str, tuple[Severity, str]] = {
    "sslv2": (Severity.CRITICAL, "SSLv2 is broken and must be removed immediately."),
    "sslv3": (Severity.CRITICAL, "SSLv3 is broken (POODLE). Remove and use TLSv1.2+."),
    "tlsv1": (Severity.HIGH, "TLSv1.0 is deprecated. Migrate to TLSv1.2 or TLSv1.3."),
    "tlsv1.0": (Severity.HIGH, "TLSv1.0 is deprecated. Migrate to TLSv1.2 or TLSv1.3."),
    "tlsv1.1": (Severity.HIGH, "TLSv1.1 is deprecated. Migrate to TLSv1.2 or TLSv1.3."),
}

# ---------------------------------------------------------------------------
# Weak cipher-suite token patterns (matched against individual cipher names)
# ---------------------------------------------------------------------------

# Each entry: (regex_pattern, algorithm_db_key, description_fragment)
_WEAK_CIPHER_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # NULL ciphers — no encryption at all
    (re.compile(r"(^|[-_])NULL([-_]|$)", re.IGNORECASE), "DES", "NULL cipher provides no encryption"),
    # Export-grade ciphers
    (re.compile(r"(^|[-_])EXP(ORT)?([-_]|$)", re.IGNORECASE), "DES", "Export-grade cipher is trivially breakable"),
    # DES (not 3DES)
    (re.compile(r"(^|[-_:!])DES([-_]CBC|[-_]|$)(?!.*3)", re.IGNORECASE), "DES", "DES cipher is broken"),
    # 3DES / Triple-DES
    (re.compile(r"(3DES|DES-CBC3|DES3)", re.IGNORECASE), "3DES", "3DES is deprecated"),
    # RC4 / arcfour
    (re.compile(r"(RC4|ARCFOUR)", re.IGNORECASE), "RC4", "RC4 is broken"),
    # MD5-based ciphers
    (re.compile(r"([-_])MD5($|[-_])", re.IGNORECASE), "MD5", "MD5 is broken for cryptographic use"),
]


# ---------------------------------------------------------------------------
# Directive patterns for different server types
# ---------------------------------------------------------------------------

# Nginx: ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
_RE_NGINX_PROTOCOLS = re.compile(r"^\s*ssl_protocols\s+(.+?)\s*;", re.MULTILINE | re.IGNORECASE)
# Nginx: ssl_ciphers 'HIGH:!aNULL:!MD5';
_RE_NGINX_CIPHERS = re.compile(r"^\s*ssl_ciphers\s+['\"]?(.+?)['\"]?\s*;", re.MULTILINE | re.IGNORECASE)

# Apache: SSLProtocol all -SSLv3 -TLSv1
_RE_APACHE_PROTOCOLS = re.compile(r"^\s*SSLProtocol\s+(.+?)$", re.MULTILINE | re.IGNORECASE)
# Apache: SSLCipherSuite HIGH:!aNULL
_RE_APACHE_CIPHERS = re.compile(r"^\s*SSLCipherSuite\s+['\"]?(.+?)['\"]?\s*$", re.MULTILINE | re.IGNORECASE)

# HAProxy: ssl-default-bind-ciphers / ssl-default-bind-options
_RE_HAPROXY_CIPHERS = re.compile(r"^\s*ssl-default-bind-ciphers\s+(.+?)$", re.MULTILINE | re.IGNORECASE)
_RE_HAPROXY_OPTIONS = re.compile(r"^\s*ssl-default-bind-options\s+(.+?)$", re.MULTILINE | re.IGNORECASE)


def _line_number_of(content: str, pos: int) -> int:
    """Return 1-based line number for a character position in content."""
    return content[:pos].count("\n") + 1


def _get_context(lines: list[str], line_num: int) -> tuple[list[str], list[str]]:
    """Return up to 2 context lines before and after line_num (1-based)."""
    idx = line_num - 1
    before = lines[max(0, idx - 2) : idx]
    after = lines[idx + 1 : min(len(lines), idx + 3)]
    return before, after


def _strip_comments(content: str) -> str:
    """Remove comment lines (# for nginx/haproxy, # for Apache) but keep structure."""
    # We don't strip comments from content — we only skip comment lines
    # when parsing individual tokens. The regex patterns already handle this
    # because they match from line start.
    return content


def _check_protocols(
    file_path: str,
    content: str,
    lines: list[str],
    match: re.Match[str],
    findings: list[Finding],
    algorithms_db: dict,
) -> None:
    """Check a protocol directive for weak TLS versions."""
    value_str = match.group(1)
    line_num = _line_number_of(content, match.start())
    raw_line = lines[line_num - 1] if line_num <= len(lines) else ""

    # Protocols can be space-separated, and Apache uses +/- prefixes
    tokens = re.split(r"[\s,]+", value_str)

    for token in tokens:
        clean = token.lstrip("+-!").strip().lower()
        if not clean:
            continue

        # Tokens with '-' prefix are *disabling* — that's good, skip
        if token.startswith("-") or token.startswith("!"):
            continue

        proto_info = _WEAK_PROTOCOLS.get(clean)
        if proto_info is None:
            continue

        severity, recommendation = proto_info

        # Weak protocols don't map directly to a crypto algorithm in the DB,
        # but the underlying issue is weak key exchange / cipher negotiation.
        # Use RSA-generic as the algorithm reference since these old protocols
        # typically rely on vulnerable key exchange.
        algo = algorithms_db.get("RSA-generic")
        if algo is None:
            continue

        ctx_before, ctx_after = _get_context(lines, line_num)

        findings.append(
            Finding(
                rule_id=f"tls-weak-protocol-{clean}",
                severity=severity,
                quantum_risk=QuantumRisk.VULNERABLE,
                algorithm=algo,
                location=FileLocation(
                    file_path=file_path,
                    line_number=line_num,
                    line_content=raw_line,
                    context_before=ctx_before,
                    context_after=ctx_after,
                ),
                message=f"Weak TLS protocol enabled: {token.strip()}",
                recommendation=recommendation,
            )
        )


def _check_ciphers(
    file_path: str,
    content: str,
    lines: list[str],
    match: re.Match[str],
    findings: list[Finding],
    algorithms_db: dict,
) -> None:
    """Check a cipher-suite directive for weak ciphers."""
    value_str = match.group(1)
    line_num = _line_number_of(content, match.start())
    raw_line = lines[line_num - 1] if line_num <= len(lines) else ""

    # Cipher suites are colon-separated (OpenSSL format) or comma/space separated
    tokens = re.split(r"[:, \t]+", value_str)

    for token in tokens:
        clean = token.strip().lstrip("!+-")
        if not clean:
            continue
        # If the token starts with ! or -, it's being excluded — skip
        if token.strip().startswith("!") or token.strip().startswith("-"):
            continue

        for pattern, algo_key, desc_fragment in _WEAK_CIPHER_PATTERNS:
            if not pattern.search(clean):
                continue

            algo = algorithms_db.get(algo_key)
            if algo is None:
                continue

            ctx_before, ctx_after = _get_context(lines, line_num)

            findings.append(
                Finding(
                    rule_id=f"tls-weak-cipher-{algo_key.lower()}-{clean.lower()}",
                    severity=_severity_for_cipher(algo),
                    quantum_risk=algo.quantum_risk,
                    algorithm=algo,
                    location=FileLocation(
                        file_path=file_path,
                        line_number=line_num,
                        line_content=raw_line,
                        context_before=ctx_before,
                        context_after=ctx_after,
                    ),
                    message=f"Weak TLS cipher suite: {clean} — {desc_fragment}",
                    recommendation=f"Remove {clean} from the cipher list. Use TLSv1.3 ciphers or ECDHE+AESGCM suites.",
                )
            )
            break  # One finding per token


def _severity_for_cipher(algo: Algorithm) -> Severity:
    """Map algorithm risk to finding severity."""
    if algo.quantum_risk == QuantumRisk.VULNERABLE:
        return Severity.CRITICAL if algo.family.value in ("DES", "RC4", "MD5", "3DES") else Severity.HIGH
    if algo.quantum_risk == QuantumRisk.WEAKENED:
        return Severity.MEDIUM
    return Severity.LOW


def _remove_comment_lines(content: str) -> str:
    """Remove full-line comments but preserve line numbering by replacing with empty lines."""
    out_lines: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            out_lines.append("")
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def parse_tls_config(file_path: str, content: str) -> list[Finding]:
    """Parse a TLS server config (nginx, Apache, HAProxy) and return findings.

    Handles comment lines, multi-line values (backslash continuation), and
    empty files gracefully.
    """
    if not content or not content.strip():
        return []

    algorithms_db = load_algorithms()
    findings: list[Finding] = []

    # Normalize backslash-continuation into single logical lines for regex
    normalized = content.replace("\\\n", " ")
    # Remove comment lines but keep line structure for accurate line numbers
    cleaned = _remove_comment_lines(normalized)
    lines = normalized.splitlines()

    # --- Nginx ---
    for m in _RE_NGINX_PROTOCOLS.finditer(cleaned):
        _check_protocols(file_path, normalized, lines, m, findings, algorithms_db)
    for m in _RE_NGINX_CIPHERS.finditer(cleaned):
        _check_ciphers(file_path, normalized, lines, m, findings, algorithms_db)

    # --- Apache ---
    for m in _RE_APACHE_PROTOCOLS.finditer(cleaned):
        _check_protocols(file_path, normalized, lines, m, findings, algorithms_db)
    for m in _RE_APACHE_CIPHERS.finditer(cleaned):
        _check_ciphers(file_path, normalized, lines, m, findings, algorithms_db)

    # --- HAProxy ---
    for m in _RE_HAPROXY_CIPHERS.finditer(cleaned):
        _check_ciphers(file_path, normalized, lines, m, findings, algorithms_db)

    # HAProxy ssl-default-bind-options can reference protocol versions
    for m in _RE_HAPROXY_OPTIONS.finditer(cleaned):
        _check_protocols(file_path, normalized, lines, m, findings, algorithms_db)

    return findings
