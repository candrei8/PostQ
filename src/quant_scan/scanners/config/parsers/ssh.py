"""SSH configuration parser — detects weak ciphers, MACs, KEX, and host-key algorithms."""

from __future__ import annotations

import re

from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding
from quant_scan.rules.loader import load_algorithms

# ---------------------------------------------------------------------------
# Weak-algorithm mappings: SSH cipher/token -> (algorithm DB key, rule_id suffix)
# ---------------------------------------------------------------------------

_WEAK_CIPHERS: dict[str, str] = {
    # DES variants
    "des": "DES",
    "des-cbc": "DES",
    "des-cbc@ssh.com": "DES",
    # 3DES variants
    "3des": "3DES",
    "3des-cbc": "3DES",
    "3des-ctr": "3DES",
    # Blowfish variants
    "blowfish": "Blowfish",
    "blowfish-cbc": "Blowfish",
    "blowfish-ctr": "Blowfish",
    # RC4 / arcfour variants
    "rc4": "RC4",
    "arcfour": "RC4",
    "arcfour128": "RC4",
    "arcfour256": "RC4",
    # AES-128 (quantum-weakened, Grover halves effective key length)
    "aes128-cbc": "AES-128",
    "aes128-ctr": "AES-128",
    "aes128-gcm@openssh.com": "AES-128",
}

_WEAK_MACS: dict[str, str] = {
    "hmac-md5": "MD5",
    "hmac-md5-96": "MD5",
    "hmac-md5-etm@openssh.com": "MD5",
    "hmac-md5-96-etm@openssh.com": "MD5",
    "hmac-sha1": "SHA-1",
    "hmac-sha1-96": "SHA-1",
    "hmac-sha1-etm@openssh.com": "SHA-1",
    "hmac-sha1-96-etm@openssh.com": "SHA-1",
    "umac-64": "SHA-1",  # UMAC-64 has insufficient tag length
    "umac-64@openssh.com": "SHA-1",
    "umac-64-etm@openssh.com": "SHA-1",
}

_WEAK_KEX: dict[str, str] = {
    "diffie-hellman-group1-sha1": "DH-generic",
    "diffie-hellman-group14-sha1": "DH-generic",
    "diffie-hellman-group-exchange-sha1": "DH-generic",
    "ecdh-sha2-nistp256": "ECDH-generic",
}

_WEAK_HOSTKEY: dict[str, str] = {
    "ssh-dss": "DSA-generic",
    "ssh-rsa": "RSA-generic",
    "ecdsa-sha2-nistp256": "ECDSA-generic",
}

# Directives we look for (case-insensitive matching for robustness)
_DIRECTIVE_MAP: dict[str, tuple[dict[str, str], str, str]] = {
    "ciphers": (
        _WEAK_CIPHERS,
        "Weak SSH cipher configured",
        "Remove {token} and use chacha20-poly1305 or aes256-gcm ciphers.",
    ),
    "macs": (
        _WEAK_MACS,
        "Weak SSH MAC algorithm configured",
        "Remove {token} and use hmac-sha2-256-etm or hmac-sha2-512-etm.",
    ),
    "kexalgorithms": (
        _WEAK_KEX,
        "Weak SSH key-exchange algorithm configured",
        "Remove {token} and use curve25519-sha256 or sntrup761x25519-sha512.",
    ),
    "hostkeyalgorithms": (
        _WEAK_HOSTKEY,
        "Weak SSH host-key algorithm configured",
        "Remove {token} and use ssh-ed25519 or rsa-sha2-512 with >= 3072-bit keys.",
    ),
}


def _severity_for(algo: Algorithm) -> Severity:
    """Derive severity from the algorithm's quantum_risk and inherent weakness."""
    if algo.quantum_risk == QuantumRisk.VULNERABLE:
        return Severity.CRITICAL if algo.family.value in ("DES", "RC4", "MD5", "3DES") else Severity.HIGH
    if algo.quantum_risk == QuantumRisk.WEAKENED:
        return Severity.MEDIUM
    return Severity.LOW


def parse_ssh_config(file_path: str, content: str) -> list[Finding]:
    """Parse an SSH/SSHD config file and return findings for weak algorithms.

    Handles comments, blank lines, and comma- or whitespace-separated values.
    """
    algorithms_db = load_algorithms()
    findings: list[Finding] = []

    lines = content.splitlines()
    for line_num, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            continue

        # Split directive from value (first whitespace or '=')
        match = re.match(r"^(\S+)\s*=?\s*(.*)", stripped)
        if not match:
            continue

        directive = match.group(1).lower()
        value_str = match.group(2).strip()

        if directive not in _DIRECTIVE_MAP:
            continue

        weak_map, message_tpl, recommendation_tpl = _DIRECTIVE_MAP[directive]

        # Values can be comma-separated and/or whitespace-separated
        tokens = re.split(r"[,\s]+", value_str)

        for token in tokens:
            token_lower = token.lower().strip()
            if not token_lower:
                continue

            algo_key = weak_map.get(token_lower)
            if algo_key is None:
                continue

            algo = algorithms_db.get(algo_key)
            if algo is None:
                continue

            # Build context lines
            ctx_before = []
            ctx_after = []
            if line_num > 1:
                start = max(0, line_num - 3)
                ctx_before = lines[start : line_num - 1]
            if line_num < len(lines):
                ctx_after = lines[line_num : min(len(lines), line_num + 2)]

            findings.append(
                Finding(
                    rule_id=f"ssh-weak-{directive}-{token_lower}",
                    severity=_severity_for(algo),
                    quantum_risk=algo.quantum_risk,
                    algorithm=algo,
                    location=FileLocation(
                        file_path=file_path,
                        line_number=line_num,
                        line_content=raw_line,
                        context_before=ctx_before,
                        context_after=ctx_after,
                    ),
                    message=f"{message_tpl}: {token}",
                    recommendation=recommendation_tpl.format(token=token),
                )
            )

    return findings
