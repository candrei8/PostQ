"""SSH endpoint probe — analyzes SSH server algorithms."""
from __future__ import annotations

import logging
import socket
import struct

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding

logger = logging.getLogger(__name__)

_TIMEOUT = 5

# Weak SSH algorithms and their classifications
_WEAK_KEX = {
    "diffie-hellman-group1-sha1": (Severity.CRITICAL, "DH-Group1-SHA1", AlgorithmFamily.DH),
    "diffie-hellman-group14-sha1": (Severity.HIGH, "DH-Group14-SHA1", AlgorithmFamily.DH),
    "diffie-hellman-group-exchange-sha1": (Severity.HIGH, "DH-GEX-SHA1", AlgorithmFamily.DH),
    "ecdh-sha2-nistp256": (Severity.HIGH, "ECDH-P256", AlgorithmFamily.ECDH),
    "ecdh-sha2-nistp384": (Severity.HIGH, "ECDH-P384", AlgorithmFamily.ECDH),
}

_WEAK_HOST_KEYS = {
    "ssh-dss": (Severity.CRITICAL, "DSA", AlgorithmFamily.DSA),
    "ssh-rsa": (Severity.HIGH, "RSA", AlgorithmFamily.RSA),
    "ecdsa-sha2-nistp256": (Severity.HIGH, "ECDSA-P256", AlgorithmFamily.ECDSA),
    "ecdsa-sha2-nistp384": (Severity.HIGH, "ECDSA-P384", AlgorithmFamily.ECDSA),
}

_WEAK_CIPHERS = {
    "3des-cbc": (Severity.HIGH, "3DES-CBC", AlgorithmFamily.TRIPLE_DES),
    "des-cbc": (Severity.CRITICAL, "DES-CBC", AlgorithmFamily.DES),
    "blowfish-cbc": (Severity.HIGH, "Blowfish-CBC", AlgorithmFamily.BLOWFISH),
    "arcfour": (Severity.CRITICAL, "RC4", AlgorithmFamily.RC4),
    "arcfour128": (Severity.CRITICAL, "RC4-128", AlgorithmFamily.RC4),
    "arcfour256": (Severity.CRITICAL, "RC4-256", AlgorithmFamily.RC4),
    "aes128-cbc": (Severity.MEDIUM, "AES-128-CBC", AlgorithmFamily.AES),
    "aes128-ctr": (Severity.MEDIUM, "AES-128-CTR", AlgorithmFamily.AES),
}

_WEAK_MACS = {
    "hmac-md5": (Severity.HIGH, "HMAC-MD5", AlgorithmFamily.MD5),
    "hmac-md5-96": (Severity.HIGH, "HMAC-MD5-96", AlgorithmFamily.MD5),
    "hmac-sha1": (Severity.MEDIUM, "HMAC-SHA1", AlgorithmFamily.SHA1),
    "hmac-sha1-96": (Severity.MEDIUM, "HMAC-SHA1-96", AlgorithmFamily.SHA1),
    "umac-64@openssh.com": (Severity.MEDIUM, "UMAC-64", AlgorithmFamily.UNKNOWN),
}


def _make_location(host: str, port: int, detail: str) -> FileLocation:
    return FileLocation(file_path=f"{host}:{port}", line_number=0, line_content=detail)


def _parse_name_list(data: bytes, offset: int) -> tuple[list[str], int]:
    """Parse an SSH name-list (uint32 length + comma-separated string)."""
    if offset + 4 > len(data):
        return [], offset
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    if offset + length > len(data):
        return [], offset
    names = data[offset:offset + length].decode("ascii", errors="ignore")
    offset += length
    return names.split(",") if names else [], offset


def probe_ssh(host: str, port: int = 22) -> list[Finding]:
    """Probe an SSH server and analyze its algorithm support."""
    findings: list[Finding] = []

    try:
        sock = socket.create_connection((host, port), timeout=_TIMEOUT)
        sock.settimeout(_TIMEOUT)

        # Read server banner
        banner = sock.recv(256).decode("ascii", errors="ignore").strip()

        # Send our banner
        sock.sendall(b"SSH-2.0-quant-scan-probe\r\n")

        # Read KEX_INIT packet
        # SSH packet: uint32 length, byte padding_length, byte msg_type, ...
        header = b""
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                break
            header += chunk

        if len(header) < 4:
            sock.close()
            return findings

        packet_len = struct.unpack(">I", header)[0]
        if packet_len > 65536:
            sock.close()
            return findings

        payload = b""
        while len(payload) < packet_len:
            chunk = sock.recv(min(4096, packet_len - len(payload)))
            if not chunk:
                break
            payload += chunk

        sock.close()

        if len(payload) < 18:
            return findings

        padding_len = payload[0]
        msg_type = payload[1]

        # msg_type 20 = SSH_MSG_KEXINIT
        if msg_type != 20:
            return findings

        # Skip cookie (16 bytes) starting at offset 2
        offset = 18  # 1 (padding_len) + 1 (msg_type) + 16 (cookie)

        # Parse algorithm lists: kex, host_key, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c
        kex_algos, offset = _parse_name_list(payload, offset)
        host_key_algos, offset = _parse_name_list(payload, offset)
        cipher_c2s, offset = _parse_name_list(payload, offset)
        cipher_s2c, offset = _parse_name_list(payload, offset)
        mac_c2s, offset = _parse_name_list(payload, offset)
        mac_s2c, offset = _parse_name_list(payload, offset)

        # Analyze KEX algorithms
        for algo in kex_algos:
            if algo in _WEAK_KEX:
                sev, name, family = _WEAK_KEX[algo]
                risk = QuantumRisk.VULNERABLE
                findings.append(Finding(
                    rule_id=f"NET-SSH-KEX-{name.upper().replace('-', '')}",
                    severity=sev,
                    quantum_risk=risk,
                    algorithm=Algorithm(
                        name=name, family=family, quantum_risk=risk,
                        description=f"SSH KEX: {algo}",
                    ),
                    location=_make_location(host, port, f"KEX: {algo}"),
                    message=f"SSH server supports weak/quantum-vulnerable key exchange: {algo}",
                    recommendation="Disable weak KEX. Use curve25519-sha256 or sntrup761x25519-sha512",
                ))

        # Analyze host key algorithms
        for algo in host_key_algos:
            if algo in _WEAK_HOST_KEYS:
                sev, name, family = _WEAK_HOST_KEYS[algo]
                findings.append(Finding(
                    rule_id=f"NET-SSH-HOSTKEY-{name.upper().replace('-', '')}",
                    severity=sev,
                    quantum_risk=QuantumRisk.VULNERABLE,
                    algorithm=Algorithm(
                        name=name, family=family, quantum_risk=QuantumRisk.VULNERABLE,
                        description=f"SSH host key: {algo}",
                    ),
                    location=_make_location(host, port, f"HostKey: {algo}"),
                    message=f"SSH server supports quantum-vulnerable host key: {algo}",
                    recommendation="Use Ed25519 host keys. Plan migration to PQC host keys",
                ))

        # Analyze ciphers (union of c2s and s2c)
        all_ciphers = set(cipher_c2s) | set(cipher_s2c)
        for algo in all_ciphers:
            if algo in _WEAK_CIPHERS:
                sev, name, family = _WEAK_CIPHERS[algo]
                risk = QuantumRisk.WEAKENED if family == AlgorithmFamily.AES else QuantumRisk.VULNERABLE
                findings.append(Finding(
                    rule_id=f"NET-SSH-CIPHER-{name.upper().replace('-', '')}",
                    severity=sev,
                    quantum_risk=risk,
                    algorithm=Algorithm(
                        name=name, family=family, quantum_risk=risk,
                        description=f"SSH cipher: {algo}",
                    ),
                    location=_make_location(host, port, f"Cipher: {algo}"),
                    message=f"SSH server supports weak cipher: {algo}",
                    recommendation="Use AES-256-GCM or ChaCha20-Poly1305",
                ))

        # Analyze MACs
        all_macs = set(mac_c2s) | set(mac_s2c)
        for algo in all_macs:
            if algo in _WEAK_MACS:
                sev, name, family = _WEAK_MACS[algo]
                findings.append(Finding(
                    rule_id=f"NET-SSH-MAC-{name.upper().replace('-', '')}",
                    severity=sev,
                    quantum_risk=QuantumRisk.VULNERABLE if family in (AlgorithmFamily.MD5,) else QuantumRisk.WEAKENED,
                    algorithm=Algorithm(
                        name=name, family=family,
                        quantum_risk=QuantumRisk.VULNERABLE if family == AlgorithmFamily.MD5 else QuantumRisk.WEAKENED,
                        description=f"SSH MAC: {algo}",
                    ),
                    location=_make_location(host, port, f"MAC: {algo}"),
                    message=f"SSH server supports weak MAC: {algo}",
                    recommendation="Use HMAC-SHA2-256 or HMAC-SHA2-512",
                ))

    except (socket.error, OSError) as e:
        logger.info("SSH probe failed for %s:%d: %s", host, port, e)

    return findings
