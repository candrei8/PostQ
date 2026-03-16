"""STARTTLS probe — upgrades plain connections to TLS and analyzes."""

from __future__ import annotations

import logging
import socket

from quant_scan.core.models import Finding

logger = logging.getLogger(__name__)

_TIMEOUT = 5


def _smtp_starttls(host: str, port: int) -> socket.socket | None:
    """Perform SMTP STARTTLS upgrade."""
    try:
        sock = socket.create_connection((host, port), timeout=_TIMEOUT)
        sock.settimeout(_TIMEOUT)
        sock.recv(1024)  # greeting
        sock.sendall(b"EHLO quant-scan\r\n")
        response = sock.recv(4096).decode("ascii", errors="ignore")
        if "STARTTLS" not in response.upper():
            sock.close()
            return None
        sock.sendall(b"STARTTLS\r\n")
        response = sock.recv(1024).decode("ascii", errors="ignore")
        if not response.startswith("220"):
            sock.close()
            return None
        return sock
    except (socket.error, OSError):
        return None


def _imap_starttls(host: str, port: int) -> socket.socket | None:
    """Perform IMAP STARTTLS upgrade."""
    try:
        sock = socket.create_connection((host, port), timeout=_TIMEOUT)
        sock.settimeout(_TIMEOUT)
        sock.recv(1024)  # greeting
        sock.sendall(b"a001 STARTTLS\r\n")
        response = sock.recv(1024).decode("ascii", errors="ignore")
        if "OK" not in response.upper():
            sock.close()
            return None
        return sock
    except (socket.error, OSError):
        return None


def _pop3_starttls(host: str, port: int) -> socket.socket | None:
    """Perform POP3 STLS upgrade."""
    try:
        sock = socket.create_connection((host, port), timeout=_TIMEOUT)
        sock.settimeout(_TIMEOUT)
        sock.recv(1024)  # greeting
        sock.sendall(b"STLS\r\n")
        response = sock.recv(1024).decode("ascii", errors="ignore")
        if not response.startswith("+OK"):
            sock.close()
            return None
        return sock
    except (socket.error, OSError):
        return None


def probe_starttls(host: str, port: int) -> list[Finding]:
    """Probe a STARTTLS-capable service."""
    import ssl

    upgraders = {
        25: _smtp_starttls,
        587: _smtp_starttls,
        143: _imap_starttls,
        110: _pop3_starttls,
    }

    upgrader = upgraders.get(port)
    if upgrader is None:
        return []

    sock = upgrader(host, port)
    if sock is None:
        return []

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)

        # Delegate to TLS probe logic
        from quant_scan.scanners.network.probes.tls_probe import probe_tls

        findings = probe_tls(host, port)

        tls_sock.close()
        return findings
    except Exception as e:
        logger.info("STARTTLS upgrade failed for %s:%d: %s", host, port, e)
        try:
            sock.close()
        except Exception:
            pass
        return []
