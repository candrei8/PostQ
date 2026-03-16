"""Configuration file scanner — detects weak crypto in SSH, TLS, and server configs."""

from __future__ import annotations

from pathlib import Path

import pathspec

from quant_scan.core.context import ScanContext
from quant_scan.core.models import Finding
from quant_scan.scanners.base import BaseScanner
from quant_scan.scanners.config.parsers.ssh import parse_ssh_config
from quant_scan.scanners.config.parsers.tls_server import parse_tls_config
from quant_scan.scanners.registry import register

# ---------------------------------------------------------------------------
# File-name patterns
# ---------------------------------------------------------------------------

_SSH_NAMES: set[str] = {
    "sshd_config",
    "ssh_config",
}

_TLS_NAMES: set[str] = {
    "nginx.conf",
    "httpd.conf",
    "apache2.conf",
    "haproxy.cfg",
}

_TLS_EXTENSIONS: set[str] = {
    ".conf",
    ".cfg",
}


def _is_ssh_config(path: Path) -> bool:
    """Return True if the path looks like an SSH configuration file."""
    return path.name in _SSH_NAMES


def _is_tls_config(path: Path) -> bool:
    """Return True if the path looks like a TLS server configuration file."""
    if path.name in _TLS_NAMES:
        return True
    if path.suffix in _TLS_EXTENSIONS:
        return True
    return False


@register("config")
class ConfigScanner(BaseScanner):
    """Scans configuration files for weak cryptographic settings.

    Covers SSH daemon/client configs and TLS server configs (nginx, Apache,
    HAProxy).
    """

    name = "config"

    def scan(self, context: ScanContext) -> list[Finding]:
        files = self._collect_config_files(context)
        findings: list[Finding] = []

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            if not content.strip():
                continue

            file_findings: list[Finding] = []

            if _is_ssh_config(file_path):
                file_findings = parse_ssh_config(str(file_path), content)
            elif _is_tls_config(file_path):
                file_findings = parse_tls_config(str(file_path), content)

            for f in file_findings:
                f.scanner_type = self.name

            findings.extend(file_findings)

        return findings

    def _collect_config_files(self, context: ScanContext) -> list[Path]:
        """Walk targets and collect SSH and TLS config files."""
        spec = (
            pathspec.PathSpec.from_lines("gitwildmatch", context.exclude_patterns)
            if context.exclude_patterns
            else None
        )

        files: list[Path] = []

        for target in context.targets:
            if target.is_file():
                if _is_ssh_config(target) or _is_tls_config(target):
                    files.append(target)
                continue

            for p in target.rglob("*"):
                if not p.is_file():
                    continue

                if not (_is_ssh_config(p) or _is_tls_config(p)):
                    continue

                try:
                    rel = p.relative_to(target)
                except ValueError:
                    rel = p

                if spec and spec.match_file(str(rel)):
                    continue

                files.append(p)

        return files
