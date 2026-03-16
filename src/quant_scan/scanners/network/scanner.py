"""Network scanner — probes live endpoints for crypto vulnerabilities."""
from __future__ import annotations

import logging

from quant_scan.core.context import ScanContext
from quant_scan.core.models import Finding
from quant_scan.scanners.base import BaseScanner
from quant_scan.scanners.registry import register

logger = logging.getLogger(__name__)


@register("network")
class NetworkScanner(BaseScanner):
    """Probes network endpoints for quantum-vulnerable cryptography."""

    name = "network"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        targets = getattr(context, "network_targets", [])
        if not targets:
            return findings

        for target in targets:
            # Parse host:port
            if ":" in target:
                host, port_str = target.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    host, port = target, 443
            else:
                host, port = target, 443

            # TLS probe
            try:
                from quant_scan.scanners.network.probes.tls_probe import probe_tls

                findings.extend(probe_tls(host, port))
            except Exception as e:
                logger.warning("TLS probe failed for %s:%d: %s", host, port, e)

            # SSH probe (port 22)
            if port == 22:
                try:
                    from quant_scan.scanners.network.probes.ssh_probe import probe_ssh

                    findings.extend(probe_ssh(host, port))
                except Exception as e:
                    logger.warning("SSH probe failed for %s:%d: %s", host, port, e)

        for f in findings:
            f.scanner_type = self.name
        return findings
