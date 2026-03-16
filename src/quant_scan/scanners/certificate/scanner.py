"""Certificate scanner — detects quantum-vulnerable crypto in X.509 certs."""

from __future__ import annotations

import logging

from quant_scan.core.context import ScanContext
from quant_scan.core.models import Finding
from quant_scan.scanners.base import BaseScanner
from quant_scan.scanners.certificate.cert_parser import parse_certificate_file
from quant_scan.scanners.registry import register

logger = logging.getLogger(__name__)

# File extensions to scan for certificates
_CERT_EXTENSIONS: set[str] = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx"}


@register("certificate")
class CertificateScanner(BaseScanner):
    """Scans X.509 certificate files for quantum-vulnerable algorithms."""

    name = "certificate"

    def scan(self, context: ScanContext) -> list[Finding]:
        files = self.collect_files(context, _CERT_EXTENSIONS)
        findings: list[Finding] = []

        for file_path in files:
            try:
                file_findings = parse_certificate_file(str(file_path))
                for f in file_findings:
                    f.scanner_type = self.name
                findings.extend(file_findings)
            except Exception as exc:
                logger.warning(
                    "Unexpected error scanning certificate %s: %s",
                    file_path,
                    exc,
                )

        return findings
