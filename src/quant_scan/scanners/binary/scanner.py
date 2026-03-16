"""Binary scanner — detects crypto usage in compiled binaries."""
from __future__ import annotations

import logging

from quant_scan.core.context import ScanContext
from quant_scan.core.models import Finding
from quant_scan.scanners.base import BaseScanner
from quant_scan.scanners.registry import register

logger = logging.getLogger(__name__)

_BINARY_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".o", ".a", ".elf", ".bin", ".lib"}


@register("binary")
class BinaryScanner(BaseScanner):
    """Scans compiled binaries for cryptographic algorithm usage."""

    name = "binary"

    def scan(self, context: ScanContext) -> list[Finding]:
        files = self.collect_files(context, _BINARY_EXTENSIONS)
        findings: list[Finding] = []

        for file_path in files:
            try:
                data = file_path.read_bytes()
            except OSError:
                continue

            # Skip very small files
            if len(data) < 64:
                continue

            from quant_scan.scanners.binary.analyzers.strings import analyze_strings

            findings.extend(analyze_strings(str(file_path), data))

            from quant_scan.scanners.binary.analyzers.symbols import analyze_symbols

            findings.extend(analyze_symbols(str(file_path), data))

            from quant_scan.scanners.binary.analyzers.entropy import analyze_entropy

            findings.extend(analyze_entropy(str(file_path), data))

        for f in findings:
            f.scanner_type = self.name
        return findings
