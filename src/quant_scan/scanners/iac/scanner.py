"""IaC scanner — detects crypto configurations in infrastructure code."""

from __future__ import annotations

import logging

from quant_scan.core.context import ScanContext
from quant_scan.core.models import Finding
from quant_scan.scanners.base import BaseScanner
from quant_scan.scanners.registry import register

logger = logging.getLogger(__name__)


@register("iac")
class IacScanner(BaseScanner):
    """Scans Infrastructure-as-Code files for crypto vulnerabilities."""

    name = "iac"

    def scan(self, context: ScanContext) -> list[Finding]:
        files = self.collect_files(context, {".tf", ".yaml", ".yml", ".json"})
        findings: list[Finding] = []

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            if file_path.suffix == ".tf":
                from quant_scan.scanners.iac.parsers.terraform import parse_terraform

                findings.extend(parse_terraform(str(file_path), content))
            elif "AWSTemplateFormatVersion" in content or "AWS::" in content:
                from quant_scan.scanners.iac.parsers.cloudformation import (
                    parse_cloudformation,
                )

                findings.extend(parse_cloudformation(str(file_path), content))
            elif any(kw in content for kw in ("hosts:", "tasks:", "- name:", "ansible")):
                from quant_scan.scanners.iac.parsers.ansible import parse_ansible

                findings.extend(parse_ansible(str(file_path), content))

        for f in findings:
            f.scanner_type = self.name
        return findings
