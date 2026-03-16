"""Container scanner — detects crypto issues in Dockerfiles and K8s manifests."""
from __future__ import annotations

import logging

from quant_scan.core.context import ScanContext
from quant_scan.core.models import Finding
from quant_scan.scanners.base import BaseScanner
from quant_scan.scanners.registry import register

logger = logging.getLogger(__name__)

_DOCKER_NAMES = {"Dockerfile", "Dockerfile.prod", "Dockerfile.dev", "Containerfile"}


@register("container")
class ContainerScanner(BaseScanner):
    """Scans container configs for cryptographic vulnerabilities."""

    name = "container"

    def scan(self, context: ScanContext) -> list[Finding]:
        files = self.collect_files(context, {".yaml", ".yml", ".dockerfile"})
        findings: list[Finding] = []

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            name = file_path.name
            if name in _DOCKER_NAMES or name.startswith("Dockerfile"):
                from quant_scan.scanners.container.analyzers.dockerfile import (
                    parse_dockerfile,
                )

                findings.extend(parse_dockerfile(str(file_path), content))
            elif any(kw in content for kw in ("kind:", "apiVersion:", "kubernetes")):
                from quant_scan.scanners.container.analyzers.kubernetes import (
                    parse_kubernetes,
                )

                findings.extend(parse_kubernetes(str(file_path), content))

        for f in findings:
            f.scanner_type = self.name
        return findings
