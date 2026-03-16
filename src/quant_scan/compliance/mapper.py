"""Compliance framework mapper — enriches findings with regulatory references."""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import Any

from quant_scan.core.models import Finding

logger = logging.getLogger(__name__)


@dataclass
class ComplianceRef:
    """A reference to a specific compliance framework requirement."""

    framework: str
    requirement_id: str
    description: str
    status: str  # "compliant", "non_compliant", "action_required"
    deadline: str | None = None

    def __str__(self) -> str:
        label = f"{self.framework} {self.requirement_id}: {self.description}"
        if self.deadline:
            label += f" (deadline: {self.deadline})"
        return label


# All known framework module names
_FRAMEWORK_MODULES = [
    "nist",
    "eu_roadmap",
    "ens",
    "iso27001",
    "pci_dss",
    "gdpr",
    "hipaa",
    "dora",
    "nis2",
    "eidas",
    "soc2",
    "bsi",
    "anssi",
    "cnss",
]


class ComplianceMapper:
    """Aggregate mapper that delegates to individual framework modules."""

    def __init__(self, enabled_frameworks: list[str] | None = None) -> None:
        self._frameworks: list[Any] = []
        targets = enabled_frameworks or _FRAMEWORK_MODULES
        for name in targets:
            try:
                mod = importlib.import_module(f"quant_scan.compliance.frameworks.{name}")
                self._frameworks.append(mod)
            except ImportError:
                logger.debug("Compliance framework %s not available", name)

    def map_finding(self, finding: Finding) -> list[ComplianceRef]:
        """Return all compliance references applicable to a single finding."""
        refs: list[ComplianceRef] = []
        for fw_module in self._frameworks:
            try:
                refs.extend(fw_module.map_finding(finding))
            except Exception:
                logger.exception("Error mapping finding with %s", fw_module.__name__)
        return refs


def enrich_findings_with_compliance(
    findings: list[Finding],
    enabled_frameworks: list[str] | None = None,
) -> list[Finding]:
    """Mutate each finding's compliance_refs with mapped framework references."""
    mapper = ComplianceMapper(enabled_frameworks=enabled_frameworks)
    for finding in findings:
        refs = mapper.map_finding(finding)
        finding.compliance_refs = [str(r) for r in refs]
    return findings
