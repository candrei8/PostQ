"""CBOM generator — creates Cryptographic Bill of Materials from scan results."""

from __future__ import annotations

from collections import defaultdict

from quant_scan.cbom.models import CryptoAsset, CryptoBOM
from quant_scan.core.enums import QuantumRisk
from quant_scan.core.models import Finding, ScanResult


def generate_cbom(result: ScanResult) -> CryptoBOM:
    """Generate a CBOM from scan results.

    Groups findings by algorithm name, deduplicates, and creates
    a structured inventory of all cryptographic assets found.
    """
    # Group findings by algorithm name
    by_algo: dict[str, list[Finding]] = defaultdict(list)
    for finding in result.findings:
        by_algo[finding.algorithm.name].append(finding)

    components: list[CryptoAsset] = []
    vulnerable = 0
    weakened = 0
    safe = 0

    for algo_name, findings in sorted(by_algo.items()):
        # Use the first finding for metadata
        first = findings[0]
        locations = sorted({f.location.file_path for f in findings})

        # Determine worst risk
        risk = first.quantum_risk
        if any(f.quantum_risk == QuantumRisk.VULNERABLE for f in findings):
            risk = QuantumRisk.VULNERABLE
        elif any(f.quantum_risk == QuantumRisk.WEAKENED for f in findings):
            risk = QuantumRisk.WEAKENED

        # Determine asset type
        if first.scanner_type == "certificate":
            asset_type = "certificate"
        elif first.scanner_type == "network":
            asset_type = "protocol"
        elif first.scanner_type == "secrets":
            asset_type = "key"
        else:
            asset_type = "algorithm"

        # Determine worst severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        worst_sev = min(findings, key=lambda f: severity_order.get(f.severity.value, 4))

        components.append(
            CryptoAsset(
                asset_type=asset_type,
                name=algo_name,
                family=first.algorithm.family.value,
                key_size=first.algorithm.key_size,
                quantum_risk=risk.value,
                severity=worst_sev.severity.value,
                occurrence_count=len(findings),
                locations=locations[:50],  # Cap at 50 locations
                pqc_replacements=first.algorithm.pqc_replacements,
                description=first.algorithm.description,
            )
        )

        if risk == QuantumRisk.VULNERABLE:
            vulnerable += 1
        elif risk == QuantumRisk.WEAKENED:
            weakened += 1
        elif risk == QuantumRisk.SAFE:
            safe += 1

    return CryptoBOM(
        targets=result.targets,
        components=components,
        total_algorithms=len(components),
        vulnerable_count=vulnerable,
        weakened_count=weakened,
        safe_count=safe,
        scan_duration_seconds=result.duration_seconds,
    )
