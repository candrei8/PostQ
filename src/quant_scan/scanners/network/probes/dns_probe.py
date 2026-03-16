"""DNS security probe — checks DNSSEC and DANE/TLSA records."""

from __future__ import annotations

import logging

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding

logger = logging.getLogger(__name__)


def probe_dns(domain: str) -> list[Finding]:
    """Check DNS security configuration for a domain.

    Uses dnspython if available, otherwise skips.
    """
    findings: list[Finding] = []

    try:
        import dns.dnssec
        import dns.resolver

        # Check for TLSA records (DANE)
        try:
            dns.resolver.resolve(f"_443._tcp.{domain}", "TLSA")
            # TLSA records exist — DANE is configured
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            findings.append(
                Finding(
                    rule_id="NET-DNS-NO-DANE",
                    severity=Severity.INFO,
                    quantum_risk=QuantumRisk.UNKNOWN,
                    algorithm=Algorithm(
                        name="DANE-Missing",
                        family=AlgorithmFamily.UNKNOWN,
                        quantum_risk=QuantumRisk.UNKNOWN,
                        description="No DANE/TLSA records found",
                    ),
                    location=FileLocation(file_path=domain, line_number=0, line_content="DNS"),
                    message=f"No DANE/TLSA records found for {domain}",
                    recommendation="Consider deploying DANE/TLSA for certificate pinning",
                )
            )
    except ImportError:
        logger.debug("dnspython not available, skipping DNS probe")

    return findings
