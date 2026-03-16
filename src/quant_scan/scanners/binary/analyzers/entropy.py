"""Entropy analysis — detects high-entropy regions that may contain embedded keys."""
from __future__ import annotations

import math

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm, FileLocation, Finding

_BLOCK_SIZE = 256
_ENTROPY_THRESHOLD = 7.5  # bits per byte (max is 8.0)
_MAX_FINDINGS = 5  # Cap number of entropy findings per file


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def analyze_entropy(file_path: str, data: bytes) -> list[Finding]:
    """Scan binary data for high-entropy regions that may contain embedded keys."""
    findings: list[Finding] = []

    # Skip files smaller than one block
    if len(data) < _BLOCK_SIZE:
        return findings

    high_entropy_regions: list[tuple[int, float]] = []

    for offset in range(0, len(data) - _BLOCK_SIZE, _BLOCK_SIZE):
        block = data[offset:offset + _BLOCK_SIZE]
        entropy = _shannon_entropy(block)

        if entropy >= _ENTROPY_THRESHOLD:
            high_entropy_regions.append((offset, entropy))

    # Only report if there are isolated high-entropy regions (not compressed files)
    # If more than 50% of blocks are high-entropy, the file is likely compressed/encrypted entirely
    total_blocks = max(1, len(data) // _BLOCK_SIZE)
    if len(high_entropy_regions) > total_blocks * 0.5:
        return findings  # Likely a compressed file, not interesting

    for offset, entropy in high_entropy_regions[:_MAX_FINDINGS]:
        findings.append(Finding(
            rule_id="BIN-ENTROPY-HIGH",
            severity=Severity.INFO,
            quantum_risk=QuantumRisk.UNKNOWN,
            algorithm=Algorithm(
                name="Unknown-HighEntropy",
                family=AlgorithmFamily.UNKNOWN,
                quantum_risk=QuantumRisk.UNKNOWN,
                description=f"High-entropy region (entropy: {entropy:.2f} bits/byte)",
            ),
            location=FileLocation(
                file_path=file_path,
                line_number=offset,
                line_content=f"offset 0x{offset:x}: entropy={entropy:.2f} bits/byte",
            ),
            message=f"High-entropy region detected at offset 0x{offset:x} (entropy: {entropy:.2f}/8.0) — may contain embedded cryptographic key material",
            recommendation="Review binary for embedded keys or certificates. Use proper key management instead of embedding keys in binaries",
        ))

    return findings
