"""CycloneDX 1.6 CBOM format — standardized crypto inventory."""
from __future__ import annotations

import json
from typing import Any

from quant_scan.cbom.models import CryptoBOM

# Map asset types to CycloneDX crypto asset types
_ASSET_TYPE_MAP = {
    "algorithm": "algorithm",
    "key": "related-crypto-material",
    "certificate": "certificate",
    "protocol": "protocol",
}

# Map algorithm families to CycloneDX primitives
_PRIMITIVE_MAP = {
    "RSA": "pke",
    "ECC": "pke",
    "ECDSA": "signature",
    "ECDH": "key-agree",
    "DSA": "signature",
    "DH": "key-agree",
    "AES": "ae",
    "DES": "block-cipher",
    "3DES": "block-cipher",
    "ChaCha20": "stream-cipher",
    "RC4": "stream-cipher",
    "Blowfish": "block-cipher",
    "MD5": "hash",
    "SHA-1": "hash",
    "SHA-2": "hash",
    "SHA-3": "hash",
    "ML-KEM": "kem",
    "ML-DSA": "signature",
    "SLH-DSA": "signature",
    "Random": "other",
    "Unknown": "unknown",
}


def render_cyclonedx(cbom: CryptoBOM) -> str:
    """Render CBOM as CycloneDX 1.6 JSON."""
    components: list[dict[str, Any]] = []

    for asset in cbom.components:
        component: dict[str, Any] = {
            "type": "cryptographic-asset",
            "name": asset.name,
            "version": "",
            "description": asset.description,
            "cryptoProperties": {
                "assetType": _ASSET_TYPE_MAP.get(asset.asset_type, "algorithm"),
                "algorithmProperties": {
                    "primitive": _PRIMITIVE_MAP.get(asset.family, "unknown"),
                },
            },
            "properties": [
                {"name": "quantum-risk", "value": asset.quantum_risk},
                {"name": "severity", "value": asset.severity},
                {"name": "occurrence-count", "value": str(asset.occurrence_count)},
                {"name": "family", "value": asset.family},
            ],
        }

        if asset.key_size:
            component["cryptoProperties"]["algorithmProperties"][
                "parameterSetIdentifier"
            ] = str(asset.key_size)

        if asset.pqc_replacements:
            component["cryptoProperties"]["algorithmProperties"][
                "certificationLevel"
            ] = asset.pqc_replacements

        if asset.locations:
            component["evidence"] = {
                "occurrences": [
                    {"location": loc} for loc in asset.locations[:20]
                ]
            }

        components.append(component)

    cdx: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{cbom.serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": cbom.timestamp.isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": cbom.tool_name,
                        "version": cbom.tool_version,
                    }
                ]
            },
            "properties": [
                {"name": "scan-targets", "value": ", ".join(cbom.targets)},
                {"name": "total-algorithms", "value": str(cbom.total_algorithms)},
                {"name": "vulnerable-count", "value": str(cbom.vulnerable_count)},
                {"name": "weakened-count", "value": str(cbom.weakened_count)},
                {"name": "safe-count", "value": str(cbom.safe_count)},
                {
                    "name": "scan-duration-seconds",
                    "value": str(cbom.scan_duration_seconds),
                },
            ],
        },
        "components": components,
    }

    return json.dumps(cdx, indent=2, ensure_ascii=False, default=str)
