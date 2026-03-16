"""Vendor recommendation engine — PQShield vs QuSecure vs Open Source."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"
_vendor_data: dict | None = None


def _load_vendor_data() -> dict:
    global _vendor_data
    if _vendor_data is None:
        path = _DATA_DIR / "vendor_capabilities.yml"
        try:
            with open(path, encoding="utf-8") as f:
                _vendor_data = yaml.safe_load(f)
        except Exception:
            logger.exception("Failed to load vendor data")
            _vendor_data = {"vendors": {}}
    return _vendor_data


# Decision matrix: use_case -> recommended vendor
_USE_CASE_MAP: dict[str, str] = {
    "hsm": "PQShield",
    "embedded": "PQShield",
    "iot": "PQShield",
    "low_latency": "PQShield",
    "hardware": "PQShield",
    "fips": "PQShield",
    "government": "PQShield",
    "defense": "PQShield",
    "tls": "QuSecure",
    "network": "QuSecure",
    "orchestration": "QuSecure",
    "hybrid": "QuSecure",
    "cloud": "QuSecure",
    "enterprise": "QuSecure",
    "vpn": "QuSecure",
    "development": "OpenSource",
    "testing": "OpenSource",
    "research": "OpenSource",
    "non_critical": "OpenSource",
    "budget": "OpenSource",
    "library_call": "OpenSource",
}


def recommend_vendor(
    context_type: str = "library_call",
    is_critical: bool = False,
    requires_fips: bool = False,
) -> str:
    """Recommend a vendor based on migration context.

    Parameters
    ----------
    context_type:
        Type of crypto usage: tls_config, certificate, key_management,
        library_call, custom_implementation, hsm, embedded.
    is_critical:
        Whether the system is business-critical.
    requires_fips:
        Whether FIPS certification is required.
    """
    if requires_fips:
        return "PQShield"

    if context_type in ("tls_config", "certificate", "vpn"):
        return "QuSecure"

    if context_type in ("hsm", "embedded", "hardware"):
        return "PQShield"

    if is_critical and context_type == "key_management":
        return "QuSecure"

    return _USE_CASE_MAP.get(context_type, "OpenSource")


def get_vendor_info(vendor_name: str) -> dict:
    """Get detailed vendor information."""
    data = _load_vendor_data()
    vendors = data.get("vendors", {})
    return vendors.get(vendor_name, {})
