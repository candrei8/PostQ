"""CBOM data models — Cryptographic Bill of Materials."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field


class CryptoAsset(BaseModel):
    """A single cryptographic asset in the inventory."""

    asset_type: str  # "algorithm", "key", "certificate", "protocol"
    name: str
    family: str = ""
    key_size: int | None = None
    quantum_risk: str = "unknown"
    severity: str = "info"
    occurrence_count: int = 1
    locations: list[str] = Field(default_factory=list)
    pqc_replacements: list[str] = Field(default_factory=list)
    description: str = ""


class CryptoBOM(BaseModel):
    """Complete Cryptographic Bill of Materials."""

    spec_version: str = "1.0"
    serial_number: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool_name: str = "quant-scan"
    tool_version: str = "0.2.0"
    targets: list[str] = Field(default_factory=list)
    components: list[CryptoAsset] = Field(default_factory=list)
    total_algorithms: int = 0
    vulnerable_count: int = 0
    weakened_count: int = 0
    safe_count: int = 0
    scan_duration_seconds: float = 0.0
