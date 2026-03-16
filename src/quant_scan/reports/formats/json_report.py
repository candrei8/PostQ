"""JSON report format."""

from __future__ import annotations

from quant_scan.core.models import ScanResult


def render_json(result: ScanResult) -> str:
    """Render scan results as a JSON string."""
    return result.model_dump_json(indent=2)
