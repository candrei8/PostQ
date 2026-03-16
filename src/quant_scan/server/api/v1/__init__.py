"""API v1 routes."""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["v1"])

from quant_scan.server.api.v1 import scans  # noqa: E402, F401
from quant_scan.server.api.v1 import projects  # noqa: E402, F401
from quant_scan.server.api.v1 import reports  # noqa: E402, F401
