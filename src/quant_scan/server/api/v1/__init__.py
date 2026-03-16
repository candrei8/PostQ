"""API v1 routes."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["v1"])

# Routes must be imported after router is defined so they can register endpoints.
from quant_scan.server.api.v1 import projects, reports, scans  # noqa: E402, F401
