"""FastAPI application — REST API for quant-scan."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


def create_app():
    """Create and configure the FastAPI application."""
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("quant-scan API server starting")
        yield
        logger.info("quant-scan API server shutting down")

    app = FastAPI(
        title="quant-scan API",
        description="Post-Quantum Cryptography Vulnerability Scanner API",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routes
    from quant_scan.server.api.v1 import router as v1_router

    app.include_router(v1_router, prefix="/api/v1")

    @app.get("/health")
    async def health():
        return {"status": "healthy", "version": "0.2.0"}

    return app
