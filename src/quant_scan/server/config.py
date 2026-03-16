"""Server configuration."""

from __future__ import annotations

from pydantic import BaseModel


class ServerConfig(BaseModel):
    """Configuration for the API server."""

    host: str = "0.0.0.0"
    port: int = 8000
    db_url: str = "sqlite:///quant-scan.db"
    workers: int = 1
    debug: bool = False
    api_key: str | None = None
