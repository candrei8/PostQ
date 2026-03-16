"""Client branding configuration for PDF reports."""

from __future__ import annotations

from pydantic import BaseModel


class BrandingConfig(BaseModel):
    """Configuration for client-branded reports."""

    client_name: str = ""
    client_logo_path: str | None = None
    report_title: str = ""
    language: str = "en"
    branding_color: str = "#6c7ee1"
    secondary_color: str = "#1a1a2e"
    accent_color: str = "#e94560"
    prepared_by: str = "EYD Company"
