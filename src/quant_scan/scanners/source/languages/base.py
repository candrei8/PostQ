"""Base class for language-specific analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from quant_scan.core.models import Finding


class LanguageAnalyzer(ABC):
    """Interface for per-language crypto detection."""

    language: str = ""

    @abstractmethod
    def analyze(self, file_path: str, content: str) -> list[Finding]:
        """Analyze source code and return findings."""
