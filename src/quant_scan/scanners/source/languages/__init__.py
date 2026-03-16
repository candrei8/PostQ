"""Language analyzers for source code scanning."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from quant_scan.scanners.source.languages.base import LanguageAnalyzer

_analyzers: dict[str, "LanguageAnalyzer"] = {}


def get_language_analyzer(language: str) -> "LanguageAnalyzer | None":
    """Get a language analyzer by name, lazy-loading on first access."""
    if language in _analyzers:
        return _analyzers[language]

    if language == "python":
        from quant_scan.scanners.source.languages.python import PythonAnalyzer

        _analyzers[language] = PythonAnalyzer()
        return _analyzers[language]

    return None
