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

    _loader_map = {
        "python": ("quant_scan.scanners.source.languages.python", "PythonAnalyzer"),
        "java": ("quant_scan.scanners.source.languages.java", "JavaAnalyzer"),
        "javascript": ("quant_scan.scanners.source.languages.javascript", "JavaScriptAnalyzer"),
        "golang": ("quant_scan.scanners.source.languages.golang", "GoAnalyzer"),
        "cpp": ("quant_scan.scanners.source.languages.cpp", "CppAnalyzer"),
        "csharp": ("quant_scan.scanners.source.languages.csharp", "CSharpAnalyzer"),
        "rust": ("quant_scan.scanners.source.languages.rust", "RustAnalyzer"),
        "swift": ("quant_scan.scanners.source.languages.swift", "SwiftAnalyzer"),
        "kotlin": ("quant_scan.scanners.source.languages.kotlin", "KotlinAnalyzer"),
        "php": ("quant_scan.scanners.source.languages.php", "PhpAnalyzer"),
        "ruby": ("quant_scan.scanners.source.languages.ruby", "RubyAnalyzer"),
        "typescript": ("quant_scan.scanners.source.languages.typescript", "TypeScriptAnalyzer"),
        "scala": ("quant_scan.scanners.source.languages.scala", "ScalaAnalyzer"),
        "dart": ("quant_scan.scanners.source.languages.dart", "DartAnalyzer"),
    }

    entry = _loader_map.get(language)
    if entry is None:
        return None

    import importlib

    module = importlib.import_module(entry[0])
    cls = getattr(module, entry[1])
    _analyzers[language] = cls()
    return _analyzers[language]
