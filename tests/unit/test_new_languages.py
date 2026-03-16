"""Tests for new language analyzers (Rust, Swift, Kotlin, PHP, Ruby, TypeScript, Scala, Dart)."""

from __future__ import annotations

from pathlib import Path

import pytest

from quant_scan.scanners.source.languages import get_language_analyzer

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

_NEW_LANGUAGES = [
    ("rust", "vulnerable_rust.rs"),
    ("swift", "vulnerable_swift.swift"),
    ("kotlin", "vulnerable_kotlin.kt"),
    ("php", "vulnerable_php.php"),
    ("ruby", "vulnerable_ruby.rb"),
    ("typescript", "vulnerable_typescript.ts"),
    ("scala", "vulnerable_scala.scala"),
    ("dart", "vulnerable_dart.dart"),
]


@pytest.mark.parametrize("lang,fixture", _NEW_LANGUAGES)
def test_analyzer_loads(lang, fixture):
    """Each new language analyzer should load successfully."""
    analyzer = get_language_analyzer(lang)
    assert analyzer is not None
    assert analyzer.language == lang


@pytest.mark.parametrize("lang,fixture", _NEW_LANGUAGES)
def test_analyzer_detects_findings(lang, fixture):
    """Each analyzer should detect findings in its fixture file."""
    analyzer = get_language_analyzer(lang)
    fixture_path = FIXTURES_DIR / fixture
    if not fixture_path.exists():
        pytest.skip(f"Fixture {fixture} not found")
    content = fixture_path.read_text(encoding="utf-8", errors="ignore")
    findings = analyzer.analyze(str(fixture_path), content)
    assert len(findings) > 0, f"{lang} analyzer found no findings in {fixture}"


@pytest.mark.parametrize("lang,fixture", _NEW_LANGUAGES)
def test_analyzer_empty_file(lang, fixture):
    """Analyzers should return empty list for empty files."""
    analyzer = get_language_analyzer(lang)
    findings = analyzer.analyze("empty.txt", "")
    assert findings == []


def test_all_14_languages_available():
    """All 14 languages should be available."""
    all_langs = [
        "python",
        "java",
        "javascript",
        "golang",
        "cpp",
        "csharp",
        "rust",
        "swift",
        "kotlin",
        "php",
        "ruby",
        "typescript",
        "scala",
        "dart",
    ]
    for lang in all_langs:
        assert get_language_analyzer(lang) is not None, f"Language {lang} not available"
