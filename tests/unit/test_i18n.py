"""Tests for internationalization."""

from __future__ import annotations

from quant_scan.reports.i18n import available_languages, t


def test_english_strings():
    assert t("report.title", "en") != "report.title"
    assert "Post-Quantum" in t("report.title", "en")


def test_spanish_strings():
    assert t("report.title", "es") != "report.title"
    assert "Post-Cuanticas" in t("report.title", "es")


def test_nested_keys():
    assert t("executive_summary.title", "en") == "Executive Summary"
    assert t("executive_summary.title", "es") == "Resumen Ejecutivo"


def test_missing_key_returns_key():
    assert t("nonexistent.key", "en") == "nonexistent.key"


def test_fallback_to_english():
    result = t("report.title", "fr")  # French not available
    assert "Post-Quantum" in result


def test_available_languages():
    langs = available_languages()
    assert "en" in langs
    assert "es" in langs
