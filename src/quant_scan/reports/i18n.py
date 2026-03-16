"""Internationalization — multi-language support for reports."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "i18n_data"
_cache: dict[str, dict[str, str]] = {}


def _load_strings(language: str) -> dict[str, str]:
    """Load string table for a language."""
    if language in _cache:
        return _cache[language]

    path = _DATA_DIR / f"{language}.yml"
    if not path.exists():
        logger.warning("Language file %s not found, falling back to en", path)
        path = _DATA_DIR / "en.yml"

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        strings = data if isinstance(data, dict) else {}
        _cache[language] = strings
        return strings
    except Exception:
        logger.exception("Failed to load language file %s", path)
        _cache[language] = {}
        return {}


def t(key: str, language: str = "en", **kwargs: str) -> str:
    """Translate a key to the given language.

    Parameters
    ----------
    key:
        Dot-separated key (e.g., "report.title").
    language:
        Language code ("en", "es").
    **kwargs:
        Format arguments for string interpolation.

    Returns
    -------
    str:
        Translated string, or the key itself if not found.
    """
    strings = _load_strings(language)

    # Support dot-separated keys for nested access
    parts = key.split(".")
    value = strings
    for part in parts:
        if isinstance(value, dict):
            value = value.get(part)
        else:
            value = None
            break

    if value is None or not isinstance(value, str):
        # Fallback to English
        if language != "en":
            return t(key, "en", **kwargs)
        return key

    if kwargs:
        try:
            return value.format(**kwargs)
        except (KeyError, IndexError):
            return value

    return value


def available_languages() -> list[str]:
    """Return list of available language codes."""
    return [p.stem for p in _DATA_DIR.glob("*.yml")]
