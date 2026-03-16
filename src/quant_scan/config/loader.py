"""Configuration loader — reads from files and CLI overrides."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from quant_scan.config.schema import ScanConfig

logger = logging.getLogger(__name__)

_CONFIG_FILENAMES = [
    ".quant-scan.toml",
    ".quant-scan.yml",
    ".quant-scan.yaml",
]


def _load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML config file."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML config file."""
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def find_config_file(search_dir: Path | None = None) -> Path | None:
    """Search for a config file starting from *search_dir* up to root."""
    start = search_dir or Path.cwd()
    current = start.resolve()

    while True:
        for name in _CONFIG_FILENAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate

        # Also check pyproject.toml for [tool.quant-scan]
        pyproject = current / "pyproject.toml"
        if pyproject.is_file():
            try:
                data = _load_toml(pyproject)
                if "tool" in data and "quant-scan" in data["tool"]:
                    return pyproject
            except Exception:
                pass

        parent = current.parent
        if parent == current:
            break
        current = parent

    return None


def load_config(
    config_path: Path | None = None,
    search_dir: Path | None = None,
) -> ScanConfig:
    """Load configuration from file, falling back to defaults.

    Priority: explicit path > auto-discovered file > defaults.
    """
    path = config_path or find_config_file(search_dir)
    if path is None:
        return ScanConfig()

    logger.info("Loading configuration from %s", path)

    try:
        if path.name == "pyproject.toml":
            raw = _load_toml(path)
            data = raw.get("tool", {}).get("quant-scan", {})
        elif path.suffix == ".toml":
            data = _load_toml(path)
        else:
            data = _load_yaml(path)

        return ScanConfig.model_validate(data)
    except Exception:
        logger.exception("Failed to load config from %s, using defaults", path)
        return ScanConfig()
