"""Shared pytest fixtures."""

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def vulnerable_python_path() -> Path:
    return FIXTURES_DIR / "vulnerable_python.py"


@pytest.fixture
def safe_python_path() -> Path:
    return FIXTURES_DIR / "safe_python.py"
