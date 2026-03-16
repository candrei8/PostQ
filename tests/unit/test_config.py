"""Tests for configuration system."""
from __future__ import annotations

from quant_scan.config.schema import ScanConfig
from quant_scan.config.profiles import get_profile, PROFILES


def test_default_config():
    cfg = ScanConfig()
    assert cfg.scan.min_severity == "info"
    assert cfg.performance.max_workers == 4


def test_quick_profile():
    p = get_profile("quick")
    assert p is not None
    assert p.scan.min_severity == "high"
    assert "source" in p.scanners.enabled


def test_paranoid_profile():
    p = get_profile("paranoid")
    assert p is not None
    assert len(p.scanners.enabled) >= 6


def test_all_profiles_exist():
    for name in ["quick", "standard", "deep", "paranoid"]:
        assert get_profile(name) is not None


def test_unknown_profile():
    assert get_profile("nonexistent") is None
