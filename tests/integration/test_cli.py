"""Integration tests — CLI end-to-end."""

import json
from pathlib import Path

from typer.testing import CliRunner

from quant_scan.cli.app import app

runner = CliRunner()

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def test_scan_command_vulnerable():
    result = runner.invoke(app, ["scan", str(FIXTURES_DIR / "vulnerable_python.py")])
    assert result.exit_code == 1  # findings exist → exit 1
    assert "Quant-Scan" in result.output
    assert "RSA" in result.output


def test_scan_command_safe():
    result = runner.invoke(app, ["scan", str(FIXTURES_DIR / "safe_python.py")])
    assert result.exit_code == 0
    assert "No quantum-vulnerable" in result.output


def test_source_command():
    result = runner.invoke(app, ["source", str(FIXTURES_DIR / "vulnerable_python.py")])
    assert result.exit_code == 1
    assert "MD5" in result.output or "RSA" in result.output


def test_json_format():
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES_DIR / "vulnerable_python.py"), "--format", "json"],
    )
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert "findings" in data
    assert len(data["findings"]) > 0


def test_severity_filter():
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "vulnerable_python.py"),
            "--format",
            "json",
            "--severity",
            "critical",
        ],
    )
    data = json.loads(result.output)
    for f in data["findings"]:
        assert f["severity"] == "critical"


def test_scan_directory():
    result = runner.invoke(app, ["scan", str(FIXTURES_DIR)])
    # Should find something in vulnerable_python.py
    assert "RSA" in result.output or "MD5" in result.output


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "quant-scan" in result.output
