"""Typer CLI application — entry point for quant-scan."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

from quant_scan import __version__
from quant_scan.core.context import ScanContext
from quant_scan.core.engine import ScanEngine
from quant_scan.core.enums import Severity
from quant_scan.reports.generator import generate_report

app = typer.Typer(
    name="quant-scan",
    help="Post-Quantum Cryptography Scanner — Detect quantum-vulnerable algorithms",
    no_args_is_help=True,
    add_completion=False,
)


def version_callback(value: bool) -> None:
    if value:
        print(f"quant-scan {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", "-v", callback=version_callback, is_eager=True, help="Show version"),
    ] = None,
) -> None:
    """Quant-Scan — Post-Quantum Cryptography Scanner."""


def _run_scan(
    targets: list[Path],
    fmt: str,
    output: str | None,
    severity: str,
    exclude: list[str],
    no_color: bool,
    scanner_names: list[str] | None = None,
    languages: list[str] | None = None,
) -> None:
    """Shared scan logic for scan/source commands."""
    ctx = ScanContext(
        targets=targets,
        exclude_patterns=exclude,
        min_severity=Severity(severity),
        output_format=fmt,
        output_file=output,
        languages=languages or [],
        no_color=no_color,
    )

    engine = ScanEngine()
    result = engine.run(ctx, scanner_names=scanner_names)

    report = generate_report(result, fmt, output)
    if not output:
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass
        try:
            sys.stdout.write(report)
            sys.stdout.write("\n")
            sys.stdout.flush()
        except UnicodeEncodeError:
            sys.stdout.buffer.write(report.encode("utf-8", errors="replace"))
            sys.stdout.buffer.write(b"\n")
            sys.stdout.buffer.flush()
    else:
        typer.echo(f"Report written to {output}")

    raise typer.Exit(code=1 if result.summary.total_findings > 0 else 0)


@app.command()
def scan(
    target: Annotated[
        list[Path],
        typer.Argument(help="Files or directories to scan"),
    ],
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: console, json"),
    ] = "console",
    output: Annotated[
        Optional[str],
        typer.Option("--output", "-o", help="Write report to file"),
    ] = None,
    severity: Annotated[
        str,
        typer.Option("--severity", "-s", help="Minimum severity: critical, high, medium, low, info"),
    ] = "info",
    exclude: Annotated[
        Optional[list[str]],
        typer.Option("--exclude", "-e", help="Exclude patterns (gitignore-style)"),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Run a full scan (source code, certificates, configs, dependencies)."""
    _run_scan(target, format, output, severity, exclude or [], no_color)


@app.command()
def source(
    target: Annotated[
        list[Path],
        typer.Argument(help="Files or directories to scan"),
    ],
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: console, json"),
    ] = "console",
    output: Annotated[
        Optional[str],
        typer.Option("--output", "-o", help="Write report to file"),
    ] = None,
    severity: Annotated[
        str,
        typer.Option("--severity", "-s", help="Minimum severity: critical, high, medium, low, info"),
    ] = "info",
    languages: Annotated[
        Optional[list[str]],
        typer.Option("--languages", "-l", help="Languages to scan (e.g. python, java)"),
    ] = None,
    exclude: Annotated[
        Optional[list[str]],
        typer.Option("--exclude", "-e", help="Exclude patterns"),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Scan source code only."""
    _run_scan(
        target, format, output, severity, exclude or [], no_color,
        scanner_names=["source"],
        languages=languages or [],
    )
