"""Typer CLI application — entry point for quant-scan."""

from __future__ import annotations

import json
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
    quality_gate: bool = False,
    min_score: float = 70.0,
    max_critical: int = 0,
    max_high: int = 5,
) -> None:
    """Shared scan logic for all commands."""
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

    # Quality gate evaluation
    if quality_gate:
        from quant_scan.cicd.quality_gate import QualityGate

        gate = QualityGate(
            min_score=min_score,
            max_critical=max_critical,
            max_high=max_high,
        )
        gate_result = gate.evaluate(result)
        if not gate_result.passed:
            typer.echo("\nQuality Gate: FAILED", err=True)
            for reason in gate_result.reasons:
                typer.echo(f"  - {reason}", err=True)
            raise typer.Exit(code=2)
        typer.echo("\nQuality Gate: PASSED", err=True)

    raise typer.Exit(code=1 if result.summary.total_findings > 0 else 0)


# ── Common option definitions ──────────────────────────────────────────

_target_arg = typer.Argument(help="Files or directories to scan")
_format_opt = typer.Option("--format", "-f", help="Output format: console, json, html, sarif")
_output_opt = typer.Option("--output", "-o", help="Write report to file")
_severity_opt = typer.Option("--severity", "-s", help="Minimum severity: critical, high, medium, low, info")
_exclude_opt = typer.Option("--exclude", "-e", help="Exclude patterns (gitignore-style)")
_no_color_opt = typer.Option("--no-color", help="Disable colored output")
_quality_gate_opt = typer.Option("--quality-gate", help="Enable quality gate evaluation")
_min_score_opt = typer.Option("--min-score", help="Quality gate: minimum score (default 70)")
_max_critical_opt = typer.Option("--max-critical", help="Quality gate: max critical findings (default 0)")
_max_high_opt = typer.Option("--max-high", help="Quality gate: max high findings (default 5)")


@app.command()
def scan(
    target: Annotated[list[Path], _target_arg],
    format: Annotated[str, _format_opt] = "console",
    output: Annotated[Optional[str], _output_opt] = None,
    severity: Annotated[str, _severity_opt] = "info",
    exclude: Annotated[Optional[list[str]], _exclude_opt] = None,
    no_color: Annotated[bool, _no_color_opt] = False,
    quality_gate: Annotated[bool, _quality_gate_opt] = False,
    min_score: Annotated[float, _min_score_opt] = 70.0,
    max_critical: Annotated[int, _max_critical_opt] = 0,
    max_high: Annotated[int, _max_high_opt] = 5,
) -> None:
    """Run a full scan (source code, certificates, configs, dependencies, secrets)."""
    _run_scan(
        target, format, output, severity, exclude or [], no_color,
        quality_gate=quality_gate, min_score=min_score,
        max_critical=max_critical, max_high=max_high,
    )


@app.command()
def source(
    target: Annotated[list[Path], _target_arg],
    format: Annotated[str, _format_opt] = "console",
    output: Annotated[Optional[str], _output_opt] = None,
    severity: Annotated[str, _severity_opt] = "info",
    languages: Annotated[
        Optional[list[str]],
        typer.Option(
            "--languages", "-l",
            help="Languages: python, java, javascript, golang, cpp, csharp, rust, swift, kotlin, php, ruby, typescript, scala, dart",
        ),
    ] = None,
    exclude: Annotated[Optional[list[str]], _exclude_opt] = None,
    no_color: Annotated[bool, _no_color_opt] = False,
) -> None:
    """Scan source code only."""
    _run_scan(
        target, format, output, severity, exclude or [], no_color,
        scanner_names=["source"],
        languages=languages or [],
    )


@app.command()
def certificate(
    target: Annotated[list[Path], _target_arg],
    format: Annotated[str, _format_opt] = "console",
    output: Annotated[Optional[str], _output_opt] = None,
    severity: Annotated[str, _severity_opt] = "info",
    exclude: Annotated[Optional[list[str]], _exclude_opt] = None,
    no_color: Annotated[bool, _no_color_opt] = False,
) -> None:
    """Scan certificates only (.pem, .crt, .cer, .der files)."""
    _run_scan(
        target, format, output, severity, exclude or [], no_color,
        scanner_names=["certificate"],
    )


@app.command()
def config(
    target: Annotated[list[Path], _target_arg],
    format: Annotated[str, _format_opt] = "console",
    output: Annotated[Optional[str], _output_opt] = None,
    severity: Annotated[str, _severity_opt] = "info",
    exclude: Annotated[Optional[list[str]], _exclude_opt] = None,
    no_color: Annotated[bool, _no_color_opt] = False,
) -> None:
    """Scan configuration files only (SSH, nginx, Apache, HAProxy)."""
    _run_scan(
        target, format, output, severity, exclude or [], no_color,
        scanner_names=["config"],
    )


@app.command()
def dependencies(
    target: Annotated[list[Path], _target_arg],
    format: Annotated[str, _format_opt] = "console",
    output: Annotated[Optional[str], _output_opt] = None,
    severity: Annotated[str, _severity_opt] = "info",
    exclude: Annotated[Optional[list[str]], _exclude_opt] = None,
    no_color: Annotated[bool, _no_color_opt] = False,
) -> None:
    """Scan dependency files only (requirements.txt, package.json, pom.xml, go.mod)."""
    _run_scan(
        target, format, output, severity, exclude or [], no_color,
        scanner_names=["dependency"],
    )


@app.command()
def secrets(
    target: Annotated[list[Path], _target_arg],
    format: Annotated[str, _format_opt] = "console",
    output: Annotated[Optional[str], _output_opt] = None,
    severity: Annotated[str, _severity_opt] = "info",
    exclude: Annotated[Optional[list[str]], _exclude_opt] = None,
    no_color: Annotated[bool, _no_color_opt] = False,
) -> None:
    """Scan for hardcoded secrets, private keys, and API credentials."""
    _run_scan(
        target, format, output, severity, exclude or [], no_color,
        scanner_names=["secrets"],
    )


@app.command()
def migrate(
    target: Annotated[list[Path], _target_arg],
    organization: Annotated[
        str, typer.Option("--organization", "--org", help="Organization name for the report")
    ] = "",
    hourly_rate: Annotated[
        float, typer.Option("--hourly-rate", help="Hourly rate in EUR for cost estimation")
    ] = 150.0,
    format: Annotated[str, _format_opt] = "console",
    output: Annotated[Optional[str], _output_opt] = None,
    severity: Annotated[str, _severity_opt] = "info",
    exclude: Annotated[Optional[list[str]], _exclude_opt] = None,
    no_color: Annotated[bool, _no_color_opt] = False,
) -> None:
    """Generate a PQC migration plan from scan results."""
    ctx = ScanContext(
        targets=target,
        exclude_patterns=exclude or [],
        min_severity=Severity(severity),
        output_format=format,
        output_file=output,
        no_color=no_color,
    )

    engine = ScanEngine()
    result = engine.run(ctx)

    from quant_scan.migration.planner import generate_migration_plan

    plan = generate_migration_plan(result, organization=organization, hourly_rate=hourly_rate)

    # Output the migration plan
    plan_json = plan.model_dump_json(indent=2)
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(plan_json)
        typer.echo(f"Migration plan written to {output}")
    else:
        typer.echo(plan_json)

    raise typer.Exit(code=0)


@app.command()
def compare(
    scan_a: Annotated[Path, typer.Argument(help="Path to first (baseline) scan result JSON")],
    scan_b: Annotated[Path, typer.Argument(help="Path to second (current) scan result JSON")],
    format: Annotated[str, _format_opt] = "console",
    output: Annotated[Optional[str], _output_opt] = None,
) -> None:
    """Compare two scan results to track migration progress."""
    from quant_scan.comparison.differ import compare_scans
    from quant_scan.core.models import ScanResult

    result_a = ScanResult.model_validate_json(scan_a.read_text(encoding="utf-8"))
    result_b = ScanResult.model_validate_json(scan_b.read_text(encoding="utf-8"))

    comparison = compare_scans(result_a, result_b)

    comparison_json = comparison.model_dump_json(indent=2)
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(comparison_json)
        typer.echo(f"Comparison written to {output}")
    else:
        typer.echo(comparison_json)

    raise typer.Exit(code=0)


@app.command()
def server(
    host: Annotated[str, typer.Option("--host", help="Bind host")] = "0.0.0.0",
    port: Annotated[int, typer.Option("--port", "-p", help="Bind port")] = 8000,
    reload: Annotated[bool, typer.Option("--reload", help="Auto-reload on changes")] = False,
) -> None:
    """Start the quant-scan API server (requires fastapi and uvicorn)."""
    try:
        import uvicorn
        from quant_scan.server.app import create_app
    except ImportError:
        typer.echo("Error: Install server dependencies: pip install quant-scan[server]", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Starting quant-scan API server on {host}:{port}")
    app = create_app()
    uvicorn.run(app, host=host, port=port, reload=reload)
