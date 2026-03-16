"""Rich console output for scan results."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.core.models import Finding, ScanResult
from quant_scan.reports.scoring import format_readiness_display, format_score_display

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_RISK_COLORS = {
    QuantumRisk.VULNERABLE: "bold red",
    QuantumRisk.WEAKENED: "yellow",
    QuantumRisk.SAFE: "green",
    QuantumRisk.UNKNOWN: "dim",
}


def render_console(result: ScanResult) -> str:
    """Render scan results as a Rich-formatted console string."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=120)

    # Header
    console.print()
    console.print(
        Panel.fit(
            "[bold]Quant-Scan[/bold] — Post-Quantum Cryptography Scanner",
            border_style="blue",
        )
    )

    s = result.summary

    # Summary panel
    grade_color = {
        "A": "green",
        "B": "cyan",
        "C": "yellow",
        "D": "red",
        "F": "bold red",
    }.get(s.grade, "white")

    summary_text = Text.assemble(
        ("Score: ", "bold"),
        (format_score_display(s), grade_color),
        ("  |  ", "dim"),
        ("PQC Readiness: ", "bold"),
        (format_readiness_display(s), "cyan"),
        ("  |  ", "dim"),
        ("Findings: ", "bold"),
        (str(s.total_findings), "white"),
        ("  |  ", "dim"),
        ("Files: ", "bold"),
        (str(s.files_scanned), "white"),
    )
    console.print(Panel(summary_text, title="Summary", border_style="blue"))

    if not result.findings:
        console.print("[green]No quantum-vulnerable cryptography detected.[/green]")
        console.print()
        return buf.getvalue()

    # Severity breakdown
    if s.by_severity:
        sev_parts = []
        for sev_name in ["critical", "high", "medium", "low", "info"]:
            count = s.by_severity.get(sev_name, 0)
            if count:
                color = _SEVERITY_COLORS.get(Severity(sev_name), "white")
                sev_parts.append(f"[{color}]{sev_name.upper()}: {count}[/{color}]")
        if sev_parts:
            console.print("  " + "  ".join(sev_parts))
            console.print()

    # Findings table
    table = Table(
        title="Findings",
        show_lines=True,
        expand=True,
        title_style="bold",
    )
    table.add_column("Sev", width=8, justify="center")
    table.add_column("Q-Risk", width=11, justify="center")
    table.add_column("Algorithm", width=14)
    table.add_column("Location", width=30, no_wrap=True)
    table.add_column("Message", ratio=1)

    for f in _sort_findings(result.findings):
        sev_style = _SEVERITY_COLORS.get(f.severity, "white")
        risk_style = _RISK_COLORS.get(f.quantum_risk, "white")

        loc = f"{f.location.file_path}:{f.location.line_number}"
        if len(loc) > 30:
            loc = "..." + loc[-27:]

        table.add_row(
            Text(f.severity.value.upper(), style=sev_style),
            Text(f.quantum_risk.value.upper(), style=risk_style),
            f.algorithm.name,
            loc,
            f.message,
        )

    console.print(table)

    # Recommendations
    recs = _unique_recommendations(result.findings)
    if recs:
        console.print()
        rec_table = Table(title="Recommendations", show_lines=True, expand=True, title_style="bold")
        rec_table.add_column("Algorithm", width=16)
        rec_table.add_column("Action", ratio=1)
        rec_table.add_column("PQC Replacement", width=30)
        for algo_name, rec_text, replacements in recs:
            rec_table.add_row(algo_name, rec_text, replacements)
        console.print(rec_table)

    console.print()
    console.print(
        f"[dim]Scan completed in {result.duration_seconds:.2f}s[/dim]"
    )
    console.print()
    return buf.getvalue()


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    return sorted(findings, key=lambda f: order.get(f.severity, 5))


def _unique_recommendations(
    findings: list[Finding],
) -> list[tuple[str, str, str]]:
    seen: set[str] = set()
    recs: list[tuple[str, str, str]] = []
    for f in _sort_findings(findings):
        if f.algorithm.name in seen or not f.recommendation:
            continue
        seen.add(f.algorithm.name)
        replacements = ", ".join(f.algorithm.pqc_replacements) if f.algorithm.pqc_replacements else "—"
        recs.append((f.algorithm.name, f.recommendation, replacements))
    return recs
