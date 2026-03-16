"""Report generator — routes to the right format."""

from __future__ import annotations

from quant_scan.core.models import ScanResult


def generate_report(result: ScanResult, fmt: str, output_file: str | None = None) -> str:
    """Generate a report in the requested format and optionally write to file."""
    if fmt == "json":
        from quant_scan.reports.formats.json_report import render_json

        text = render_json(result)
    else:
        from quant_scan.reports.formats.console import render_console

        text = render_console(result)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(text)

    return text
