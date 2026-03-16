"""Report generator — routes to the right format."""

from __future__ import annotations

from quant_scan.core.models import ScanResult


def generate_report(result: ScanResult, fmt: str, output_file: str | None = None) -> str:
    """Generate a report in the requested format and optionally write to file.

    Supported formats: console, json, html, sarif, cbom, pdf.
    """
    if fmt == "pdf":
        from quant_scan.reports.formats.pdf_report import render_pdf_html

        text = render_pdf_html(result)
    elif fmt == "json":
        from quant_scan.reports.formats.json_report import render_json

        text = render_json(result)
    elif fmt == "html":
        from quant_scan.reports.formats.html_report import render_html

        text = render_html(result)
    elif fmt == "sarif":
        from quant_scan.reports.formats.sarif_report import render_sarif

        text = render_sarif(result)
    elif fmt == "cbom":
        from quant_scan.cbom.formats.cyclonedx import render_cyclonedx
        from quant_scan.cbom.generator import generate_cbom

        cbom = generate_cbom(result)
        text = render_cyclonedx(cbom)
    else:
        from quant_scan.reports.formats.console import render_console

        text = render_console(result)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(text)

    return text
