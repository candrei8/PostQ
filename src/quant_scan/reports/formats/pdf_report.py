"""PDF report generator — executive-ready PDF via HTML+CSS rendering."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from jinja2 import Template

from quant_scan.core.models import ScanResult
from quant_scan.reports.branding import BrandingConfig
from quant_scan.reports.i18n import t

logger = logging.getLogger(__name__)

_PDF_TEMPLATE = """<!DOCTYPE html>
<html lang="{{ lang }}">
<head>
<meta charset="utf-8">
<style>
@page {
    size: A4;
    margin: 2cm 2.5cm;
    @top-center { content: "{{ t_confidential }}"; font-size: 8pt; color: #999; }
    @bottom-left { content: "{{ t_generated_by }}"; font-size: 8pt; color: #999; }
    @bottom-right { content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color: #999; }
}
@page :first { margin-top: 0; @top-center { content: ""; } }

* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 10pt; color: #333; line-height: 1.5; }

.cover { height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center;
         background: linear-gradient(135deg, {{ primary_color }} 0%, {{ secondary_color }} 100%);
         color: white; text-align: center; page-break-after: always; padding: 3cm; }
.cover h1 { font-size: 28pt; margin-bottom: 0.5cm; font-weight: 700; }
.cover h2 { font-size: 16pt; margin-bottom: 1.5cm; font-weight: 300; opacity: 0.9; }
.cover .meta { font-size: 11pt; opacity: 0.8; margin-top: 2cm; }
.cover .meta p { margin: 0.2cm 0; }
.cover .score-big { font-size: 72pt; font-weight: 800; margin: 1cm 0; }
.cover .grade-badge { display: inline-block; padding: 0.3cm 1cm; border: 3px solid white;
                      border-radius: 0.5cm; font-size: 24pt; font-weight: 700; margin-top: 0.5cm; }

h2 { color: {{ primary_color }}; font-size: 16pt; margin: 1cm 0 0.5cm; border-bottom: 2px solid {{ primary_color }};
     padding-bottom: 0.2cm; page-break-after: avoid; }
h3 { color: {{ secondary_color }}; font-size: 12pt; margin: 0.6cm 0 0.3cm; page-break-after: avoid; }

.summary-grid { display: flex; flex-wrap: wrap; gap: 0.4cm; margin: 0.5cm 0; }
.summary-card { flex: 1 1 45%; background: #f8f9fa; border-left: 4px solid {{ primary_color }};
                padding: 0.4cm 0.6cm; border-radius: 0 4px 4px 0; }
.summary-card .label { font-size: 8pt; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }
.summary-card .value { font-size: 18pt; font-weight: 700; color: {{ secondary_color }}; }

table { width: 100%; border-collapse: collapse; margin: 0.4cm 0; font-size: 9pt; page-break-inside: auto; }
thead { background: {{ primary_color }}; color: white; }
th { padding: 6px 8px; text-align: left; font-weight: 600; }
td { padding: 5px 8px; border-bottom: 1px solid #e0e0e0; }
tr { page-break-inside: avoid; }
tbody tr:nth-child(even) { background: #f8f9fa; }

.badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 8pt;
         font-weight: 600; color: white; text-transform: uppercase; }
.badge-critical { background: #e74c3c; }
.badge-high { background: #e67e22; }
.badge-medium { background: #f39c12; color: #333; }
.badge-low { background: #3498db; }
.badge-info { background: #95a5a6; }
.badge-vulnerable { background: #e74c3c; }
.badge-weakened { background: #f39c12; color: #333; }
.badge-safe { background: #2ecc71; }

.chart-container { text-align: center; margin: 0.5cm 0; page-break-inside: avoid; }
.chart-container img { max-width: 80%; height: auto; }

.phase-box { background: #f0f4ff; border: 1px solid {{ primary_color }}; border-radius: 6px;
             padding: 0.5cm; margin: 0.4cm 0; page-break-inside: avoid; }
.phase-box h3 { margin-top: 0; color: {{ primary_color }}; border: none; }

.recommendation-box { background: #fff3cd; border-left: 4px solid #f39c12; padding: 0.4cm;
                       margin: 0.3cm 0; border-radius: 0 4px 4px 0; }

.appendix { font-size: 8pt; }
.appendix p { margin: 0.2cm 0; }

.page-break { page-break-before: always; }
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
    <h1>{{ t_title }}</h1>
    <h2>{{ t_subtitle }}</h2>
    {% if client_name %}<p style="font-size: 14pt; margin-top: 1cm;">
      {{ t_prepared_for }}: <strong>{{ client_name }}</strong>
    </p>{% endif %}
    <div class="score-big">{{ score }}</div>
    <div class="grade-badge">{{ grade }}</div>
    <div class="meta">
        <p>{{ t_date_label }}: {{ report_date }}</p>
        <p>{{ t_prepared_by }}: {{ prepared_by }}</p>
        <p>{{ t_generated_by }}</p>
    </div>
</div>

<!-- EXECUTIVE SUMMARY -->
<h2>{{ t_exec_title }}</h2>
<p>{{ t_exec_overview }}</p>

<div class="summary-grid">
    <div class="summary-card"><div class="label">{{ t_score_label }}</div><div class="value">{{ score }}/100</div></div>
    <div class="summary-card"><div class="label">{{ t_grade_label }}</div><div class="value">{{ grade }}</div></div>
    <div class="summary-card"><div class="label">{{ t_pqc_readiness }}</div>
      <div class="value">{{ pqc_readiness }}%</div></div>
    <div class="summary-card"><div class="label">{{ t_total_findings }}</div>
      <div class="value">{{ total_findings }}</div></div>
    <div class="summary-card"><div class="label">{{ t_files_scanned }}</div>
      <div class="value">{{ files_scanned }}</div></div>
    <div class="summary-card"><div class="label">{{ t_scan_duration }}</div>
      <div class="value">{{ duration }}s</div></div>
</div>

{% if severity_pie_b64 %}
<div class="chart-container">
    <img src="data:image/png;base64,{{ severity_pie_b64 }}" alt="Severity Distribution">
</div>
{% endif %}

{% if risk_bar_b64 %}
<div class="chart-container">
    <img src="data:image/png;base64,{{ risk_bar_b64 }}" alt="Quantum Risk Distribution">
</div>
{% endif %}

<!-- FINDINGS TABLE -->
<div class="page-break"></div>
<h2>{{ t_findings_title }}</h2>

{% if findings %}
<table>
<thead>
<tr><th>{{ t_severity }}</th><th>{{ t_algorithm }}</th>
  <th>{{ t_quantum_risk }}</th><th>{{ t_location }}</th>
  <th>{{ t_message }}</th></tr>
</thead>
<tbody>
{% for f in findings %}
<tr>
    <td><span class="badge badge-{{ f.severity }}">{{ f.severity_label }}</span></td>
    <td><strong>{{ f.algorithm_name }}</strong></td>
    <td><span class="badge badge-{{ f.quantum_risk }}">{{ f.quantum_risk_label }}</span></td>
    <td><code>{{ f.file_path }}:{{ f.line_number }}</code></td>
    <td>{{ f.message }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% else %}
<p>{{ t_no_findings }}</p>
{% endif %}

<!-- COMPLIANCE -->
{% if compliance_refs %}
<div class="page-break"></div>
<h2>{{ t_compliance_title }}</h2>
<table>
<thead><tr><th>{{ t_framework }}</th><th>{{ t_requirement }}</th><th>{{ t_status }}</th></tr></thead>
<tbody>
{% for ref in compliance_refs[:50] %}
<tr><td>{{ ref }}</td><td></td><td></td></tr>
{% endfor %}
</tbody>
</table>
{% endif %}

<!-- APPENDIX -->
<div class="page-break"></div>
<h2>{{ t_appendix_title }}</h2>
<div class="appendix">
    <h3>{{ t_methodology }}</h3>
    <p>{{ t_methodology_text }}</p>
    <h3>{{ t_limitations }}</h3>
    <p>{{ t_limitations_text }}</p>
    <h3>{{ t_glossary }}</h3>
    <p><strong>PQC:</strong> {{ t_pqc_def }}</p>
    <p><strong>HNDL:</strong> {{ t_hndl_def }}</p>
    <p><strong>QVSS:</strong> {{ t_qvss_def }}</p>
</div>

</body>
</html>"""


def render_pdf_html(
    result: ScanResult,
    branding: BrandingConfig | None = None,
) -> str:
    """Render the PDF report as HTML (for WeasyPrint conversion or standalone use).

    If WeasyPrint is not available, returns the HTML string which can
    be saved as an .html file and opened in a browser for printing to PDF.
    """
    branding = branding or BrandingConfig()
    lang = branding.language

    # Generate charts
    severity_pie_b64 = ""
    risk_bar_b64 = ""
    try:
        from quant_scan.reports.charts import generate_risk_bar, generate_severity_pie

        severity_pie_b64 = generate_severity_pie(result)
        risk_bar_b64 = generate_risk_bar(result)
    except Exception:
        logger.debug("Chart generation failed, proceeding without charts")

    # Prepare findings data for template
    severity_labels = {
        "critical": t("severity_labels.critical", lang),
        "high": t("severity_labels.high", lang),
        "medium": t("severity_labels.medium", lang),
        "low": t("severity_labels.low", lang),
        "info": t("severity_labels.info", lang),
    }
    risk_labels = {
        "vulnerable": t("quantum_risk_labels.vulnerable", lang),
        "weakened": t("quantum_risk_labels.weakened", lang),
        "safe": t("quantum_risk_labels.safe", lang),
        "unknown": t("quantum_risk_labels.unknown", lang),
    }

    findings_data = []
    compliance_all: list[str] = []
    for f in result.findings:
        findings_data.append(
            {
                "severity": f.severity.value,
                "severity_label": severity_labels.get(f.severity.value, f.severity.value),
                "algorithm_name": f.algorithm.name,
                "quantum_risk": f.quantum_risk.value,
                "quantum_risk_label": risk_labels.get(f.quantum_risk.value, f.quantum_risk.value),
                "file_path": f.location.file_path.split("/")[-1].split("\\")[-1],
                "line_number": f.location.line_number,
                "message": f.message,
                "recommendation": f.recommendation,
            }
        )
        compliance_all.extend(f.compliance_refs)

    # Deduplicate compliance refs
    unique_refs = sorted(set(compliance_all))

    now = datetime.now(timezone.utc)

    template = Template(_PDF_TEMPLATE)
    html = template.render(
        lang=lang,
        primary_color=branding.branding_color,
        secondary_color=branding.secondary_color,
        accent_color=branding.accent_color,
        client_name=branding.client_name,
        prepared_by=branding.prepared_by,
        report_date=now.strftime("%Y-%m-%d"),
        score=result.summary.score,
        grade=result.summary.grade,
        pqc_readiness=result.summary.pqc_readiness_pct,
        total_findings=result.summary.total_findings,
        files_scanned=result.summary.files_scanned,
        duration=result.duration_seconds,
        severity_pie_b64=severity_pie_b64,
        risk_bar_b64=risk_bar_b64,
        findings=findings_data,
        compliance_refs=unique_refs,
        # i18n strings
        t_title=branding.report_title or t("report.title", lang),
        t_subtitle=t("report.subtitle", lang),
        t_confidential=t("report.confidential", lang),
        t_generated_by=t("report.generated_by", lang),
        t_date_label=t("report.date_label", lang),
        t_prepared_for=t("report.prepared_for", lang),
        t_prepared_by=t("report.prepared_by", lang),
        t_exec_title=t("executive_summary.title", lang),
        t_exec_overview=t("executive_summary.overview", lang),
        t_score_label=t("executive_summary.score_label", lang),
        t_grade_label=t("executive_summary.grade_label", lang),
        t_pqc_readiness=t("executive_summary.pqc_readiness", lang),
        t_total_findings=t("executive_summary.total_findings", lang),
        t_files_scanned=t("executive_summary.files_scanned", lang),
        t_scan_duration=t("executive_summary.scan_duration", lang),
        t_findings_title=t("findings.title", lang),
        t_severity=t("findings.severity", lang),
        t_algorithm=t("findings.algorithm", lang),
        t_quantum_risk=t("findings.quantum_risk", lang),
        t_location=t("findings.location", lang),
        t_message=t("findings.message", lang),
        t_no_findings=t("findings.no_findings", lang),
        t_compliance_title=t("compliance.title", lang),
        t_framework=t("compliance.framework", lang),
        t_requirement=t("compliance.requirement", lang),
        t_status=t("compliance.status", lang),
        t_appendix_title=t("appendix.title", lang),
        t_methodology=t("appendix.methodology", lang),
        t_methodology_text=t("appendix.methodology_text", lang),
        t_limitations=t("appendix.limitations", lang),
        t_limitations_text=t("appendix.limitations_text", lang),
        t_glossary=t("appendix.glossary", lang),
        t_pqc_def=t("appendix.pqc_def", lang),
        t_hndl_def=t("appendix.hndl_def", lang),
        t_qvss_def=t("appendix.qvss_def", lang),
    )

    return html


def render_pdf(
    result: ScanResult,
    branding: BrandingConfig | None = None,
    output_path: str | None = None,
) -> str:
    """Render scan results as a PDF report.

    Requires WeasyPrint. If not available, returns the HTML string
    which can be saved as .html and printed from a browser.
    """
    html = render_pdf_html(result, branding)

    if output_path:
        try:
            from weasyprint import HTML

            HTML(string=html).write_pdf(output_path)
            logger.info("PDF written to %s", output_path)
            return f"PDF report written to {output_path}"
        except ImportError:
            logger.warning("WeasyPrint not available, saving as HTML instead")
            html_path = output_path.replace(".pdf", ".html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)
            return f"HTML report written to {html_path} (install weasyprint for PDF)"

    return html
