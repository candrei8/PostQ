"""Self-contained HTML report generator using Jinja2."""

from __future__ import annotations

from jinja2 import Template

from quant_scan.core.enums import Severity
from quant_scan.core.models import Finding, ScanResult

# ---------------------------------------------------------------------------
# Jinja2 HTML template (fully self-contained, inline CSS, no external deps)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = Template(
    r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Quant-Scan Report</title>
<style>
/* ---------- Reset & base ---------- */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f1117;--surface:#181b23;--surface2:#1e2230;--border:#2a2e3b;
  --text:#e4e6eb;--text-dim:#8b8fa3;--accent:#6c7ee1;
  --critical:#e74c3c;--high:#e67e22;--medium:#f1c40f;--low:#3498db;--info:#7f8c8d;
  --safe:#2ecc71;--vulnerable:#e74c3c;--weakened:#f39c12;
}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;
  line-height:1.6;padding:0}
a{color:var(--accent);text-decoration:none}

/* ---------- Layout ---------- */
.container{max-width:1200px;margin:0 auto;padding:24px 32px 48px}
header{text-align:center;padding:40px 0 32px;border-bottom:1px solid var(--border)}
header h1{font-size:2rem;font-weight:700;letter-spacing:-.5px}
header .meta{color:var(--text-dim);font-size:.85rem;margin-top:8px}
section{margin-top:40px}
section h2{font-size:1.25rem;font-weight:600;margin-bottom:16px;
  padding-bottom:8px;border-bottom:1px solid var(--border)}
footer{text-align:center;color:var(--text-dim);font-size:.8rem;
  margin-top:56px;padding-top:24px;border-top:1px solid var(--border)}

/* ---------- Executive summary cards ---------- */
.summary-grid{display:grid;
  grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;text-align:center}
.card .label{font-size:.75rem;text-transform:uppercase;
  letter-spacing:1px;color:var(--text-dim);margin-bottom:6px}
.card .value{font-size:1.75rem;font-weight:700}

/* ---------- Score gauge ---------- */
.gauge-wrap{display:flex;justify-content:center;align-items:center;margin-bottom:24px}
.gauge{position:relative;width:160px;height:80px;overflow:hidden}
.gauge::before{content:'';display:block;width:160px;height:160px;
  border-radius:50%;border:14px solid var(--surface2);
  border-bottom-color:transparent;border-left-color:transparent;
  transform:rotate(225deg)}
.gauge .fill{position:absolute;top:0;left:0;width:160px;height:160px;
  border-radius:50%;border:14px solid transparent;
  border-bottom-color:transparent;border-left-color:transparent;
  transform:rotate(225deg)}
.gauge .score-text{position:absolute;bottom:4px;left:50%;
  transform:translateX(-50%);font-size:1.6rem;font-weight:700}
.gauge .grade-text{position:absolute;bottom:-18px;left:50%;
  transform:translateX(-50%);font-size:.85rem;color:var(--text-dim)}

/* Simpler CSS-only score bar */
.score-bar-wrap{width:100%;max-width:400px;margin:0 auto 8px}
.score-bar-bg{height:12px;background:var(--surface2);border-radius:6px;overflow:hidden}
.score-bar-fill{height:100%;border-radius:6px;transition:width .5s}

/* ---------- Risk distribution bars ---------- */
.bar-group{margin-bottom:20px}
.bar-group h3{font-size:.9rem;font-weight:600;margin-bottom:10px;color:var(--text-dim)}
.bar-row{display:flex;align-items:center;margin-bottom:6px}
.bar-label{width:100px;font-size:.8rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text-dim)}
.bar-track{flex:1;height:22px;background:var(--surface2);border-radius:4px;overflow:hidden;position:relative}
.bar-fill{height:100%;border-radius:4px;display:flex;align-items:center;
  padding-left:8px;font-size:.75rem;font-weight:600;color:#fff;
  min-width:fit-content;transition:width .4s}
.bar-count{margin-left:8px;font-size:.8rem;color:var(--text-dim)}

/* ---------- Findings table ---------- */
.findings-table{width:100%;border-collapse:collapse;font-size:.85rem}
.findings-table th{background:var(--surface);text-align:left;
  padding:10px 12px;font-weight:600;font-size:.75rem;
  text-transform:uppercase;letter-spacing:.5px;color:var(--text-dim);
  border-bottom:2px solid var(--border);position:sticky;top:0}
.findings-table td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}
.findings-table tr:hover td{background:var(--surface2)}
.badge{display:inline-block;padding:2px 10px;border-radius:4px;
  font-size:.75rem;font-weight:600;text-transform:uppercase;
  letter-spacing:.3px}
.badge-critical{background:rgba(231,76,60,.18);color:var(--critical)}
.badge-high{background:rgba(230,126,34,.18);color:var(--high)}
.badge-medium{background:rgba(241,196,15,.15);color:var(--medium)}
.badge-low{background:rgba(52,152,219,.18);color:var(--low)}
.badge-info{background:rgba(127,140,141,.18);color:var(--info)}
.badge-vulnerable{background:rgba(231,76,60,.18);color:var(--vulnerable)}
.badge-weakened{background:rgba(243,156,18,.15);color:var(--weakened)}
.badge-safe{background:rgba(46,204,113,.15);color:var(--safe)}
.badge-unknown{background:rgba(127,140,141,.18);color:var(--info)}
.loc{font-family:'Cascadia Code','Fira Code',monospace;font-size:.8rem;color:var(--accent);word-break:break-all}

/* ---------- Recommendations ---------- */
.rec-list{list-style:none;padding:0}
.rec-list li{background:var(--surface);border:1px solid var(--border);
  border-radius:8px;padding:14px 18px;margin-bottom:10px}
.rec-list .algo{font-weight:600;color:var(--accent)}
.rec-list .action{margin-top:4px;color:var(--text)}
.rec-list .pqc{margin-top:4px;font-size:.85rem;color:var(--safe)}

/* ---------- Compliance ---------- */
.compliance-table{width:100%;border-collapse:collapse;font-size:.85rem}
.compliance-table th{background:var(--surface);text-align:left;
  padding:10px 12px;font-weight:600;font-size:.75rem;
  text-transform:uppercase;letter-spacing:.5px;color:var(--text-dim);
  border-bottom:2px solid var(--border)}
.compliance-table td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}
.compliance-table tr:hover td{background:var(--surface2)}
.status-non_compliant{color:var(--critical);font-weight:600}
.status-action_required{color:var(--medium);font-weight:600}
.status-compliant{color:var(--safe);font-weight:600}

/* ---------- Responsive ---------- */
@media(max-width:768px){
  .container{padding:16px}
  .summary-grid{grid-template-columns:1fr 1fr}
  .findings-table{font-size:.78rem}
  .findings-table th,.findings-table td{padding:8px 6px}
}
</style>
</head>
<body>
<div class="container">

<!-- ============ HEADER ============ -->
<header>
  <h1>Quant-Scan Report</h1>
  <div class="meta">
    Generated on {{ timestamp }}&nbsp;&nbsp;|&nbsp;&nbsp;Scanner v{{ version }}
  </div>
</header>

<!-- ============ EXECUTIVE SUMMARY ============ -->
<section>
  <h2>Executive Summary</h2>

  <div class="score-bar-wrap" style="text-align:center;margin-bottom:24px">
    <div style="font-size:2.2rem;font-weight:700;color:{{ score_color }}">
      {{ "%.0f"|format(score) }}<span style="font-size:1rem;color:var(--text-dim)">/100</span>
    </div>
    <div style="font-size:1rem;margin-bottom:8px">
      Grade&nbsp;<span style="font-size:1.4rem;font-weight:700;color:{{ score_color }}">{{ grade }}</span>
    </div>
    <div class="score-bar-bg">
      <div class="score-bar-fill" style="width:{{ score }}%;background:{{ score_color }}"></div>
    </div>
  </div>

  <div class="summary-grid">
    <div class="card">
      <div class="label">PQC Readiness</div>
      <div class="value" style="color:{{ readiness_color }}">{{ "%.0f"|format(pqc_readiness) }}%</div>
    </div>
    <div class="card">
      <div class="label">Total Findings</div>
      <div class="value">{{ total_findings }}</div>
    </div>
    <div class="card">
      <div class="label">Files Scanned</div>
      <div class="value">{{ files_scanned }}</div>
    </div>
    <div class="card">
      <div class="label">Duration</div>
      <div class="value" style="font-size:1.3rem">{{ "%.2f"|format(duration) }}s</div>
    </div>
  </div>
</section>

<!-- ============ RISK DISTRIBUTION ============ -->
{% if findings %}
<section>
  <h2>Risk Distribution</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:32px">

    <div class="bar-group">
      <h3>By Severity</h3>
      {% for sev_name, count, color, pct in severity_bars %}
      <div class="bar-row">
        <span class="bar-label">{{ sev_name }}</span>
        <div class="bar-track">
          <div class="bar-fill" style="width:{{ pct }}%;background:{{ color }}">{{ count }}</div>
        </div>
      </div>
      {% endfor %}
    </div>

    <div class="bar-group">
      <h3>By Quantum Risk</h3>
      {% for risk_name, count, color, pct in risk_bars %}
      <div class="bar-row">
        <span class="bar-label">{{ risk_name }}</span>
        <div class="bar-track">
          <div class="bar-fill" style="width:{{ pct }}%;background:{{ color }}">{{ count }}</div>
        </div>
      </div>
      {% endfor %}
    </div>

  </div>
</section>
{% endif %}

<!-- ============ FINDINGS TABLE ============ -->
{% if findings %}
<section>
  <h2>Findings ({{ findings|length }})</h2>
  <div style="overflow-x:auto">
  <table class="findings-table">
    <thead>
      <tr>
        <th>Severity</th>
        <th>Q-Risk</th>
        <th>Algorithm</th>
        <th>Location</th>
        <th>Message</th>
        <th>Recommendation</th>
      </tr>
    </thead>
    <tbody>
    {% for f in findings %}
      <tr>
        <td><span class="badge badge-{{ f.severity }}">{{ f.severity|upper }}</span></td>
        <td><span class="badge badge-{{ f.quantum_risk }}">{{ f.quantum_risk|upper }}</span></td>
        <td>{{ f.algorithm }}</td>
        <td class="loc">{{ f.location }}</td>
        <td>{{ f.message }}</td>
        <td>{{ f.recommendation }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  </div>
</section>
{% endif %}

<!-- ============ RECOMMENDATIONS ============ -->
{% if recommendations %}
<section>
  <h2>Recommendations</h2>
  <ul class="rec-list">
  {% for algo, action, replacements in recommendations %}
    <li>
      <div class="algo">{{ algo }}</div>
      <div class="action">{{ action }}</div>
      {% if replacements %}
      <div class="pqc">PQC replacement → {{ replacements }}</div>
      {% endif %}
    </li>
  {% endfor %}
  </ul>
</section>
{% endif %}

<!-- ============ COMPLIANCE MAPPING ============ -->
{% if compliance_rows %}
<section>
  <h2>Compliance Mapping</h2>
  <div style="overflow-x:auto">
  <table class="compliance-table">
    <thead>
      <tr>
        <th>Algorithm</th>
        <th>Location</th>
        <th>Framework</th>
        <th>Requirement</th>
        <th>Description</th>
        <th>Status</th>
        <th>Deadline</th>
      </tr>
    </thead>
    <tbody>
    {% for row in compliance_rows %}
      <tr>
        <td>{{ row.algorithm }}</td>
        <td class="loc">{{ row.location }}</td>
        <td>{{ row.framework }}</td>
        <td>{{ row.requirement_id }}</td>
        <td>{{ row.description }}</td>
        <td><span class="status-{{ row.status }}">{{ row.status_display }}</span></td>
        <td>{{ row.deadline or "—" }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  </div>
</section>
{% else %}
<section>
  <h2>Compliance Mapping</h2>
  <p style="color:var(--text-dim)">No compliance references mapped for these findings.</p>
</section>
{% endif %}

<!-- ============ FOOTER ============ -->
<footer>
  Generated by Quant-Scan v{{ version }} — EYD Company
</footer>

</div>
</body>
</html>""",
    autoescape=True,
)

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "info": "#7f8c8d",
}

_RISK_COLORS = {
    "vulnerable": "#e74c3c",
    "weakened": "#f39c12",
    "safe": "#2ecc71",
    "unknown": "#7f8c8d",
}


def _score_color(score: float) -> str:
    if score >= 90:
        return "#2ecc71"
    if score >= 75:
        return "#3498db"
    if score >= 60:
        return "#f1c40f"
    if score >= 40:
        return "#e67e22"
    return "#e74c3c"


def _readiness_color(pct: float) -> str:
    if pct >= 80:
        return "#2ecc71"
    if pct >= 50:
        return "#f1c40f"
    return "#e74c3c"


# ---------------------------------------------------------------------------
# Bar chart data builders
# ---------------------------------------------------------------------------


def _severity_bars(by_severity: dict[str, int], total: int) -> list[tuple[str, int, str, float]]:
    """Return (label, count, color, percentage) for each severity level."""
    order = ["critical", "high", "medium", "low", "info"]
    bars: list[tuple[str, int, str, float]] = []
    for name in order:
        count = by_severity.get(name, 0)
        pct = (count / total * 100) if total else 0
        bars.append((name, count, _SEVERITY_COLORS.get(name, "#7f8c8d"), pct))
    return bars


def _risk_bars(by_risk: dict[str, int], total: int) -> list[tuple[str, int, str, float]]:
    order = ["vulnerable", "weakened", "safe", "unknown"]
    bars: list[tuple[str, int, str, float]] = []
    for name in order:
        count = by_risk.get(name, 0)
        pct = (count / total * 100) if total else 0
        bars.append((name, count, _RISK_COLORS.get(name, "#7f8c8d"), pct))
    return bars


# ---------------------------------------------------------------------------
# Finding / recommendation row helpers
# ---------------------------------------------------------------------------


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    return sorted(findings, key=lambda f: order.get(f.severity, 5))


def _finding_rows(findings: list[Finding]) -> list[dict]:
    rows = []
    for f in _sort_findings(findings):
        rows.append(
            {
                "severity": f.severity.value,
                "quantum_risk": f.quantum_risk.value,
                "algorithm": f.algorithm.name,
                "location": f"{f.location.file_path}:{f.location.line_number}",
                "message": f.message,
                "recommendation": f.recommendation or "—",
            }
        )
    return rows


def _unique_recommendations(
    findings: list[Finding],
) -> list[tuple[str, str, str]]:
    seen: set[str] = set()
    recs: list[tuple[str, str, str]] = []
    for f in _sort_findings(findings):
        if f.algorithm.name in seen or not f.recommendation:
            continue
        seen.add(f.algorithm.name)
        replacements = ", ".join(f.algorithm.pqc_replacements) if f.algorithm.pqc_replacements else ""
        recs.append((f.algorithm.name, f.recommendation, replacements))
    return recs


def _compliance_rows(findings: list[Finding]) -> list[dict]:
    """Parse compliance_refs strings back into structured rows.

    The compliance mapper stores refs as strings like:
      "NIST SP 800-131A: RSA key sizes below 2048 bits are disallowed"
      "EU PQC Roadmap INV-2026-Q4: Complete cryptographic inventory ..."

    We also re-map via the ComplianceMapper to get the structured data directly.
    """
    try:
        from quant_scan.compliance.mapper import ComplianceMapper

        mapper = ComplianceMapper()
    except Exception:
        return []

    rows: list[dict] = []
    for f in _sort_findings(findings):
        refs = mapper.map_finding(f)
        loc = f"{f.location.file_path}:{f.location.line_number}"
        for ref in refs:
            status_display = ref.status.replace("_", " ").title()
            rows.append(
                {
                    "algorithm": f.algorithm.name,
                    "location": loc,
                    "framework": ref.framework,
                    "requirement_id": ref.requirement_id,
                    "description": ref.description,
                    "status": ref.status,
                    "status_display": status_display,
                    "deadline": ref.deadline,
                }
            )
    return rows


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_html(result: ScanResult) -> str:
    """Render a fully self-contained HTML report from *result*."""
    s = result.summary
    total = s.total_findings or len(result.findings)

    return _HTML_TEMPLATE.render(
        timestamp=result.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        version=result.scanner_version,
        score=s.score,
        grade=s.grade,
        score_color=_score_color(s.score),
        pqc_readiness=s.pqc_readiness_pct,
        readiness_color=_readiness_color(s.pqc_readiness_pct),
        total_findings=total,
        files_scanned=s.files_scanned,
        duration=result.duration_seconds,
        findings=_finding_rows(result.findings),
        severity_bars=_severity_bars(s.by_severity, total),
        risk_bars=_risk_bars(s.by_quantum_risk, total),
        recommendations=_unique_recommendations(result.findings),
        compliance_rows=_compliance_rows(result.findings),
    )
