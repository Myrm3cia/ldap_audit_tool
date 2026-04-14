"""
HTML report generator — Nessus-inspired layout.

Produces a single self-contained .html file (no external dependencies).
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from checks.anonymous_bind import Finding
from config.settings import Severity
from core.enumerator import DirectoryInfo


# ---------------------------------------------------------------------------
# Severity palette (Nessus-inspired)
# ---------------------------------------------------------------------------

_SEV_COLOR = {
    Severity.CRITICAL: ("#7B0D1E", "#ffd6dc"),
    Severity.HIGH:     ("#C0392B", "#fde8e8"),
    Severity.MEDIUM:   ("#D35400", "#fef3e2"),
    Severity.LOW:      ("#1A5276", "#d6eaf8"),
    Severity.INFO:     ("#424242", "#f5f5f5"),
}

_SEV_BADGE = {
    Severity.CRITICAL: "#7B0D1E",
    Severity.HIGH:     "#C0392B",
    Severity.MEDIUM:   "#D35400",
    Severity.LOW:      "#1A5276",
    Severity.INFO:     "#757575",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_html(
    findings: list[Finding],
    dir_info: DirectoryInfo,
    host: str,
    port: int,
    bind_dn: Optional[str],
    output_path: Optional[str],
) -> None:
    """
    Render findings to a self-contained HTML file (or stdout if output_path is None).
    """
    doc = _render(findings, dir_info, host, port, bind_dn)

    if output_path is None:
        print(doc)
        return

    path = Path(output_path).with_suffix(".html")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")
    print(f"[+] HTML report written to: {path}")


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def _render(
    findings: list[Finding],
    dir_info: DirectoryInfo,
    host: str,
    port: int,
    bind_dn: Optional[str],
) -> str:
    by_sev = Counter(f.severity for f in findings)
    ts     = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LDAP Audit Report — {html.escape(host)}</title>
{_css()}
</head>
<body>

{_header(host, port, bind_dn, dir_info, ts)}
{_summary_cards(by_sev, findings)}
{_domain_info(dir_info)}
{_findings_table(findings)}
{_findings_detail(findings)}
{_footer(ts)}

{_js()}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _header(host: str, port: int, bind_dn: Optional[str], dir_info: DirectoryInfo, ts: str) -> str:
    return f"""
<header class="page-header">
  <div class="header-inner">
    <div class="header-logo">
      <span class="logo-icon">&#128274;</span>
      <div>
        <div class="logo-title">LDAP Security Audit</div>
        <div class="logo-sub">Security Posture Report</div>
      </div>
    </div>
    <div class="header-meta">
      <table class="meta-table">
        <tr><td>Target</td><td><strong>{html.escape(f"{host}:{port}")}</strong></td></tr>
        <tr><td>Base DN</td><td><code>{html.escape(dir_info.base_dn or "—")}</code></td></tr>
        <tr><td>Bind DN</td><td><code>{html.escape(bind_dn or "(anonymous)")}</code></td></tr>
        <tr><td>Generated</td><td>{ts}</td></tr>
      </table>
    </div>
  </div>
</header>"""


def _summary_cards(by_sev: Counter, findings: list[Finding]) -> str:
    sevs = [
        (Severity.CRITICAL, "Critical"),
        (Severity.HIGH,     "High"),
        (Severity.MEDIUM,   "Medium"),
        (Severity.LOW,      "Low"),
        (Severity.INFO,     "Info"),
    ]
    cards = ""
    for sev, label in sevs:
        count  = by_sev.get(sev, 0)
        bg, _  = _SEV_COLOR[sev]
        active = " card-active" if count > 0 else " card-zero"
        cards += f"""
      <div class="summary-card{active}" style="--card-color:{bg}">
        <div class="card-count">{count}</div>
        <div class="card-label">{label}</div>
      </div>"""

    total = len(findings)
    return f"""
<section class="section summary-section">
  <h2 class="section-title">Risk Summary</h2>
  <div class="summary-cards">
    {cards}
    <div class="summary-card card-total">
      <div class="card-count">{total}</div>
      <div class="card-label">Total</div>
    </div>
  </div>
</section>"""


def _domain_info(dir_info: DirectoryInfo) -> str:
    si   = dir_info.server_info
    rows = ""
    info_items = [
        ("OUs",            str(dir_info.ou_count)),
        ("Users",          str(dir_info.user_count)),
        ("Groups",         str(dir_info.group_count)),
        ("Naming contexts", "<br>".join(html.escape(nc) for nc in dir_info.naming_contexts)),
        ("Vendor",         html.escape(si.get("vendor_name", "—") or "—")),
        ("Version",        html.escape(si.get("vendor_version", "—") or "—")),
        ("LDAP versions",  html.escape(", ".join(si.get("supported_ldap_versions", [])) or "—")),
        ("SASL mechanisms",html.escape(", ".join(si.get("supported_sasl_mechanisms", [])) or "—")),
    ]
    for label, value in info_items:
        rows += f'<tr><td class="di-label">{label}</td><td>{value}</td></tr>\n'

    return f"""
<section class="section">
  <h2 class="section-title">Directory Information</h2>
  <table class="di-table">
    {rows}
  </table>
</section>"""


def _findings_table(findings: list[Finding]) -> str:
    if not findings:
        return '<section class="section"><p class="no-findings">No findings.</p></section>'

    rows = ""
    for i, f in enumerate(findings, start=1):
        bg, light = _SEV_COLOR[f.severity]
        badge = (
            f'<span class="badge" style="background:{bg}">'
            f'{html.escape(f.severity.value)}</span>'
        )
        rows += f"""
      <tr class="finding-row" onclick="toggleDetail('detail-{i}')"
          style="--row-light:{light}">
        <td class="td-num">{i}</td>
        <td>{badge}</td>
        <td class="td-id"><code>{html.escape(f.id)}</code></td>
        <td class="td-title">{html.escape(f.title)}</td>
        <td class="td-chevron">&#9660;</td>
      </tr>
      <tr id="detail-{i}" class="detail-row" style="display:none">
        <td colspan="5">
          {_finding_detail_inner(f)}
        </td>
      </tr>"""

    return f"""
<section class="section">
  <h2 class="section-title">Findings
    <span class="findings-count">{len(findings)}</span>
  </h2>
  <p class="table-hint">Click a row to expand details.</p>
  <table class="findings-table" id="findingsTable">
    <thead>
      <tr>
        <th class="th-num">#</th>
        <th>Severity</th>
        <th>ID</th>
        <th>Title</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</section>"""


def _findings_detail(findings: list[Finding]) -> str:
    """Detailed finding cards below the table (printable / non-JS fallback)."""
    if not findings:
        return ""

    cards = ""
    for i, f in enumerate(findings, start=1):
        bg, light = _SEV_COLOR[f.severity]
        evidence_html = _render_evidence(f.evidence)
        cards += f"""
  <div class="finding-card" id="card-{i}" style="--card-bg:{light};--card-border:{bg}">
    <div class="fc-header" style="background:{bg}">
      <span class="fc-num">#{i}</span>
      <span class="fc-id">{html.escape(f.id)}</span>
      <span class="fc-sev">{html.escape(f.severity.value)}</span>
      <span class="fc-title">{html.escape(f.title)}</span>
    </div>
    <div class="fc-body">
      <div class="fc-section">
        <div class="fc-label">Description</div>
        <div class="fc-text">{html.escape(f.description)}</div>
      </div>
      <div class="fc-section">
        <div class="fc-label">Evidence</div>
        <div class="fc-evidence">{evidence_html}</div>
      </div>
      <div class="fc-section">
        <div class="fc-label">Recommendation</div>
        <div class="fc-text fc-rec">{html.escape(f.recommendation)}</div>
      </div>
    </div>
  </div>"""

    return f"""
<section class="section print-only">
  <h2 class="section-title">Finding Details</h2>
  {cards}
</section>"""


def _finding_detail_inner(f: Finding) -> str:
    evidence_html = _render_evidence(f.evidence)
    bg, _ = _SEV_COLOR[f.severity]
    return f"""
<div class="inline-detail" style="--detail-border:{bg}">
  <div class="id-grid">
    <div class="id-cell">
      <div class="id-label">Description</div>
      <div class="id-text">{html.escape(f.description)}</div>
    </div>
    <div class="id-cell">
      <div class="id-label">Recommendation</div>
      <div class="id-text id-rec">{html.escape(f.recommendation)}</div>
    </div>
  </div>
  <div class="id-evidence">
    <div class="id-label">Evidence</div>
    {evidence_html}
  </div>
</div>"""


def _render_evidence(evidence: dict) -> str:
    """Render evidence dict as an HTML definition list."""
    if not evidence:
        return "<em>No evidence recorded.</em>"
    items = ""
    for k, v in evidence.items():
        if isinstance(v, (list, dict)):
            val_str = f'<pre class="ev-json">{html.escape(json.dumps(v, indent=2, default=str))}</pre>'
        else:
            val_str = f"<code>{html.escape(str(v))}</code>"
        items += f'<div class="ev-row"><span class="ev-key">{html.escape(k)}</span>{val_str}</div>'
    return f'<div class="ev-list">{items}</div>'


def _footer(ts: str) -> str:
    return f"""
<footer class="page-footer">
  <span>Generated by <strong>ldap-audit</strong> &mdash; {ts}</span>
  <span>Read-only security posture analysis. No exploits or attacks performed.</span>
</footer>"""


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

def _css() -> str:
    return """<style>
/* Reset & base */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-size: 14px;
  background: #f0f2f5;
  color: #1a1a2e;
  line-height: 1.5;
}
code { font-family: "Consolas", "Courier New", monospace; font-size: 0.9em; }

/* Header */
.page-header {
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 60%, #0f3460 100%);
  color: #fff;
  padding: 0;
}
.header-inner {
  max-width: 1200px;
  margin: 0 auto;
  padding: 28px 32px;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 32px;
  flex-wrap: wrap;
}
.header-logo { display: flex; align-items: center; gap: 16px; }
.logo-icon { font-size: 2.8rem; }
.logo-title { font-size: 1.6rem; font-weight: 700; letter-spacing: 0.5px; }
.logo-sub   { font-size: 0.85rem; color: #a0aec0; margin-top: 2px; }
.meta-table { border-collapse: collapse; color: #e2e8f0; }
.meta-table td { padding: 3px 12px 3px 0; vertical-align: top; }
.meta-table td:first-child { color: #a0aec0; white-space: nowrap; padding-right: 16px; }
.meta-table code { color: #90cdf4; }

/* Section */
.section {
  max-width: 1200px;
  margin: 28px auto;
  padding: 0 32px;
}
.section-title {
  font-size: 1.1rem;
  font-weight: 700;
  color: #1a1a2e;
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 2px solid #e2e8f0;
  display: flex;
  align-items: center;
  gap: 10px;
}
.findings-count {
  background: #1a1a2e;
  color: #fff;
  border-radius: 12px;
  padding: 1px 10px;
  font-size: 0.8rem;
  font-weight: 600;
}

/* Summary cards */
.summary-section { margin-top: 32px; }
.summary-cards {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}
.summary-card {
  flex: 1;
  min-width: 110px;
  background: #fff;
  border-top: 4px solid var(--card-color, #ccc);
  border-radius: 6px;
  padding: 20px 16px 16px;
  text-align: center;
  box-shadow: 0 1px 4px rgba(0,0,0,.08);
  transition: transform .15s;
}
.summary-card:hover { transform: translateY(-2px); }
.card-active { box-shadow: 0 2px 8px rgba(0,0,0,.15); }
.card-zero   { opacity: .55; }
.card-total  { --card-color: #374151; }
.card-count  { font-size: 2.2rem; font-weight: 800; color: var(--card-color, #374151); }
.card-label  { font-size: 0.78rem; font-weight: 600; text-transform: uppercase;
               letter-spacing: .6px; color: #6b7280; margin-top: 4px; }

/* Directory info table */
.di-table { border-collapse: collapse; width: 100%; background: #fff;
            border-radius: 6px; overflow: hidden;
            box-shadow: 0 1px 4px rgba(0,0,0,.08); }
.di-table td { padding: 9px 16px; border-bottom: 1px solid #f0f0f0; }
.di-label { font-weight: 600; color: #4b5563; width: 180px; background: #f9fafb; }
.di-table tr:last-child td { border-bottom: none; }

/* Findings table */
.table-hint { color: #6b7280; font-size: 0.82rem; margin-bottom: 10px; }
.findings-table {
  width: 100%;
  border-collapse: collapse;
  background: #fff;
  border-radius: 6px;
  overflow: hidden;
  box-shadow: 0 1px 4px rgba(0,0,0,.08);
}
.findings-table thead tr { background: #1a1a2e; color: #e2e8f0; }
.findings-table th { padding: 11px 14px; text-align: left; font-size: 0.8rem;
                     text-transform: uppercase; letter-spacing: .5px; font-weight: 600; }
.findings-table td { padding: 10px 14px; border-bottom: 1px solid #f0f0f0;
                     vertical-align: middle; }
.finding-row { cursor: pointer; transition: background .12s; }
.finding-row:hover { background: var(--row-light, #f9fafb) !important; }
.finding-row:hover .td-chevron { color: #1a1a2e; }
.td-num     { width: 40px; color: #9ca3af; font-size: 0.82rem; text-align: center; }
.td-id      { width: 110px; }
.td-title   { font-weight: 500; }
.td-chevron { width: 28px; text-align: center; color: #d1d5db; font-size: 0.75rem;
              transition: transform .2s; }
.detail-row td { padding: 0; background: #fafafa; }
.badge {
  display: inline-block;
  padding: 3px 9px;
  border-radius: 3px;
  color: #fff;
  font-size: 0.73rem;
  font-weight: 700;
  letter-spacing: .4px;
  text-transform: uppercase;
  white-space: nowrap;
}

/* Inline detail (expanded row) */
.inline-detail {
  border-left: 4px solid var(--detail-border, #ccc);
  padding: 20px 24px;
  background: #fafafa;
}
.id-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 20px; }
@media (max-width: 700px) { .id-grid { grid-template-columns: 1fr; } }
.id-label { font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
            letter-spacing: .5px; color: #6b7280; margin-bottom: 6px; }
.id-text  { color: #374151; }
.id-rec   { color: #065f46; background: #ecfdf5; padding: 10px 12px; border-radius: 4px;
            border-left: 3px solid #059669; }
.id-evidence { margin-top: 4px; }

/* Evidence */
.ev-list  { display: flex; flex-direction: column; gap: 6px; }
.ev-row   { display: flex; align-items: flex-start; gap: 12px; }
.ev-key   { font-weight: 600; color: #374151; min-width: 200px; font-size: 0.85rem; }
.ev-json  {
  background: #1e293b; color: #94a3b8; padding: 10px 14px;
  border-radius: 4px; font-size: 0.8rem; overflow-x: auto;
  white-space: pre; margin-top: 4px; width: 100%;
}

/* Print-only detail cards */
.print-only { display: none; }
.finding-card {
  background: var(--card-bg, #f9fafb);
  border-left: 5px solid var(--card-border, #ccc);
  border-radius: 6px;
  margin-bottom: 20px;
  overflow: hidden;
  box-shadow: 0 1px 4px rgba(0,0,0,.08);
}
.fc-header {
  padding: 12px 20px;
  color: #fff;
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
}
.fc-num   { font-weight: 800; font-size: 1rem; }
.fc-id    { font-family: monospace; font-size: 0.85rem; opacity: .85; }
.fc-sev   { background: rgba(255,255,255,.2); border-radius: 3px; padding: 2px 8px;
            font-size: 0.75rem; font-weight: 700; letter-spacing: .4px; text-transform: uppercase; }
.fc-title { font-weight: 600; font-size: 0.95rem; }
.fc-body  { padding: 18px 20px; display: flex; flex-direction: column; gap: 16px; }
.fc-section { display: flex; flex-direction: column; gap: 6px; }
.fc-label { font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
            letter-spacing: .5px; color: #6b7280; }
.fc-text  { color: #374151; }
.fc-rec   { color: #065f46; background: #ecfdf5; padding: 10px 12px; border-radius: 4px;
            border-left: 3px solid #059669; }
.no-findings { color: #6b7280; font-style: italic; padding: 16px 0; }

/* Footer */
.page-footer {
  max-width: 1200px;
  margin: 40px auto 24px;
  padding: 0 32px;
  display: flex;
  justify-content: space-between;
  font-size: 0.78rem;
  color: #9ca3af;
  flex-wrap: wrap;
  gap: 8px;
  border-top: 1px solid #e5e7eb;
  padding-top: 16px;
}

/* Print */
@media print {
  body { background: #fff; font-size: 11pt; }
  .page-header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .summary-card { border-top: 4px solid var(--card-color); -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .fc-header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .table-hint { display: none; }
  .td-chevron { display: none; }
  .detail-row { display: none !important; }
  .print-only { display: block !important; }
  .section { page-break-inside: avoid; }
  .finding-card { page-break-inside: avoid; }
}
</style>"""


# ---------------------------------------------------------------------------
# JavaScript (expand/collapse rows)
# ---------------------------------------------------------------------------

def _js() -> str:
    return """<script>
function toggleDetail(id) {
  var row = document.getElementById(id);
  if (!row) return;
  var chevron = row.previousElementSibling.querySelector('.td-chevron');
  if (row.style.display === 'none' || row.style.display === '') {
    row.style.display = 'table-row';
    if (chevron) chevron.style.transform = 'rotate(180deg)';
  } else {
    row.style.display = 'none';
    if (chevron) chevron.style.transform = 'rotate(0deg)';
  }
}
</script>"""
