"""
Reporter Module
Outputs analysis results as plain text, JSON, or HTML reports.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from .analyzer import AnalysisResult

logger = logging.getLogger(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Syslog Analysis Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e2e8f0; }}
    .header {{ background: linear-gradient(135deg, #1e293b, #0f172a); padding: 32px 40px; border-bottom: 1px solid #334155; }}
    .header h1 {{ font-size: 1.8rem; color: #38bdf8; }}
    .header p {{ color: #94a3b8; margin-top: 6px; font-size: 0.9rem; }}
    .container {{ max-width: 1100px; margin: 32px auto; padding: 0 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 20px; }}
    .card h3 {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: .05em; color: #94a3b8; margin-bottom: 8px; }}
    .card .value {{ font-size: 2rem; font-weight: 700; color: #f1f5f9; }}
    .card.danger .value {{ color: #f87171; }}
    .card.warn .value {{ color: #fbbf24; }}
    .card.ok .value {{ color: #34d399; }}
    .section {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 24px; margin-bottom: 24px; }}
    .section h2 {{ font-size: 1rem; color: #38bdf8; margin-bottom: 16px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
    th {{ text-align: left; padding: 8px 12px; color: #94a3b8; font-weight: 600; border-bottom: 1px solid #334155; }}
    td {{ padding: 8px 12px; border-bottom: 1px solid #1e293b; }}
    tr:hover td {{ background: #0f172a; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }}
    .badge-error {{ background: #7f1d1d; color: #fca5a5; }}
    .badge-warn {{ background: #78350f; color: #fde68a; }}
    .badge-info {{ background: #1e3a5f; color: #93c5fd; }}
    .alert-box {{ background: #450a0a; border: 1px solid #991b1b; border-radius: 8px; padding: 12px 16px; margin-bottom: 10px; color: #fca5a5; }}
    .no-alerts {{ color: #34d399; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>&#128203; Syslog Analysis Report</h1>
    <p>Generated: {generated_at}</p>
    {time_range_html}
  </div>
  <div class="container">
    <div class="grid">
      <div class="card"><h3>Total Entries</h3><div class="value">{total}</div></div>
      <div class="card danger"><h3>Errors</h3><div class="value">{errors}</div></div>
      <div class="card warn"><h3>Warnings</h3><div class="value">{warnings}</div></div>
      <div class="card"><h3>Unparseable</h3><div class="value">{unparseable}</div></div>
    </div>

    {alerts_section}

    <div class="section">
      <h2>By Severity</h2>
      <table>
        <tr><th>Severity</th><th>Count</th></tr>
        {severity_rows}
      </table>
    </div>

    <div class="section">
      <h2>Top Processes</h2>
      <table>
        <tr><th>Process</th><th>Count</th></tr>
        {process_rows}
      </table>
    </div>

    <div class="section">
      <h2>Top Hostnames</h2>
      <table>
        <tr><th>Hostname</th><th>Count</th></tr>
        {hostname_rows}
      </table>
    </div>

    <div class="section">
      <h2>By Facility</h2>
      <table>
        <tr><th>Facility</th><th>Count</th></tr>
        {facility_rows}
      </table>
    </div>

    <div class="section">
      <h2>Recent Errors (up to 20)</h2>
      <table>
        <tr><th>Time</th><th>Host</th><th>Process</th><th>Severity</th><th>Message</th></tr>
        {error_rows}
      </table>
    </div>
  </div>
</body>
</html>
"""


def _severity_badge(sev: str) -> str:
    sev = sev.upper()
    if sev in ("EMERGENCY", "ALERT", "CRITICAL", "ERROR"):
        cls = "badge-error"
    elif sev == "WARNING":
        cls = "badge-warn"
    else:
        cls = "badge-info"
    return f'<span class="badge {cls}">{sev}</span>'


class Reporter:
    def __init__(self, output_dir: str = "/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def print_summary(self, result: AnalysisResult):
        """Print a human-readable summary to stdout."""
        sep = "=" * 60
        print(sep)
        print("  SYSLOG ANALYSIS REPORT")
        print(sep)
        print(f"  Total entries    : {result.total_entries:,}")
        print(f"  Errors           : {len(result.error_entries):,}")
        print(f"  Warnings         : {len(result.warning_entries):,}")
        print(f"  Unparseable      : {result.unparseable_count:,}")
        if result.time_range:
            print(f"  Time range       : {result.time_range['start']} → {result.time_range['end']}")
        print()

        if result.alerts:
            print("  ⚠  ALERTS")
            for a in result.alerts:
                print(f"    • {a}")
            print()

        print("  Severity Breakdown:")
        for sev, count in sorted(result.by_severity.items()):
            bar = "█" * min(count // max(result.total_entries // 40, 1), 40)
            print(f"    {sev:<12} {count:>6,}  {bar}")
        print()

        print("  Top 10 Processes:")
        for proc, count in result.top_processes:
            print(f"    {proc:<30} {count:>6,}")
        print()

        print("  Top 10 Hostnames:")
        for host, count in result.top_hostnames:
            print(f"    {host:<30} {count:>6,}")
        print(sep)

    def save_json(self, result: AnalysisResult, filename: str = "report.json") -> str:
        """Save analysis result as JSON."""
        path = self.output_dir / filename
        data = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_entries": result.total_entries,
            "errors": len(result.error_entries),
            "warnings": len(result.warning_entries),
            "unparseable": result.unparseable_count,
            "time_range": result.time_range,
            "by_severity": result.by_severity,
            "by_facility": result.by_facility,
            "by_hostname": result.by_hostname,
            "by_process": result.by_process,
            "by_format": result.by_format,
            "top_processes": result.top_processes,
            "top_hostnames": result.top_hostnames,
            "alerts": result.alerts,
            "recent_errors": [e.to_dict() for e in result.error_entries[:50]],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"JSON report saved to {path}")
        return str(path)

    def save_html(self, result: AnalysisResult, filename: str = "report.html") -> str:
        """Save analysis result as an HTML dashboard."""
        path = self.output_dir / filename
        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        time_range_html = ""
        if result.time_range:
            time_range_html = (
                f"<p>Log range: {result.time_range['start']} → {result.time_range['end']}</p>"
            )

        # Alerts section
        if result.alerts:
            alert_items = "".join(
                f'<div class="alert-box">&#9888; {a}</div>' for a in result.alerts
            )
            alerts_section = f'<div class="section"><h2>&#9888; Alerts</h2>{alert_items}</div>'
        else:
            alerts_section = (
                '<div class="section"><h2>Alerts</h2>'
                '<p class="no-alerts">&#10003; No alerts triggered.</p></div>'
            )

        def table_rows(data: dict) -> str:
            return "".join(
                f"<tr><td>{k}</td><td>{v:,}</td></tr>"
                for k, v in sorted(data.items(), key=lambda x: -x[1])
            )

        error_rows = ""
        for e in result.error_entries[:20]:
            ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "-"
            msg = e.message[:120].replace("<", "&lt;").replace(">", "&gt;")
            error_rows += (
                f"<tr><td>{ts}</td><td>{e.hostname}</td><td>{e.process}</td>"
                f"<td>{_severity_badge(e.severity)}</td><td>{msg}</td></tr>"
            )

        html = HTML_TEMPLATE.format(
            generated_at=generated_at,
            time_range_html=time_range_html,
            total=f"{result.total_entries:,}",
            errors=f"{len(result.error_entries):,}",
            warnings=f"{len(result.warning_entries):,}",
            unparseable=f"{result.unparseable_count:,}",
            alerts_section=alerts_section,
            severity_rows=table_rows(result.by_severity),
            process_rows="".join(
                f"<tr><td>{p}</td><td>{c:,}</td></tr>" for p, c in result.top_processes
            ),
            hostname_rows="".join(
                f"<tr><td>{h}</td><td>{c:,}</td></tr>" for h, c in result.top_hostnames
            ),
            facility_rows=table_rows(result.by_facility),
            error_rows=error_rows or "<tr><td colspan='5'>No errors found.</td></tr>",
        )

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"HTML report saved to {path}")
        return str(path)
