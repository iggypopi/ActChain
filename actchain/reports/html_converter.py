# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
JSON to HTML converter for ActChain reports.
"""

import html
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from ..utils.file_utils import FileUtils

logger = logging.getLogger('actchain.reports.html_converter')


class HTMLReportGenerator:
    """Generates HTML reports from JSON data."""

    def __init__(self):
        """Initialize the HTML report generator."""
        self.css_styles = self._get_css_styles()

    def convert_json_to_html(self, json_path: str) -> Optional[str]:
        """
        Convert a consolidated JSON report to HTML format.

        Args:
            json_path: Path to the consolidated JSON report

        Returns:
            Path to the generated HTML report, or None if failed
        """
        try:
            # Determine output path
            html_path = str(Path(json_path).with_suffix('.html'))

            # Load JSON data
            json_content = FileUtils.safe_read_file(json_path)
            if not json_content:
                return self._create_error_html(html_path, "Failed to read JSON file")

            # Parse JSON
            try:
                data = json.loads(json_content)
            except json.JSONDecodeError as e:
                return self._create_error_html(html_path, f"Invalid JSON: {e}")

            # Generate HTML
            html_content = self._generate_html_content(data)

            # Save HTML file
            if FileUtils.safe_write_file(html_content, html_path):
                logger.info(f"Generated HTML report: {html_path}")
                return html_path
            else:
                return None

        except Exception as e:
            logger.error(f"Error converting JSON to HTML: {e}")
            return None

    def _generate_html_content(self, data: Dict[str, Any]) -> str:
        """Generate HTML content from report data."""
        # Extract data sections
        meta = data.get('meta', {})
        workflow = data.get('workflow', {})
        findings = data.get('findings', [])
        dependencies = data.get('dependencies', [])
        statistics = data.get('statistics', {})

        # Generate HTML sections
        html_parts = [
            self._generate_html_header(workflow.get('name', 'Unknown')),
            self._generate_header_section(meta, workflow),
            self._generate_malicious_section(findings),
            self._generate_summary_section(statistics),
            self._generate_gate_section(data.get('gate')),
            self._generate_ai_section(data.get('ai')),
            self._generate_findings_section(findings, statistics),
            self._generate_dependencies_section(dependencies),
            self._generate_footer()
        ]

        return '\n'.join(part for part in html_parts if part)

    def _generate_malicious_section(self, findings: List[Dict[str, Any]]) -> str:
        """Prominent banner listing findings flagged as malicious."""
        malicious = [f for f in findings if isinstance(f, dict) and f.get('malicious')]
        if not malicious:
            return ''

        items = []
        for finding in malicious[:20]:
            title = html.escape(str(finding.get('title', 'untitled')))
            where = html.escape(str(finding.get('action_ref')
                                    or finding.get('location', {}).get('path', 'unknown')))
            scanner = html.escape(str(finding.get('source_scanner', '?')))
            items.append(f"<li><strong>{title}</strong> — <code>{where}</code> ({scanner})</li>")
        more = ''
        if len(malicious) > 20:
            more = f"<p><em>… and {len(malicious) - 20} more — see the findings below.</em></p>"

        return f"""
    <div class="malicious-banner">
        <h2>🚨 Malicious behavior detected — {len(malicious)} finding(s)</h2>
        <ul>{''.join(items)}</ul>
        {more}
    </div>"""

    def _generate_gate_section(self, gate: Optional[Dict[str, Any]]) -> str:
        """Pinning policy gate verdict and planned pins."""
        if not isinstance(gate, dict) or not gate.get('evaluated'):
            return ''

        threshold = html.escape(str(gate.get('threshold', 'high')))
        if gate.get('passed'):
            verdict = ('<span class="gate-passed">PASSED</span> — no blocking findings at or '
                       f'above <strong>{threshold}</strong>')
            reasons_html = ''
        else:
            verdict = '<span class="gate-blocked">BLOCKED</span> — the pinning PR was not opened:'
            reasons = [f"<li>{html.escape(str(r))}</li>" for r in gate.get('reasons', [])[:10]]
            reasons_html = f"<ul>{''.join(reasons)}</ul>"

        plan_html = ''
        plan = gate.get('pin_plan')
        if isinstance(plan, dict):
            rows = []
            for entry in plan.get('entries', [])[:50]:
                if not isinstance(entry, dict):
                    continue
                rows.append(
                    "<tr>"
                    f"<td><code>{html.escape(str(entry.get('workflow', '')))}</code></td>"
                    f"<td><code>{html.escape(str(entry.get('action', '')))}</code></td>"
                    f"<td><code>{html.escape(str(entry.get('old_ref', '')))}</code></td>"
                    f"<td><code>{html.escape(str(entry.get('new_sha', ''))[:12])}</code></td>"
                    "</tr>"
                )
            total = plan.get('entries_total', len(rows))
            skipped = plan.get('skipped_total', 0)
            table = ''
            if rows:
                table = f"""
            <table>
                <tr><th>Workflow</th><th>Action</th><th>Old ref</th><th>Pinned SHA</th></tr>
                {''.join(rows)}
            </table>"""
                if total > 50:
                    table += f"<p><em>… and {total - 50} more — see the JSON report.</em></p>"
            plan_html = (f"<p><strong>Pin plan:</strong> {total} reference(s) to pin, "
                         f"{skipped} skipped.</p>{table}")

        excluded = gate.get('excluded_findings', 0)
        excluded_html = ''
        if excluded:
            excluded_html = (f"<p><em>{excluded} unpinned-action finding(s) excluded from the "
                             f"gate (pinning is their fix).</em></p>")

        return f"""
    <div class="summary-card">
        <h3>Pinning Policy Gate</h3>
        <p>{verdict}</p>
        {reasons_html}
        {excluded_html}
        {plan_html}
    </div>"""

    def _generate_ai_section(self, ai: Optional[Dict[str, Any]]) -> str:
        """AI analysis status: model, calls and audit coverage."""
        if not isinstance(ai, dict):
            return ''
        if not ai.get('enabled'):
            error = ai.get('error')
            if not error:
                return ''
            return (f'<div class="summary-card"><h3>AI Analysis</h3>'
                    f'<p>Unavailable: {html.escape(str(error))}</p></div>')

        lines = [f"<p><strong>Model:</strong> {html.escape(str(ai.get('model', '?')))} — "
                 f"<strong>API calls:</strong> {html.escape(str(ai.get('calls', 0)))}</p>"]
        triage = ai.get('triage')
        if isinstance(triage, dict) and triage.get('findings_triaged') is not None:
            verdicts = triage.get('verdict_counts', {})
            verdict_text = ', '.join(f"{html.escape(str(k))}: {html.escape(str(v))}"
                                     for k, v in sorted(verdicts.items())) or 'none'
            lines.append(f"<p><strong>Triage:</strong> {html.escape(str(triage['findings_triaged']))} "
                         f"finding(s) — {verdict_text}</p>")
        coverage = ai.get('audit_coverage')
        if isinstance(coverage, dict) and coverage.get('audited') is not None:
            skipped = (coverage.get('skipped_cap', 0) or 0) + (coverage.get('skipped_namespace', 0) or 0)
            lines.append(f"<p><strong>Audit coverage:</strong> {html.escape(str(coverage.get('audited', 0)))} "
                         f"audited, {html.escape(str(coverage.get('truncated', 0)))} truncated, "
                         f"{html.escape(str(skipped))} skipped</p>")

        return f"""
    <div class="summary-card">
        <h3>AI Analysis</h3>
        {''.join(lines)}
    </div>"""

    def _generate_html_header(self, workflow_name: str) -> str:
        """Generate HTML document header."""
        # Escape the workflow name for the title
        escaped_workflow_name = html.escape(workflow_name)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ActChain Report - {escaped_workflow_name}</title>
    <style>
{self.css_styles}
    </style>
</head>
<body>"""

    def _generate_header_section(self, meta: Dict[str, Any], workflow: Dict[str, Any]) -> str:
        """Generate report header section."""
        # Escape all dynamic content
        scan_id = html.escape(meta.get('scan_id', 'Unknown'))
        timestamp = html.escape(meta.get('timestamp', datetime.now().isoformat()))
        workflow_name = html.escape(workflow.get('name', 'Unknown'))
        workflow_path = html.escape(workflow.get('path', 'Unknown'))

        return f"""
    <div class="header">
        <h1>ActChain Security Report</h1>
        <p><strong>Workflow:</strong> {workflow_name}</p>
        <p><strong>Path:</strong> {workflow_path}</p>
        <p><strong>Scan ID:</strong> {scan_id}</p>
        <p><strong>Date:</strong> {timestamp}</p>
    </div>"""

    def _generate_summary_section(self, statistics: Dict[str, Any]) -> str:
        """Generate summary section with statistics."""
        severity_counts = statistics.get('severity_counts', {})
        dependency_counts = statistics.get('dependency_counts', {})

        # Generate severity table
        severity_table = self._generate_severity_table(severity_counts)

        # Generate dependency table
        dependency_table = self._generate_dependency_table(dependency_counts)

        # Generate severity bar
        severity_bar = self._generate_severity_bar(severity_counts)

        return f"""
    <div class="summary-grid">
        <div class="summary-card">
            <h3>Security Findings</h3>
            {severity_table}
            {severity_bar}
        </div>
        <div class="summary-card">
            <h3>Dependencies</h3>
            {dependency_table}
        </div>
    </div>"""

    def _generate_severity_table(self, severity_counts: Dict[str, Any]) -> str:
        """Generate severity counts table."""
        severities = ['critical', 'high', 'medium', 'low']
        rows = []

        for severity in severities:
            count = severity_counts.get(severity, 0)
            # Escape values (though these are likely safe, being defensive)
            escaped_severity = html.escape(severity.capitalize())
            escaped_count = html.escape(str(count))
            rows.append(f"""
                <tr>
                    <td>{escaped_severity}</td>
                    <td>{escaped_count}</td>
                </tr>""")

        total = severity_counts.get('total', 0)
        escaped_total = html.escape(str(total))
        rows.append(f"""
                <tr>
                    <td><strong>Total</strong></td>
                    <td><strong>{escaped_total}</strong></td>
                </tr>""")

        return f"""
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                {''.join(rows)}
            </table>"""

    def _generate_dependency_table(self, dependency_counts: Dict[str, Any]) -> str:
        """Generate dependency counts table."""
        rows = []

        # Add depth information
        by_depth = dependency_counts.get('by_depth', {})
        if by_depth:
            sorted_depths = sorted(by_depth.items(), key=lambda x: int(x[0]))
            for depth, count in sorted_depths:
                escaped_depth = html.escape(str(depth))
                escaped_count = html.escape(str(count))
                rows.append(f"""
                <tr>
                    <td>Depth {escaped_depth}</td>
                    <td>{escaped_count}</td>
                </tr>""")
        else:
            rows.append("""
                <tr>
                    <td colspan="2"><em>No depth data available</em></td>
                </tr>""")

        total = dependency_counts.get('total', 0)
        escaped_total = html.escape(str(total))
        rows.append(f"""
                <tr>
                    <td><strong>Total Dependencies</strong></td>
                    <td><strong>{escaped_total}</strong></td>
                </tr>""")

        return f"""
            <table>
                <tr>
                    <th>Type</th>
                    <th>Count</th>
                </tr>
                {''.join(rows)}
            </table>"""

    def _generate_severity_bar(self, severity_counts: Dict[str, Any]) -> str:
        """Generate visual severity bar."""
        total = severity_counts.get('total', 0)
        if total == 0:
            return '<div class="severity-bar"></div>'

        # Calculate percentages (these are safe numeric values)
        critical_pct = (severity_counts.get('critical', 0) / total) * 100
        high_pct = (severity_counts.get('high', 0) / total) * 100
        medium_pct = (severity_counts.get('medium', 0) / total) * 100
        low_pct = (severity_counts.get('low', 0) / total) * 100

        return f"""
            <div class="severity-bar">
                <div class="severity-critical" style="width: {critical_pct}%;"></div>
                <div class="severity-high" style="width: {high_pct}%;"></div>
                <div class="severity-medium" style="width: {medium_pct}%;"></div>
                <div class="severity-low" style="width: {low_pct}%;"></div>
            </div>"""

    def _generate_findings_section(self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]) -> str:
        """Generate findings section."""
        if not findings:
            return '<h2>No Security Findings</h2>'

        sections = []

        # Add scanner statistics
        scanner_counts = statistics.get('scanner_counts', {})
        if scanner_counts:
            sections.append(self._generate_scanner_stats_table(scanner_counts))

        # Group findings by severity
        severity_groups = self._group_findings_by_severity(findings)

        for severity in ['critical', 'high', 'medium', 'low']:
            severity_findings = severity_groups.get(severity, [])
            if severity_findings:
                sections.append(self._generate_severity_findings_section(severity, severity_findings))

        return '\n'.join(sections)

    def _generate_scanner_stats_table(self, scanner_counts: Dict[str, int]) -> str:
        """Generate scanner statistics table."""
        rows = []
        for scanner, count in scanner_counts.items():
            # Escape scanner names and counts
            escaped_scanner = html.escape(str(scanner))
            escaped_count = html.escape(str(count))
            rows.append(f"""
        <tr>
            <td>{escaped_scanner}</td>
            <td>{escaped_count}</td>
        </tr>""")

        return f"""
    <h2>Scanner Statistics</h2>
    <table>
        <tr>
            <th>Scanner</th>
            <th>Findings Count</th>
        </tr>
        {''.join(rows)}
    </table>"""

    def _generate_severity_findings_section(self, severity: str, findings: List[Dict[str, Any]]) -> str:
        """Generate section for findings of a specific severity."""
        finding_items = []

        for finding in findings:
            finding_items.append(self._generate_finding_item(finding, severity))

        # Escape severity for display
        escaped_severity = html.escape(severity.capitalize())
        escaped_count = html.escape(str(len(findings)))

        return f"""
    <h3>{escaped_severity} Severity Issues ({escaped_count})</h3>
    {''.join(finding_items)}"""

    def _generate_finding_item(self, finding: Dict[str, Any], severity: str) -> str:
        """Generate HTML for a single finding."""
        # Escape all user-controlled data
        title = html.escape(finding.get('title', 'Unknown Issue'))
        description = html.escape(finding.get('description', ''))
        recommendation = html.escape(finding.get('recommendation', ''))
        rule_id = html.escape(finding.get('rule_id', ''))
        scanner = html.escape(finding.get('source_scanner', 'Unknown Scanner'))
        severity = html.escape(severity)  # Also escape severity to be safe

        location = finding.get('location', {})

        # Location information
        location_info = ""
        if location:
            file_path = html.escape(location.get('path', ''))
            line = html.escape(str(location.get('line', '')))
            column = html.escape(str(location.get('column', '')))
            if file_path:
                location_info = f"""
        <p><strong>Location:</strong> <span class="finding-location">{file_path}:{line}:{column}</span></p>"""

        # AI triage annotation (advisory only — never filters findings)
        triage_info = ""
        triage = finding.get('ai_triage')
        if isinstance(triage, dict):
            verdict = html.escape(str(triage.get('verdict', '')))
            rationale = html.escape(str(triage.get('rationale', '')))
            triage_info = f"""
        <p><strong>AI triage:</strong> {verdict} — {rationale}</p>"""

        # Recommendation
        recommendation_info = ""
        if recommendation:
            recommendation_info = f"""
        <p><strong>Recommendation:</strong> {recommendation}</p>"""

        # Rule ID
        rule_info = ""
        if rule_id:
            rule_info = f"""
        <p><strong>Rule ID:</strong> {rule_id}</p>"""

        malicious_badge = ""
        if finding.get('malicious'):
            malicious_badge = ' <span class="badge malicious">MALICIOUS</span>'

        return f"""
    <div class="finding {severity}">
        <h4 class="finding-title">{title} <span class="badge {severity}">{severity}</span>{malicious_badge}</h4>
        <p>{description}</p>
        {location_info}
        {triage_info}
        {recommendation_info}
        {rule_info}
        <p><strong>Scanner:</strong> {scanner}</p>
    </div>"""

    def _generate_dependencies_section(self, dependencies: List[Dict[str, Any]]) -> str:
        """Generate dependencies section."""
        if not dependencies:
            return '<h2>No Dependencies Found</h2>'

        rows = []
        for dep in dependencies:
            # Escape all dependency data
            name = html.escape(dep.get('name', 'Unknown'))
            dep_type = html.escape(dep.get('type', 'Unknown'))
            depth = html.escape(str(dep.get('depth', 0)))
            findings_count = html.escape(str(dep.get('findings_count', 0)))

            rows.append(f"""
        <tr>
            <td>{name}</td>
            <td>{dep_type}</td>
            <td>{depth}</td>
            <td>{findings_count}</td>
        </tr>""")

        return f"""
    <h2>Dependencies</h2>
    <table>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Depth</th>
            <th>Findings</th>
        </tr>
        {''.join(rows)}
    </table>"""

    def _generate_footer(self) -> str:
        """Generate HTML footer."""
        return """
    <div class="footer">
        <p>Generated by ActChain - GitHub Actions Workflow Security Scanner</p>
    </div>
</body>
</html>"""

    def _group_findings_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by severity level."""
        groups = {'critical': [], 'high': [], 'medium': [], 'low': []}

        for finding in findings:
            severity = str(finding.get('severity', 'low')).lower()
            if severity not in groups:
                # Never silently drop a finding with an unexpected severity
                # string; show it with the lowest severity instead.
                severity = 'low'
            groups[severity].append(finding)

        return groups

    def _create_error_html(self, html_path: str, error_message: str) -> str:
        """Create a simple error HTML page."""
        try:
            # Escape the error message to prevent XSS
            escaped_error_message = html.escape(error_message)

            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ActChain Report Error</title>
</head>
<body>
    <h1>Error Generating Report</h1>
    <p>There was an error converting the JSON report to HTML: {escaped_error_message}</p>
</body>
</html>"""

            if FileUtils.safe_write_file(html_content, html_path):
                return html_path
        except Exception:
            pass

        return None

    def _get_css_styles(self) -> str:
        """Get CSS styles for the HTML report."""
        return """
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3, h4 {
            color: #0366d6;
            margin-top: 24px;
            margin-bottom: 16px;
        }
        .header {
            border-bottom: 1px solid #eaecef;
            padding-bottom: 16px;
            margin-bottom: 16px;
        }
        .header p {
            margin: 4px 0;
            color: #586069;
        }
        .header h1 {
            margin-bottom: 8px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }
        .summary-card {
            border: 1px solid #e1e4e8;
            border-radius: 6px;
            padding: 16px;
            background-color: #f6f8fa;
        }
        .summary-card h3 {
            margin-top: 0;
            border-bottom: 1px solid #eaecef;
            padding-bottom: 8px;
        }
        .severity-bar {
            display: flex;
            margin-top: 16px;
            border-radius: 4px;
            overflow: hidden;
            height: 8px;
        }
        .severity-critical { background-color: #e53e3e; }
        .severity-high { background-color: #dd6b20; }
        .severity-medium { background-color: #d69e2e; }
        .severity-low { background-color: #38a169; }
        .finding {
            padding: 16px;
            margin-bottom: 16px;
            border-radius: 6px;
            border-left: 4px solid #0366d6;
        }
        .finding.critical {
            border-left-color: #e53e3e;
            background-color: #fff5f5;
        }
        .finding.high {
            border-left-color: #dd6b20;
            background-color: #fffaf0;
        }
        .finding.medium {
            border-left-color: #d69e2e;
            background-color: #fffff0;
        }
        .finding.low {
            border-left-color: #38a169;
            background-color: #f0fff4;
        }
        .finding-title {
            font-weight: 600;
            margin: 0 0 8px 0;
        }
        .finding-location {
            font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, monospace;
            font-size: 0.85em;
            background-color: rgba(27, 31, 35, 0.05);
            padding: 4px 6px;
            border-radius: 3px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
        }
        th, td {
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid #e1e4e8;
        }
        th {
            background-color: #f6f8fa;
            font-weight: 600;
        }
        .footer {
            margin-top: 40px;
            padding-top: 16px;
            border-top: 1px solid #eaecef;
            color: #586069;
            font-size: 0.9em;
            text-align: center;
        }
        .badge {
            display: inline-block;
            padding: 3px 6px;
            font-size: 0.75em;
            font-weight: 600;
            border-radius: 3px;
            margin-left: 4px;
            color: white;
        }
        .badge.critical { background-color: #e53e3e; }
        .badge.high { background-color: #dd6b20; }
        .badge.medium { background-color: #d69e2e; }
        .badge.low { background-color: #38a169; }
        .badge.malicious { background-color: #742a2a; }
        .malicious-banner {
            border: 2px solid #e53e3e;
            border-radius: 6px;
            background-color: #fff5f5;
            padding: 16px;
            margin-bottom: 24px;
        }
        .malicious-banner h2 {
            color: #c53030;
            margin-top: 0;
        }
        .gate-passed { color: #2f855a; font-weight: 700; }
        .gate-blocked { color: #c05621; font-weight: 700; }"""


def convert_json_to_html(json_path: str) -> Optional[str]:
    """
    Convenience function to convert JSON report to HTML.

    Args:
        json_path: Path to the JSON report

    Returns:
        Path to the generated HTML report or None if failed
    """
    generator = HTMLReportGenerator()
    return generator.convert_json_to_html(json_path)
