# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

from actchain.reports.html_converter import HTMLReportGenerator

XSS = "<script>alert('pwned')</script>"


def make_report(findings):
    return {
        "meta": {"timestamp": "2026-01-01T00:00:00", "scan_id": "scan_x"},
        "workflow": {"name": f"wf{XSS}.yml", "path": f".github/workflows/{XSS}.yml"},
        "findings": findings,
        "dependencies": [
            {"name": f"evil/{XSS}@v1", "type": "composite", "depth": 1, "findings_count": 2}
        ],
        "statistics": {
            "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "total": 1},
            "dependency_counts": {"total": 1, "by_depth": {"1": 1}},
            "scanner_counts": {f"Scanner{XSS}": 1},
        },
    }


class TestXssEscaping:
    def test_untrusted_content_is_escaped_everywhere(self):
        findings = [{
            "title": f"Injection {XSS}",
            "severity": "high",
            "description": f"desc {XSS}",
            "recommendation": f"rec {XSS}",
            "rule_id": f"rule-{XSS}",
            "source_scanner": f"scanner {XSS}",
            "location": {"path": f"path/{XSS}.yml", "line": 1, "column": 2},
        }]
        html = HTMLReportGenerator()._generate_html_content(make_report(findings))
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_unknown_severity_is_rendered_not_dropped(self):
        findings = [{
            "title": "Odd finding",
            "severity": "bogus-severity",
            "description": "something",
            "location": {"path": "wf.yml", "line": 1, "column": 1},
        }]
        html = HTMLReportGenerator()._generate_html_content(make_report(findings))
        assert "Odd finding" in html

    def test_empty_findings_section(self):
        html = HTMLReportGenerator()._generate_html_content(make_report([]))
        assert "No Security Findings" in html


class TestV2Sections:
    def _full_report(self):
        report = make_report([{
            "title": "Exfil to pastebin",
            "severity": "critical",
            "malicious": True,
            "action_ref": "evil/action@v1",
            "source_scanner": "AI Audit (Claude)",
            "description": "sends secrets out",
            "ai_triage": {"verdict": "confirmed", "rationale": "real exfiltration"},
            "location": {"path": "action_evil/action@v1", "line": 0, "column": 0},
        }])
        report["gate"] = {
            "evaluated": True, "passed": False, "threshold": "high",
            "reasons": [f"blocked because {XSS}"],
            "blocking_findings_count": 1,
            "excluded_findings": 2,
            "pin_plan": {
                "files_changed": 1, "entries_total": 1, "skipped_total": 0,
                "entries": [{"workflow": ".github/workflows/ci.yml", "line": 3,
                             "action": f"evil/{XSS}", "old_ref": "v1", "new_sha": "a" * 40}],
                "skipped": [],
            },
        }
        report["ai"] = {
            "enabled": True, "model": "claude-opus-5-5", "calls": 4,
            "triage": {"findings_triaged": 1, "verdict_counts": {"confirmed": 1}},
            "audit_coverage": {"audited": 5, "truncated": 1, "skipped_cap": 0,
                               "skipped_namespace": 2},
        }
        return report

    def test_malicious_banner_rendered_first_and_escaped(self):
        html = HTMLReportGenerator()._generate_html_content(self._full_report())
        assert "Malicious behavior detected" in html
        assert html.index("Malicious behavior detected") < html.index("Security Findings")
        assert "MALICIOUS" in html  # badge on the finding itself
        assert "<script>" not in html

    def test_gate_section_with_pin_plan(self):
        html = HTMLReportGenerator()._generate_html_content(self._full_report())
        assert "Pinning Policy Gate" in html
        assert "BLOCKED" in html
        assert "1 reference(s) to pin" in html
        assert "a" * 40 not in html  # SHA shown truncated
        assert ("a" * 12) in html
        assert "&lt;script&gt;" in html  # reasons/plan cells escaped

    def test_ai_section_and_triage_annotation(self):
        html = HTMLReportGenerator()._generate_html_content(self._full_report())
        assert "AI Analysis" in html
        assert "claude-opus-5-5" in html
        assert "AI triage:" in html
        assert "real exfiltration" in html

    def test_sections_absent_without_data(self):
        html = HTMLReportGenerator()._generate_html_content(make_report([]))
        assert "Pinning Policy Gate" not in html
        assert "Malicious behavior detected" not in html
        assert "AI Analysis" not in html
