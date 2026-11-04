# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""Tests for the PDF report converter.

Report content is asserted through PDFReportGenerator's documented test
seam: every logical line written into the PDF body is also collected in
``generator.rendered_lines``, so tests check content without parsing the
PDF binary (no PDF text-extraction library is required).
"""

import json
import logging

from actchain.reports import pdf_converter
from actchain.reports.pdf_converter import PDFReportGenerator, convert_json_to_pdf


def make_finding(index=1, severity="high", **overrides):
    finding = {
        "finding_id": f"f-{index:04d}",
        "rule_id": "unpinned-uses",
        "title": f"Finding {index}",
        "severity": severity,
        "description": f"Description for finding {index}.",
        "recommendation": "Pin the action to a full commit SHA.",
        "location": {"path": ".github/workflows/ci.yml", "line": index, "column": 1},
        "source_scanner": "zizmor",
    }
    finding.update(overrides)
    return finding


def make_report(findings=None, dependencies=None, **extra):
    findings = findings if findings is not None else [make_finding()]
    dependencies = dependencies if dependencies is not None else [
        {"name": "actions/checkout@v4", "type": "action", "depth": 1, "findings_count": 0},
    ]
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity", "low")).lower()
        if severity not in severity_counts:
            severity = "low"
        severity_counts[severity] += 1
    severity_counts["total"] = len(findings)
    report = {
        "meta": {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "scan_id": "scan_20260101_abcd1234",
            "report_version": "1.1",
            "total_reports": 3,
        },
        "workflow": {"name": "ci.yml", "path": ".github/workflows/ci.yml"},
        "findings": findings,
        "dependencies": dependencies,
        "statistics": {
            "severity_counts": severity_counts,
            "dependency_counts": {"total": len(dependencies), "by_depth": {"1": len(dependencies)}},
            "scanner_counts": {"zizmor": len(findings)},
        },
    }
    report.update(extra)
    return report


def write_report(tmp_path, report):
    json_path = tmp_path / "consolidated_report.json"
    json_path.write_text(json.dumps(report), encoding="utf-8")
    return str(json_path)


def generate(tmp_path, report):
    """Generate a PDF for ``report`` and return (generator, pdf_path)."""
    generator = PDFReportGenerator()
    pdf_path = generator.convert_json_to_pdf(write_report(tmp_path, report))
    return generator, pdf_path


def pdf_bytes(pdf_path):
    with open(pdf_path, "rb") as handle:
        return handle.read()


class TestPdfGeneration:
    def test_full_report_produces_pdf(self, tmp_path):
        findings = [
            make_finding(1, "critical", malicious=True),
            make_finding(2, "critical", ai_triage={"verdict": "confirmed", "rationale": "Real."}),
            make_finding(3, "high"),
            make_finding(4, "medium"),
            make_finding(5, "low"),
        ]
        report = make_report(
            findings=findings,
            gate={"evaluated": True, "passed": False, "threshold": "high",
                  "reasons": ["high findings present"], "blocking_findings_count": 3},
            ai={"enabled": True, "model": "claude-opus-5-5", "calls": 4},
            pr_url=None,
        )
        json_path = write_report(tmp_path, report)

        pdf_path = convert_json_to_pdf(json_path)

        assert pdf_path is not None
        assert pdf_path.endswith("consolidated_report.pdf")
        assert pdf_bytes(pdf_path).startswith(b"%PDF")

    def test_empty_report_object_still_renders(self, tmp_path):
        generator, pdf_path = generate(tmp_path, {})

        assert pdf_path is not None
        assert pdf_bytes(pdf_path).startswith(b"%PDF")
        lines = generator.rendered_lines
        assert "ActChain Security Report" in lines
        assert "No security findings." in lines
        assert "AI analysis: not enabled" in lines
        assert "No dependencies recorded." in lines

    def test_missing_optional_sections_do_not_crash(self, tmp_path):
        report = make_report(findings=[], dependencies=[])
        report.pop("workflow")
        report["statistics"] = {}

        generator, pdf_path = generate(tmp_path, report)

        assert pdf_path is not None
        joined = "\n".join(generator.rendered_lines)
        assert "MALICIOUS BEHAVIOR DETECTED" not in joined
        assert "Pinning Gate" not in joined
        assert "AI analysis: not enabled" in joined


class TestSummaryPage:
    def test_severity_table_counts(self, tmp_path):
        findings = [make_finding(1, "critical"), make_finding(2, "high"), make_finding(3, "high")]
        generator, pdf_path = generate(tmp_path, make_report(findings=findings))

        assert pdf_path is not None
        lines = generator.rendered_lines
        assert "Severity | Count" in lines
        assert "Critical | 1" in lines
        assert "High | 2" in lines
        assert "Total | 3" in lines

    def test_scanners_and_ai_enabled_line(self, tmp_path):
        report = make_report(ai={"enabled": True, "model": "claude-opus-5-5", "calls": 4})
        generator, _ = generate(tmp_path, report)

        lines = generator.rendered_lines
        assert "- zizmor: 1 finding(s)" in lines
        assert "AI analysis: claude-opus-5-5, 4 calls" in lines

    def test_gate_passed_verdict(self, tmp_path):
        report = make_report(gate={"evaluated": True, "passed": True, "threshold": "high", "reasons": []})
        generator, _ = generate(tmp_path, report)

        assert "PASSED (threshold: high)" in generator.rendered_lines

    def test_gate_blocked_reasons_capped_at_five(self, tmp_path):
        reasons = [f"reason-{index}" for index in range(1, 8)]
        report = make_report(gate={"evaluated": True, "passed": False, "threshold": "medium",
                                   "reasons": reasons, "blocking_findings_count": 7})
        generator, _ = generate(tmp_path, report)

        lines = generator.rendered_lines
        joined = "\n".join(lines)
        assert "BLOCKED (threshold: medium) - 7 blocking finding(s)" in lines
        for index in range(1, 6):
            assert f"- reason-{index}" in lines
        assert "reason-6" not in joined
        assert "reason-7" not in joined
        assert "... and 2 more reason(s) - see the JSON report." in lines


class TestMaliciousBanner:
    def test_banner_lists_titles_and_paths(self, tmp_path):
        findings = [
            make_finding(1, "critical", malicious=True, title="Evil exfiltration",
                         location={"path": "actions/evil/action.yml", "line": 9, "column": 1}),
            make_finding(2, "high", malicious=True, title="Curl pipe bash"),
            make_finding(3, "critical"),
        ]
        generator, pdf_path = generate(tmp_path, make_report(findings=findings))

        assert pdf_path is not None
        lines = generator.rendered_lines
        assert "MALICIOUS BEHAVIOR DETECTED - 2 finding(s)" in lines
        assert "- Evil exfiltration (actions/evil/action.yml)" in lines
        assert "- Curl pipe bash (.github/workflows/ci.yml)" in lines
        # The banner belongs to the summary page, before the findings section.
        assert lines.index("MALICIOUS BEHAVIOR DETECTED - 2 finding(s)") < lines.index("Findings")

    def test_malicious_findings_render_first_and_in_full(self, tmp_path):
        findings = [
            make_finding(1, "critical"),
            make_finding(2, "low", malicious=True, title="Hidden backdoor"),
        ]
        generator, _ = generate(tmp_path, make_report(findings=findings))

        lines = generator.rendered_lines
        assert lines.index("Malicious Findings (1)") < lines.index("Critical Severity (1)")
        assert "[LOW] Hidden backdoor" in lines
        assert "Description for finding 2." in lines


class TestFindingDetail:
    def test_full_detail_for_critical_with_ai_triage(self, tmp_path):
        finding = make_finding(3, "critical",
                               ai_triage={"verdict": "confirmed", "rationale": "Reachable from a fork PR."})
        generator, _ = generate(tmp_path, make_report(findings=[finding]))

        lines = generator.rendered_lines
        assert "[CRITICAL] Finding 3" in lines
        assert "Location: .github/workflows/ci.yml:3" in lines
        assert "Scanner: zizmor" in lines
        assert "AI triage: confirmed - Reachable from a fork PR." in lines
        assert "Description for finding 3." in lines
        assert "Recommendation: Pin the action to a full commit SHA." in lines

    def test_unknown_severity_treated_as_low(self, tmp_path):
        finding = make_finding(1, "bogus-severity", title="Odd finding")
        generator, pdf_path = generate(tmp_path, make_report(findings=[finding]))

        assert pdf_path is not None
        lines = generator.rendered_lines
        assert "Low Severity (1)" in lines
        assert any(line.startswith("- Odd finding") for line in lines)


class TestCaps:
    def test_medium_findings_capped_at_25(self, tmp_path):
        findings = [make_finding(index, "medium") for index in range(1, 27)]
        generator, pdf_path = generate(tmp_path, make_report(findings=findings))

        assert pdf_path is not None
        lines = generator.rendered_lines
        joined = "\n".join(lines)
        assert "... and 1 more medium findings - see the JSON report." in lines
        assert sum(1 for line in lines if line.startswith("- Finding ")) == 25
        assert "Finding 26" not in joined

    def test_low_findings_capped_at_25(self, tmp_path):
        findings = [make_finding(index, "low") for index in range(1, 31)]
        generator, _ = generate(tmp_path, make_report(findings=findings))

        assert "... and 5 more low findings - see the JSON report." in generator.rendered_lines

    def test_dependency_table_capped_at_50(self, tmp_path):
        dependencies = [
            {"name": f"owner/dep-{index:03d}@v1", "type": "action", "depth": 1, "findings_count": 0}
            for index in range(1, 61)
        ]
        generator, pdf_path = generate(tmp_path, make_report(dependencies=dependencies))

        assert pdf_path is not None
        joined = "\n".join(generator.rendered_lines)
        assert "... and 10 more dependencies - see the JSON report." in generator.rendered_lines
        assert "dep-050" in joined
        assert "dep-051" not in joined


class TestHostileText:
    def test_control_and_bidi_chars_are_stripped(self, tmp_path):
        finding = make_finding(
            1, "critical",
            title="Bad\x07Title\x1b[31m ‮evil",
            description="desc\x00with\x08controls",
            location={"path": "wf\x1b.yml", "line": 1, "column": 1},
        )
        dependencies = [{"name": "evil\x07/dep@v1", "type": "action", "depth": 1, "findings_count": 0}]
        generator, pdf_path = generate(tmp_path, make_report(findings=[finding],
                                                             dependencies=dependencies))

        assert pdf_path is not None
        assert pdf_bytes(pdf_path).startswith(b"%PDF")
        joined = "\n".join(generator.rendered_lines)
        for forbidden in ("\x00", "\x07", "\x08", "\x1b", "‮"):
            assert forbidden not in joined
        assert "BadTitle" in joined

    def test_huge_markup_and_unicode_text_does_not_crash(self, tmp_path):
        finding = make_finding(
            1, "high",
            title="<script>alert('x')</script> \U0001f525 漢字 title",
            description="A" * 10000,
            recommendation="おすすめ " + "B" * 5000,
        )
        dependencies = [{"name": "漢字/\U0001f525-action@v1" + "C" * 200,
                         "type": "composite", "depth": 2, "findings_count": 1}]
        generator, pdf_path = generate(tmp_path, make_report(findings=[finding],
                                                             dependencies=dependencies))

        assert pdf_path is not None
        assert pdf_bytes(pdf_path).startswith(b"%PDF")
        lines = generator.rendered_lines
        joined = "\n".join(lines)
        # Truncated to the 800-char description cap, then rendered as-is.
        assert any(line == "A" * 800 for line in lines)
        assert "A" * 801 not in joined
        # Non-latin-1 characters are replaced, never crash generation.
        assert "\U0001f525" not in joined
        assert "漢" not in joined

    def test_garbage_shaped_data_is_tolerated(self, tmp_path):
        report = make_report(findings=["not-a-dict", make_finding(1, "high", location="nope")],
                             dependencies=["also-not-a-dict"])
        report["statistics"] = "garbage"
        report["gate"] = "garbage"
        report["ai"] = ["garbage"]

        generator, pdf_path = generate(tmp_path, report)

        assert pdf_path is not None
        lines = generator.rendered_lines
        assert "[HIGH] Finding 1" in lines
        assert not any(line.startswith("Location:") for line in lines)


class TestFailureModes:
    def test_returns_none_for_unreadable_file(self, tmp_path):
        assert convert_json_to_pdf(str(tmp_path / "missing.json")) is None

    def test_returns_none_for_invalid_json(self, tmp_path):
        json_path = tmp_path / "broken.json"
        json_path.write_text("not json {{{", encoding="utf-8")

        assert convert_json_to_pdf(str(json_path)) is None
        assert not (tmp_path / "broken.pdf").exists()

    def test_returns_none_for_non_object_json(self, tmp_path):
        json_path = tmp_path / "list.json"
        json_path.write_text("[1, 2, 3]", encoding="utf-8")

        assert convert_json_to_pdf(str(json_path)) is None

    def test_missing_fpdf2_returns_none_with_hint(self, tmp_path, monkeypatch, caplog):
        def raise_import_error():
            raise ImportError("No module named 'fpdf'")

        monkeypatch.setattr(pdf_converter, "_import_fpdf", raise_import_error)
        json_path = write_report(tmp_path, make_report())

        with caplog.at_level(logging.ERROR, logger="actchain.reports.pdf_converter"):
            result = convert_json_to_pdf(json_path)

        assert result is None
        assert not (tmp_path / "consolidated_report.pdf").exists()
        assert 'pip install "actchain[pdf]"' in caplog.text
