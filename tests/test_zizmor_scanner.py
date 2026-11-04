# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

import subprocess
from types import SimpleNamespace

import pytest

from actchain.scanners.base import BaseScanner, ScannerError
from actchain.scanners.zizmor import ZizmorScanner

SAMPLE_OUTPUT = """\
error[template-injection]: code injection via template expansion
  --> /tmp/actchain_abc/workflow.yml:10:9

warning[artipacked]: credential persistence through GitHub Actions artifacts
  --> /tmp/actchain_abc/workflow.yml:20:3

note[unpinned-uses]: unpinned action reference marked high priority
  --> /tmp/actchain_abc/workflow.yml:30:1
"""


def make_scanner(min_severity="low"):
    scanner = ZizmorScanner.__new__(ZizmorScanner)
    BaseScanner.__init__(scanner, min_severity)
    scanner.scanner_name = "Zizmor Scanner"
    scanner._zizmor_path = "/fake/zizmor"
    return scanner


class TestParseOutput:
    def test_parses_findings_with_locations(self):
        findings = make_scanner()._parse_zizmor_output(SAMPLE_OUTPUT, "real/workflow.yml")
        assert len(findings) == 3
        assert findings[0]["rule_id"] == "template-injection"
        assert findings[0]["severity"] == "high"
        assert findings[0]["location"]["line"] == 10
        # The scan runs on a temp copy; the report must show the real path
        # (temp paths would leak the local username).
        assert all(f["location"]["path"] == "real/workflow.yml" for f in findings)

    def test_severity_comes_from_type_not_message(self):
        # The message quotes scanned (attacker-influenced) content; the word
        # "high" inside it must not escalate the severity.
        findings = make_scanner()._parse_zizmor_output(SAMPLE_OUTPUT, "wf.yml")
        note = [f for f in findings if f["rule_id"] == "unpinned-uses"][0]
        assert note["severity"] == "low"

    def test_min_severity_filter(self):
        findings = make_scanner(min_severity="high")._parse_zizmor_output(SAMPLE_OUTPUT, "wf.yml")
        assert [f["severity"] for f in findings] == ["high"]

    def test_empty_output(self):
        assert make_scanner()._parse_zizmor_output("", "wf.yml") == []

    def test_echoed_snippet_content_cannot_forge_findings(self):
        # Zizmor's plain output echoes lines of the scanned (untrusted) file
        # inside gutter-prefixed snippets; such content must not be parsed
        # as additional findings.
        output = (
            "warning[artipacked]: credential persistence\n"
            "  --> workflow.yml:5:3\n"
            "   |\n"
            " 5 |   run: echo 'error[forged-rule]: attacker controlled text'\n"
            "   |\n"
        )
        findings = make_scanner()._parse_zizmor_output(output, "wf.yml")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "artipacked"

    def test_windows_paths_in_locations_parse(self):
        output = (
            "error[template-injection]: code injection\n"
            "  --> C:\\Users\\dev\\AppData\\Local\\Temp\\actchain_x\\workflow.yml:12:7\n"
        )
        findings = make_scanner()._parse_zizmor_output(output, "wf.yml")
        assert findings[0]["location"]["line"] == 12
        assert findings[0]["location"]["column"] == 7
        assert findings[0]["location"]["path"] == "wf.yml"


class TestRunScan:
    def test_error_exit_with_no_output_raises(self, monkeypatch):
        scanner = make_scanner()

        def fake_run(*args, **kwargs):
            return SimpleNamespace(returncode=2, stdout="", stderr="fatal: bad flag")

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(ScannerError, match="exited with code 2"):
            scanner._run_zizmor_scan("/tmp/x.yml", "wf.yml")

    def test_findings_exit_code_is_not_an_error(self, monkeypatch):
        scanner = make_scanner()

        def fake_run(*args, **kwargs):
            return SimpleNamespace(returncode=14, stdout=SAMPLE_OUTPUT, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        findings = scanner._run_zizmor_scan("/tmp/x.yml", "wf.yml")
        assert len(findings) == 3

    def test_timeout_raises(self, monkeypatch):
        scanner = make_scanner()

        def fake_run(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="zizmor", timeout=1)

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(ScannerError, match="timed out"):
            scanner._run_zizmor_scan("/tmp/x.yml", "wf.yml")

    def test_scan_workflow_surfaces_errors_in_report(self, monkeypatch):
        # Scanner failures must fail closed (an error report), never read as
        # a clean scan with zero findings.
        scanner = make_scanner()

        def fake_run(*args, **kwargs):
            return SimpleNamespace(returncode=2, stdout="", stderr="boom")

        monkeypatch.setattr(subprocess, "run", fake_run)
        report = scanner.scan_workflow("on: push", "wf.yml")
        assert "error" in report["results"]

    def test_scan_action_uses_action_yml_and_raw_content(self, monkeypatch):
        # Zizmor only audits files named action.yml/action.yaml as actions.
        scanner = make_scanner()
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["file"] = cmd[-1]
            from pathlib import Path
            seen["content"] = Path(cmd[-1]).read_text(encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        action_data = {
            "ref": "a/b@v1",
            "type": "composite",
            "content": {"parsed": True},
            "raw_content": "name: original text\nruns:\n  using: composite\n",
        }
        report = scanner.scan_action(action_data)
        assert seen["file"].endswith("action.yml")
        assert seen["content"].startswith("name: original text")
        assert "error" not in report["results"]
