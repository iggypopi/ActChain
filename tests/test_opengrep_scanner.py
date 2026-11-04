# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

import json

from actchain.scanners.base import BaseScanner
from actchain.scanners.opengrep import OpenGrepScanner


def make_scanner(min_severity="low"):
    scanner = OpenGrepScanner.__new__(OpenGrepScanner)
    BaseScanner.__init__(scanner, min_severity)
    scanner.scanner_name = "OpenGrep Scanner"
    scanner._opengrep_path = "/fake/opengrep"
    return scanner


SAMPLE_JSON = json.dumps({
    "results": [
        {
            "check_id": "yaml.github-actions.security.run-shell-injection",
            "path": "/tmp/actchain_xyz/.github/workflows/workflow.yml",
            "start": {"line": 12, "col": 9},
            "extra": {"message": "Possible shell injection", "severity": "ERROR"},
        },
        {
            "check_id": "yaml.github-actions.security.unpinned-action",
            "path": "/tmp/actchain_xyz/.github/workflows/workflow.yml",
            "start": {"line": 20, "col": 7},
            "extra": {"message": "Unpinned action", "severity": "INFO"},
        },
    ]
})


class TestParseJsonOutput:
    def test_parses_findings(self):
        findings = make_scanner()._parse_opengrep_output(SAMPLE_JSON, "wf.yml")
        assert len(findings) == 2
        assert findings[0]["rule_id"] == "run-shell-injection"
        assert findings[0]["severity"] == "high"
        assert findings[0]["location"]["line"] == 12

    def test_temp_paths_never_leak_into_findings(self):
        # Temp paths contain the local username; reports must show the
        # original workflow path instead.
        findings = make_scanner()._parse_opengrep_output(SAMPLE_JSON, "wf.yml")
        assert all(f["location"]["path"] == "wf.yml" for f in findings)

    def test_min_severity_filter(self):
        findings = make_scanner(min_severity="high")._parse_opengrep_output(SAMPLE_JSON, "wf.yml")
        assert len(findings) == 1

    def test_severity_mapping(self):
        scanner = make_scanner()
        assert scanner._map_opengrep_severity("ERROR") == "high"
        assert scanner._map_opengrep_severity("WARNING") == "medium"
        assert scanner._map_opengrep_severity("INFO") == "low"
        assert scanner._map_opengrep_severity("WEIRD") == "medium"


class TestRunScan:
    def test_fatal_exit_raises_even_with_json_output(self, monkeypatch):
        # A fatal opengrep error that still prints JSON must surface as an
        # error, never as a clean scan.
        import subprocess
        from types import SimpleNamespace

        import pytest

        from actchain.scanners.base import ScannerError

        scanner = make_scanner()

        def fake_run(*args, **kwargs):
            return SimpleNamespace(
                returncode=2,
                stdout='{"results": [], "errors": [{"message": "config error"}]}',
                stderr="fatal: could not load config",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(ScannerError, match="exited with code 2"):
            scanner._run_opengrep_scan("/tmp/x.yml", "wf.yml")


class TestFallbackPatternScan:
    def test_detects_unpinned_actions(self):
        content = "steps:\n  - uses: actions/checkout@v4\n"
        findings = make_scanner()._fallback_pattern_scan(content, "wf.yml")
        assert any(f["rule_id"] == "unpinned-github-action" for f in findings)

    def test_detects_write_all_permissions(self):
        findings = make_scanner()._fallback_pattern_scan("permissions: write-all\n", "wf.yml")
        assert any(f["rule_id"] == "excessive-permissions" for f in findings)

    def test_sha_pinned_action_not_flagged(self):
        content = "steps:\n  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
        findings = make_scanner()._fallback_pattern_scan(content, "wf.yml")
        assert not any(f["rule_id"] == "unpinned-github-action" for f in findings)
