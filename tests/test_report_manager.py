# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

import json
import re

import pytest

from actchain.reports.manager import ReportManager


@pytest.fixture
def manager(tmp_path):
    return ReportManager(str(tmp_path / "reports"))


class TestDotGeneration:
    def test_labels_are_escaped(self, manager):
        # Action refs come from untrusted workflows: a crafted ref must not
        # break out of the DOT string literal and inject attributes/statements.
        hostile = 'evil/repo@v1"]; node [image="/etc/passwd'
        dot = manager._generate_dot_content({hostile, "actions/checkout@v4"})

        for line in dot.splitlines():
            if "label=" in line:
                unescaped_quotes = re.findall(r'(?<!\\)"', line)
                assert len(unescaped_quotes) == 4  # two balanced string literals

    def test_control_chars_stripped_from_labels(self, manager):
        dot = manager._generate_dot_content({"evil/repo\x1b[31m@v1"})
        assert "\x1b" not in dot


class TestSaveReport:
    def test_collisions_do_not_overwrite(self, manager):
        # Distinct raw names can sanitize to the same filename.
        first = manager.save_report({"a": 1}, "action_a/b@v1")
        second = manager.save_report({"b": 2}, "action_a\\b@v1")
        assert first != second
        assert json.loads(open(first, encoding="utf-8").read()) == {"a": 1}
        assert json.loads(open(second, encoding="utf-8").read()) == {"b": 2}


class TestWorkflowTree:
    def test_trees_are_saved_per_workflow(self, manager):
        # Multi-workflow scans must not overwrite each other's trees.
        path_a = manager.save_workflow_tree("tree a", "workflow_tree_ci")
        path_b = manager.save_workflow_tree("tree b", "workflow_tree_release")
        assert path_a != path_b
        assert open(path_a, encoding="utf-8").read() == "tree a"
        assert open(path_b, encoding="utf-8").read() == "tree b"

    def test_tree_name_collisions_do_not_overwrite(self, manager):
        # Workflow names that sanitize to the same filename must not clobber
        # each other.
        path_a = manager.save_workflow_tree("tree a", "workflow_tree_a/b")
        path_b = manager.save_workflow_tree("tree b", "workflow_tree_a\\b")
        assert path_a != path_b
        assert open(path_a, encoding="utf-8").read() == "tree a"
        assert open(path_b, encoding="utf-8").read() == "tree b"


class TestConsolidatedReport:
    def _generate(self, manager, findings, **kwargs):
        defaults = dict(
            findings=findings,
            dependencies=[{"name": "a/b@v1", "type": "composite", "depth": 0, "findings_count": 1}],
            action_count_by_depth={0: 1},
            workflow={"name": "ci.yml", "path": ".github/workflows/ci.yml"},
        )
        defaults.update(kwargs)
        path = manager.generate_consolidated_report(**defaults)
        return json.loads(open(path, encoding="utf-8").read())

    def test_findings_are_the_single_source_of_truth(self, manager):
        # AI triage annotations written onto the finding dicts must reach the
        # consolidated report (R4 regression guard).
        findings = [{
            "finding_id": "f-0001", "title": "x", "severity": "high",
            "source_scanner": "OpenGrep Scanner",
            "ai_triage": {"verdict": "confirmed", "rationale": "real issue"},
        }]
        data = self._generate(
            manager, findings,
            gate={"evaluated": True, "passed": False, "threshold": "high", "reasons": ["why"]},
            ai={"enabled": True, "model": "claude-opus-5-5", "calls": 2},
        )
        assert data["findings"][0]["source_scanner"] == "OpenGrep Scanner"
        assert data["findings"][0]["ai_triage"]["verdict"] == "confirmed"
        assert data["gate"]["passed"] is False
        assert data["ai"]["model"] == "claude-opus-5-5"
        assert data["dependencies"][0]["name"] == "a/b@v1"
        assert data["statistics"]["dependency_counts"]["total"] == 1
        assert data["statistics"]["scanner_counts"]["OpenGrep Scanner"] == 1
        assert data["meta"]["report_version"] == "1.1"

    def test_unknown_severity_counts_as_low(self, manager):
        data = self._generate(manager, [{"title": "x", "severity": "weird",
                                         "source_scanner": "Zizmor Scanner"}])
        stats = data["statistics"]["severity_counts"]
        assert stats["low"] == 1
        assert stats["total"] == 1

    def test_malicious_findings_sort_first(self, manager):
        findings = [
            {"title": "critical thing", "severity": "critical", "source_scanner": "s"},
            {"title": "bad actor", "severity": "medium", "malicious": True, "source_scanner": "s"},
        ]
        data = self._generate(manager, findings)
        assert data["findings"][0]["title"] == "bad actor"
