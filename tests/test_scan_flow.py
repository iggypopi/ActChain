# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Characterization tests for the end-to-end scan flow.

These pin the externally observable behavior of `ActChainDisplay.run_scan`
(consolidated report content, saved report names, error isolation) with a
mocked GitHub client and stub scanners, so the pipeline refactor can be
verified against the exact behavior of the previous implementation.
"""

import json
from pathlib import Path

import click
import pytest

import actchain.cli.display as display_module
from actchain.cli.display import ActChainDisplay
from actchain.core.github_client import GitHubClientError
from actchain.scanners.base import BaseScanner

GOOD_WORKFLOW = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: octo/composite@v1
      - run: echo hello
"""

BROKEN_WORKFLOW = """
name: Not a workflow
jobs:
  a:
    steps: []
"""

COMPOSITE_ACTION = {
    "name": "composite",
    "runs": {
        "using": "composite",
        "steps": [{"uses": "nested/action@v2"}],
    },
}

LEAF_ACTION = {
    "name": "leaf",
    "runs": {"using": "node20", "main": "index.js"},
}


class StubGitHubClient:
    """Offline GitHubClient double."""

    workflows = [
        {"name": "ci.yml", "path": ".github/workflows/ci.yml"},
        {"name": "broken.yml", "path": ".github/workflows/broken.yml"},
    ]

    contents = {
        ".github/workflows/ci.yml": GOOD_WORKFLOW,
        ".github/workflows/broken.yml": BROKEN_WORKFLOW,
    }

    def __init__(self, token, repo_name):
        if not token:
            raise GitHubClientError("GitHub token is required")
        self.repo_name = repo_name

    def get_workflows(self):
        return list(self.workflows)

    def get_file_content(self, path):
        try:
            return self.contents[path]
        except KeyError:
            raise GitHubClientError(f"not found: {path}")

    def get_file_content_optional(self, repo_name, path, ref="main"):
        return None

    def get_action_content(self, action_ref):
        base = action_ref.split("@")[0]
        if base == "octo/composite":
            return {"ref": action_ref, "type": "composite", "content": COMPOSITE_ACTION,
                    "raw_content": "name: composite\n"}
        if base in ("actions/checkout", "nested/action"):
            return {"ref": action_ref, "type": "javascript", "content": LEAF_ACTION,
                    "raw_content": "name: leaf\n"}
        return None


class StubScanner(BaseScanner):
    """Deterministic scanner: one medium finding per workflow, one per action."""

    def __init__(self, min_severity="low"):
        super().__init__(min_severity)
        self.scanner_name = "Stub Scanner"

    def scan_workflow(self, content, path):
        report = self.create_base_report(self.generate_scan_id(), path)
        report["results"]["findings"] = [{
            "rule_id": "stub-workflow-rule",
            "title": "stub workflow finding",
            "severity": "medium",
            "description": "workflow finding",
            "location": {"path": path, "line": 1, "column": 1},
            "recommendation": "none",
        }]
        return report

    def scan_action(self, action_data):
        ref = action_data.get("ref", "unknown")
        report = self.create_base_report(self.generate_scan_id(), f"action_{ref}")
        report["action"] = ref
        report["type"] = action_data.get("type", "unknown")
        report["results"]["findings"] = [{
            "rule_id": "stub-action-rule",
            "title": f"stub action finding for {ref}",
            "severity": "low",
            "description": "action finding",
            "location": {"path": f"action_{ref}", "line": 1, "column": 1},
            "recommendation": "none",
        }]
        return report


class ExplodingScanner(StubScanner):
    """Raises on one specific action to test per-item error isolation."""

    def __init__(self, min_severity="low"):
        super().__init__(min_severity)
        self.scanner_name = "Exploding Scanner"

    def scan_action(self, action_data):
        if action_data.get("ref", "").startswith("nested/action"):
            raise RuntimeError("boom on nested action")
        return super().scan_action(action_data)


@pytest.fixture
def patched_env(tmp_path, monkeypatch):
    """Patch the GitHub client and scanner factory used by the display layer."""
    monkeypatch.setattr(display_module, "GitHubClient", StubGitHubClient)
    monkeypatch.setattr(display_module, "get_scanner", lambda t, s: [StubScanner(s)])
    return tmp_path


def make_config(tmp_path, **overrides):
    config = {
        "repo": "owner/repo",
        "output_dir": str(tmp_path / "out"),
        "workflow_path": None,
        "scan_all_workflows": False,
        "max_depth": 5,
        "scanner": "all",
        "min_severity": "low",
        "verbose": False,
        "debug": False,
        "deep_scan": False,
        "dependency_graph": False,
    }
    config.update(overrides)
    return config


def load_consolidated(tmp_path):
    paths = list(Path(tmp_path / "out").glob("scan_*/consolidated_report.json"))
    assert len(paths) == 1, f"expected one consolidated report, got {paths}"
    return json.loads(paths[0].read_text(encoding="utf-8")), paths[0].parent


class TestWorkflowPathFlow:
    def test_specific_workflow_scan(self, patched_env):
        config = make_config(patched_env, workflow_path=".github/workflows/ci.yml")
        ActChainDisplay().run_scan(config, token="t")

        data, scan_dir = load_consolidated(patched_env)

        # Workflow finding + action findings for the three resolved actions.
        rule_ids = [f["rule_id"] for f in data["findings"]]
        assert "stub-workflow-rule" in rule_ids
        assert rule_ids.count("stub-action-rule") == 3  # checkout, composite, nested

        # All findings carry the scanner attribution.
        assert all(f["source_scanner"] == "Stub Scanner" for f in data["findings"])

        # Dependency statistics: 3 unique actions; nested is at depth 1.
        assert data["statistics"]["dependency_counts"]["total"] == 3
        assert data["statistics"]["dependency_counts"]["by_depth"]["0"] == 2
        assert data["statistics"]["dependency_counts"]["by_depth"]["1"] == 1

        # Per-item reports keep their naming convention.
        names = {p.name for p in scan_dir.glob("*.json")}
        assert "main_workflow_ci_0.json" in names
        assert any(n.startswith("action_actions_checkout@v4_depth_0") for n in names)
        assert any(n.startswith("action_nested_action@v2_depth_1") for n in names)

        # A workflow tree file exists per scanned workflow.
        assert any(p.name.startswith("workflow_tree_ci") for p in scan_dir.glob("*.txt"))

    def test_missing_workflow_raises(self, patched_env):
        config = make_config(patched_env, workflow_path=".github/workflows/nope.yml")
        with pytest.raises(Exception, match="Failed to fetch workflow"):
            ActChainDisplay().run_scan(config, token="t")


class TestScanAllFlow:
    def test_broken_workflow_is_skipped_not_fatal(self, patched_env):
        config = make_config(patched_env, scan_all_workflows=True)
        ActChainDisplay().run_scan(config, token="t")

        data, scan_dir = load_consolidated(patched_env)

        # broken.yml fails parsing and is skipped; ci.yml findings survive.
        assert any(f["rule_id"] == "stub-workflow-rule" for f in data["findings"])
        workflow_names = {f.get("workflow_name") for f in data["findings"]
                          if f["rule_id"] == "stub-workflow-rule"}
        assert workflow_names == {"ci.yml"}

    def test_both_scanners_attributed(self, patched_env, monkeypatch):
        monkeypatch.setattr(
            display_module, "get_scanner",
            lambda t, s: [StubScanner(s), ExplodingScanner(s)],
        )
        config = make_config(patched_env, workflow_path=".github/workflows/ci.yml")
        ActChainDisplay().run_scan(config, token="t")

        data, _ = load_consolidated(patched_env)
        scanners = {f["source_scanner"] for f in data["findings"]}
        assert scanners == {"Stub Scanner", "Exploding Scanner"}

        # The exploding scanner failed only on nested/action: the stub scanner
        # still produced a finding for it (per-item isolation, not fatal).
        nested = [f for f in data["findings"]
                  if f["rule_id"] == "stub-action-rule" and "nested/action" in f["title"]]
        assert {f["source_scanner"] for f in nested} == {"Stub Scanner"}


class TestInteractiveFlow:
    def test_selection_of_single_workflow(self, patched_env, monkeypatch):
        monkeypatch.setattr(click, "prompt", lambda *a, **k: 1)  # pick ci.yml
        config = make_config(patched_env)
        ActChainDisplay().run_scan(config, token="t")

        data, _ = load_consolidated(patched_env)
        assert any(f["rule_id"] == "stub-workflow-rule" for f in data["findings"])

    def test_selection_zero_scans_all(self, patched_env, monkeypatch):
        monkeypatch.setattr(click, "prompt", lambda *a, **k: 0)
        config = make_config(patched_env)
        ActChainDisplay().run_scan(config, token="t")

        _, scan_dir = load_consolidated(patched_env)
        names = {p.name for p in scan_dir.glob("*.json")}
        assert "main_workflow_ci_0.json" in names  # good workflow scanned

    def test_out_of_range_selection_raises(self, patched_env, monkeypatch):
        monkeypatch.setattr(click, "prompt", lambda *a, **k: 99)
        config = make_config(patched_env)
        with pytest.raises(Exception, match="Invalid workflow selection"):
            ActChainDisplay().run_scan(config, token="t")
