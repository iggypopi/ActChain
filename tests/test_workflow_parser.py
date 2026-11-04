# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

import pytest

from actchain.core.workflow_parser import WorkflowParseError, WorkflowParser

VALID_WORKFLOW = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: echo hello
"""


@pytest.fixture
def parser():
    return WorkflowParser()


class TestParse:
    def test_parses_valid_workflow(self, parser):
        data = parser.parse(VALID_WORKFLOW)
        assert "jobs" in data

    def test_rejects_empty_content(self, parser):
        with pytest.raises(WorkflowParseError):
            parser.parse("   ")

    def test_rejects_non_mapping(self, parser):
        with pytest.raises(WorkflowParseError):
            parser.parse("- just\n- a\n- list\n")

    def test_rejects_missing_trigger(self, parser):
        with pytest.raises(WorkflowParseError, match="trigger"):
            parser.parse("name: x\njobs:\n  a:\n    steps: []\n")

    def test_rejects_missing_jobs(self, parser):
        with pytest.raises(WorkflowParseError, match="jobs"):
            parser.parse("name: x\non: push\n")

    def test_accepts_unquoted_on_parsed_as_bool(self, parser):
        # YAML 1.1 parses a bare `on:` key as boolean True
        data = parser.parse("True:\n  push\njobs:\n  a:\n    steps: []\n")
        assert "jobs" in data

    def test_rejects_invalid_yaml(self, parser):
        with pytest.raises(WorkflowParseError):
            parser.parse("on: [unclosed\njobs:")


class TestExtractActions:
    def test_extracts_action_refs(self, parser):
        actions = parser.extract_actions(parser.parse(VALID_WORKFLOW))
        assert actions == {"actions/checkout@v4", "actions/setup-python@v5"}

    def test_ignores_invalid_steps(self, parser):
        data = {"on": "push", "jobs": {"a": {"steps": [{"uses": 123}, "nope", {"run": "x"}]}}}
        assert parser.extract_actions(data) == set()

    def test_valid_action_ref_rules(self, parser):
        assert parser._is_valid_action_ref("owner/repo@v1")
        assert parser._is_valid_action_ref("docker://alpine:3")
        assert parser._is_valid_action_ref("./local/action")
        assert not parser._is_valid_action_ref("/absolute")
        assert not parser._is_valid_action_ref("")
        assert not parser._is_valid_action_ref("no-slash")


class TestPermissions:
    def test_wildcard_string(self, parser):
        analysis = parser.analyze_permissions({"permissions": "write-all", "jobs": {}})
        assert analysis["has_wildcard_permissions"]

    def test_wildcard_in_job(self, parser):
        data = {"jobs": {"a": {"permissions": {"contents": "write"}}}}
        assert parser.analyze_permissions(data)["has_wildcard_permissions"]

    def test_no_wildcard(self, parser):
        data = {"permissions": {"contents": "read"}, "jobs": {}}
        assert not parser.analyze_permissions(data)["has_wildcard_permissions"]


class TestCompositeActions:
    def test_extracts_nested_actions(self, parser):
        action = {
            "runs": {
                "using": "composite",
                "steps": [
                    {"uses": "actions/cache@v4"},
                    {"run": "echo hi", "shell": "bash"},
                ],
            }
        }
        assert parser.extract_composite_actions(action) == {"actions/cache@v4"}

    def test_non_composite_returns_empty(self, parser):
        assert parser.extract_composite_actions({"runs": {"using": "node20"}}) == set()
