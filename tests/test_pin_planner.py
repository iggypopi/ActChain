# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Tests for the pin planner: textual rewrite matrix, skip reasons, diff output.

The planner is pure (no network, no filesystem), so every case drives it with
in-memory workflow content, parser-extracted step refs and recorded SHAs.
"""

from actchain.pinning import build_pin_plan
from actchain.pinning.planner import (
    REASON_NO_RECORDED_SHA,
    REASON_NO_REF,
    REASON_REUSABLE_WORKFLOW,
)

PATH = ".github/workflows/ci.yml"
SHA = "1234567890abcdef1234567890abcdef12345678"
SHA2 = "fedcba9876543210fedcba9876543210fedcba98"


def make_plan(content, step_refs, actions, path=PATH):
    workflows = [{"name": "ci.yml", "path": path, "content": content}]
    return build_pin_plan(workflows, {path: step_refs}, actions)


class TestRewrite:
    def test_plain_step_gets_sha_and_comment(self):
        content = "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
        plan = make_plan(content, ["actions/checkout@v4"],
                         {"actions/checkout@v4": {"commit_sha": SHA}})

        assert plan.new_contents[PATH] == (
            f"jobs:\n  build:\n    steps:\n      - uses: actions/checkout@{SHA}  # v4\n"
        )
        assert len(plan.entries) == 1
        entry = plan.entries[0]
        assert entry.workflow_path == PATH
        assert entry.line_number == 4  # 1-based
        assert entry.action_base == "actions/checkout"
        assert entry.old_ref == "v4"
        assert entry.new_sha == SHA
        assert plan.skipped == []

    def test_indented_without_dash(self):
        content = "        uses: a/b@v1\n"
        plan = make_plan(content, ["a/b@v1"], {"a/b@v1": {"commit_sha": SHA}})
        assert plan.new_contents[PATH] == f"        uses: a/b@{SHA}  # v1\n"

    def test_single_quoted_ref_keeps_comment_outside_quote(self):
        content = "      - uses: 'a/b@v1'\n"
        plan = make_plan(content, ["a/b@v1"], {"a/b@v1": {"commit_sha": SHA}})
        assert plan.new_contents[PATH] == f"      - uses: 'a/b@{SHA}'  # v1\n"

    def test_double_quoted_ref_keeps_comment_outside_quote(self):
        content = '      - uses: "a/b@v1"\n'
        plan = make_plan(content, ["a/b@v1"], {"a/b@v1": {"commit_sha": SHA}})
        assert plan.new_contents[PATH] == f'      - uses: "a/b@{SHA}"  # v1\n'

    def test_existing_comment_is_preserved_and_no_new_comment_added(self):
        content = "      - uses: a/b@v1 # keep me\n"
        plan = make_plan(content, ["a/b@v1"], {"a/b@v1": {"commit_sha": SHA}})
        assert plan.new_contents[PATH] == f"      - uses: a/b@{SHA} # keep me\n"
        assert len(plan.entries) == 1

    def test_short_sha_expanded_with_original_in_comment(self):
        content = "      - uses: a/b@deadbeef\n"
        plan = make_plan(content, ["a/b@deadbeef"], {"a/b@deadbeef": {"commit_sha": SHA}})
        assert plan.new_contents[PATH] == f"      - uses: a/b@{SHA}  # deadbeef\n"
        assert plan.entries[0].old_ref == "deadbeef"

    def test_subpath_action_rewritten(self):
        content = "      - uses: owner/repo/sub/dir@v2\n"
        plan = make_plan(content, ["owner/repo/sub/dir@v2"],
                         {"owner/repo/sub/dir@v2": {"commit_sha": SHA2}})
        assert plan.new_contents[PATH] == f"      - uses: owner/repo/sub/dir@{SHA2}  # v2\n"
        assert plan.entries[0].action_base == "owner/repo/sub/dir"

    def test_flow_mapping_replaced_without_comment(self):
        content = "      - { uses: a/b@v1 }\n"
        plan = make_plan(content, ["a/b@v1"], {"a/b@v1": {"commit_sha": SHA}})
        new_line = plan.new_contents[PATH].rstrip("\n")
        assert new_line == f"      - {{ uses: a/b@{SHA} }}"
        assert "#" not in new_line  # a comment would break the flow mapping
        assert len(plan.entries) == 1

    def test_same_ref_on_two_lines_rewritten_independently(self):
        content = ("      - uses: a/b@v1\n"
                   "      - run: echo hi\n"
                   "      - uses: a/b@v1\n")
        plan = make_plan(content, ["a/b@v1"], {"a/b@v1": {"commit_sha": SHA}})
        assert len(plan.entries) == 2
        assert [e.line_number for e in plan.entries] == [1, 3]
        assert plan.new_contents[PATH].count(f"a/b@{SHA}  # v1") == 2


class TestUntouchedLines:
    def test_commented_out_line_skipped_silently(self):
        content = "      # - uses: a/b@v1\n"
        plan = make_plan(content, ["a/b@v1"], {"a/b@v1": {"commit_sha": SHA}})
        assert plan.entries == []
        assert plan.skipped == []
        assert plan.new_contents == {}

    def test_uses_inside_run_block_not_in_step_refs_untouched(self):
        content = ("      - run: |\n"
                   "          uses: evil/x@v1\n")
        plan = make_plan(content, [], {"evil/x@v1": {"commit_sha": SHA}})
        assert plan.entries == []
        assert plan.skipped == []
        assert plan.new_contents == {}

    def test_run_block_line_matching_a_real_step_ref_untouched(self):
        # The same ref is BOTH a legitimate step and literal text inside a
        # run: | script (e.g. a script writing a YAML file): only the step
        # line may be rewritten, never the script line.
        content = (
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: |\n"
            "          cat > wf.yml <<'EOF'\n"
            "          uses: actions/checkout@v4\n"
            "          EOF\n"
        )
        plan = make_plan(content, ["actions/checkout@v4"],
                         {"actions/checkout@v4": {"commit_sha": SHA}})

        assert len(plan.entries) == 1
        assert plan.entries[0].line_number == 4
        new_lines = plan.new_contents[PATH].splitlines()
        assert new_lines[3] == f"      - uses: actions/checkout@{SHA}  # v4"
        assert new_lines[6] == "          uses: actions/checkout@v4"  # script line intact

    def test_folded_block_scalar_without_dash_is_skipped(self):
        content = (
            "      - name: write\n"
            "        run: >\n"
            "          uses: a/b@v1\n"
            "      - uses: a/b@v1\n"
        )
        plan = make_plan(content, ["a/b@v1"], {"a/b@v1": {"commit_sha": SHA}})

        assert [e.line_number for e in plan.entries] == [4]
        new_lines = plan.new_contents[PATH].splitlines()
        assert new_lines[2] == "          uses: a/b@v1"  # folded scalar content intact
        assert new_lines[3] == f"      - uses: a/b@{SHA}  # v1"

    def test_step_after_closed_block_scalar_is_rewritten(self):
        content = (
            "      - run: |\n"
            "          echo hello\n"
            "      - uses: a/b@v1\n"
        )
        plan = make_plan(content, ["a/b@v1"], {"a/b@v1": {"commit_sha": SHA}})
        assert [e.line_number for e in plan.entries] == [3]
        assert plan.new_contents[PATH].splitlines()[2] == f"      - uses: a/b@{SHA}  # v1"

    def test_blank_lines_inside_block_scalar_do_not_terminate_it(self):
        content = (
            "      - run: |-\n"
            "          line1\n"
            "\n"
            "          uses: a/b@v1\n"
            "      - uses: a/b@v1\n"
        )
        plan = make_plan(content, ["a/b@v1"], {"a/b@v1": {"commit_sha": SHA}})

        assert [e.line_number for e in plan.entries] == [5]
        new_lines = plan.new_contents[PATH].splitlines()
        assert new_lines[3] == "          uses: a/b@v1"  # still scalar content
        assert new_lines[4] == f"      - uses: a/b@{SHA}  # v1"

    def test_sibling_key_at_run_indent_closes_the_scalar(self):
        # 'env:' sits at the indent of 'run' (not of the dash): it terminates
        # the scalar, and the next step is rewritten normally.
        content = (
            "      - run: |\n"
            "          uses: a/b@v1\n"
            "        env:\n"
            "          FOO: bar\n"
            "      - uses: a/b@v1\n"
        )
        plan = make_plan(content, ["a/b@v1"], {"a/b@v1": {"commit_sha": SHA}})
        assert [e.line_number for e in plan.entries] == [5]
        assert plan.new_contents[PATH].splitlines()[1] == "          uses: a/b@v1"

    def test_already_sha_pinned_is_silent(self):
        content = f"      - uses: a/b@{SHA}\n"
        plan = make_plan(content, [f"a/b@{SHA}"], {})
        assert plan.entries == []
        assert plan.skipped == []
        assert plan.new_contents == {}


class TestSkippedPins:
    def test_reusable_workflow_is_skipped_with_reason(self):
        ref = "owner/repo/.github/workflows/x.yml@v1"
        content = f"    uses: {ref}\n"
        plan = make_plan(content, [ref], {ref: {"commit_sha": SHA}})
        assert plan.entries == []
        assert plan.new_contents == {}
        assert len(plan.skipped) == 1
        skipped = plan.skipped[0]
        assert skipped.workflow_path == PATH
        assert skipped.line_number == 1
        assert skipped.reason == REASON_REUSABLE_WORKFLOW

    def test_ref_without_recorded_sha_is_skipped(self):
        content = "      - uses: a/b@v1\n"
        plan = make_plan(content, ["a/b@v1"], {})
        assert plan.entries == []
        assert [s.reason for s in plan.skipped] == [REASON_NO_RECORDED_SHA]

    def test_falsy_commit_sha_is_skipped(self):
        content = "      - uses: a/b@v1\n"
        plan = make_plan(content, ["a/b@v1"], {"a/b@v1": {"commit_sha": None}})
        assert [s.reason for s in plan.skipped] == [REASON_NO_RECORDED_SHA]

    def test_ref_without_at_is_skipped(self):
        content = "      - uses: a/b\n"
        plan = make_plan(content, ["a/b"], {"a/b": {"commit_sha": SHA}})
        assert plan.entries == []
        assert [s.reason for s in plan.skipped] == [REASON_NO_REF]


class TestPlanOutputs:
    def test_idempotent_on_own_output(self):
        content = ("      - uses: actions/checkout@v4\n"
                   "      - uses: 'a/b@v1'\n")
        actions = {"actions/checkout@v4": {"commit_sha": SHA},
                   "a/b@v1": {"commit_sha": SHA2}}
        first = make_plan(content, ["actions/checkout@v4", "a/b@v1"], actions)
        rewritten = first.new_contents[PATH]

        second = make_plan(rewritten, [f"actions/checkout@{SHA}", f"a/b@{SHA2}"], actions)
        assert second.entries == []
        assert second.skipped == []
        assert second.new_contents == {}
        assert second.base_contents == {}
        assert second.diff_text == ""

    def test_diff_text_and_changed_files_only(self):
        changed = ".github/workflows/ci.yml"
        unchanged = ".github/workflows/release.yml"
        workflows = [
            {"name": "ci.yml", "path": changed,
             "content": "      - uses: actions/checkout@v4\n"},
            {"name": "release.yml", "path": unchanged,
             "content": "      - run: make release\n"},
        ]
        plan = build_pin_plan(
            workflows,
            {changed: ["actions/checkout@v4"], unchanged: []},
            {"actions/checkout@v4": {"commit_sha": SHA}},
        )

        assert set(plan.new_contents) == {changed}
        # Scan-time originals recorded for changed files only (TOCTOU guard).
        assert plan.base_contents == {changed: "      - uses: actions/checkout@v4\n"}
        assert f"--- a/{changed}" in plan.diff_text
        assert f"+++ b/{changed}" in plan.diff_text
        assert "-      - uses: actions/checkout@v4" in plan.diff_text
        assert f"+      - uses: actions/checkout@{SHA}  # v4" in plan.diff_text
        assert unchanged not in plan.diff_text
