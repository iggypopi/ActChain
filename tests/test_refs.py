# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

from actchain.core.refs import ActionRef, is_full_sha, parse_action_ref


class TestParseActionRef:
    def test_plain_ref(self):
        ref = parse_action_ref("actions/checkout@v4")
        assert ref == ActionRef(owner="actions", repo="checkout", subpath="",
                                ref="v4", raw="actions/checkout@v4")
        assert ref.repo_full_name == "actions/checkout"
        assert ref.base == "actions/checkout"

    def test_no_ref(self):
        ref = parse_action_ref("actions/checkout")
        assert ref.ref == ""

    def test_subpath_action(self):
        ref = parse_action_ref("owner/repo/path/to/action@v1")
        assert ref.repo_full_name == "owner/repo"
        assert ref.subpath == "path/to/action"
        assert ref.base == "owner/repo/path/to/action"

    def test_reusable_workflow(self):
        ref = parse_action_ref("owner/repo/.github/workflows/ci.yml@main")
        assert ref.is_reusable_workflow

    def test_slash_containing_ref(self):
        ref = parse_action_ref("owner/repo@releases/v1")
        assert ref.ref == "releases/v1"

    def test_sha_pinned(self):
        sha = "a" * 40
        ref = parse_action_ref(f"actions/checkout@{sha}")
        assert ref.is_sha_pinned
        assert not ref.is_short_sha

    def test_short_sha(self):
        ref = parse_action_ref("actions/checkout@abc1234")
        assert ref.is_short_sha
        assert not ref.is_sha_pinned

    def test_rejected_forms(self):
        for raw in (
            "docker://alpine:3",
            "./local/action",
            "/absolute@v1",
            "no-slash",
            "owner/repo@${{ matrix.ref }}",
            "owner/repo@ref with space",
            "owner/repo@",
            "",
            None,
            "-startshyphen/repo@v1",
            "owner/repo@v1@v2",
        ):
            assert parse_action_ref(raw) is None, raw

    def test_hostile_strings_rejected(self):
        for raw in (
            'evil/x@v1"];injection',
            "owner/repo@v1#comment",
            "owner/repo@v1`cmd`",
            "@victim/repo@v1",
        ):
            assert parse_action_ref(raw) is None, raw


class TestIsFullSha:
    def test_full_sha(self):
        assert is_full_sha("0" * 40)

    def test_rejects_other(self):
        assert not is_full_sha("0" * 39)
        assert not is_full_sha("g" * 40)
        assert not is_full_sha("")
        assert not is_full_sha(None)
