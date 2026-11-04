# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

from actchain.cli.commands import _parse_github_remote


class TestParseGithubRemote:
    def test_https_url(self):
        assert _parse_github_remote("https://github.com/owner/repo.git") == "owner/repo"
        assert _parse_github_remote("https://github.com/owner/repo") == "owner/repo"
        assert _parse_github_remote("https://github.com/owner/repo/") == "owner/repo"

    def test_ssh_scp_url(self):
        assert _parse_github_remote("git@github.com:owner/repo.git") == "owner/repo"

    def test_ssh_scheme_url(self):
        assert _parse_github_remote("ssh://git@github.com/owner/repo.git") == "owner/repo"

    def test_userinfo_in_https(self):
        assert _parse_github_remote("https://token@github.com/owner/repo.git") == "owner/repo"

    def test_lookalike_hosts_rejected(self):
        # A host merely containing 'github.com' must never be treated as
        # github.com — otherwise the wrong repository gets scanned and could
        # even receive a pinning PR.
        for url in (
            "https://notgithub.com/owner/repo.git",
            "https://mygithub.com/owner/repo",
            "https://github.com.evil.example/owner/repo",
            "git@github.com.evil.example:owner/repo.git",
            "https://git.corp/mirrors/github.com/owner/repo",
            "https://gitlab.com/owner/repo.git",
        ):
            assert _parse_github_remote(url) is None, url

    def test_garbage_rejected(self):
        for url in ("", None, "not a url", "github.com", "https://github.com/"):
            assert _parse_github_remote(url) is None, url
