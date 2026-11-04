# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

import pytest

from actchain.core.github_client import GitHubClient, GitHubClientError


@pytest.fixture
def client():
    # Bypass __init__ (which connects to GitHub) to test pure helpers.
    return GitHubClient.__new__(GitHubClient)


class TestParseActionReference:
    def test_with_version(self, client):
        assert client._parse_action_reference("owner/repo@v1.2") == ("owner/repo", "v1.2")

    def test_without_version_defaults_to_main(self, client):
        assert client._parse_action_reference("owner/repo") == ("owner/repo", "main")

    def test_invalid_refs(self, client):
        assert client._parse_action_reference("no-slash@v1") is None
        assert client._parse_action_reference("") is None


class TestDetermineActionType:
    def test_composite(self, client):
        assert client._determine_action_type({"runs": {"using": "composite"}}) == "composite"

    def test_node_versions_map_to_javascript(self, client):
        for node in ("node12", "node16", "node20"):
            assert client._determine_action_type({"runs": {"using": node}}) == "javascript"

    def test_unknown_shapes(self, client):
        assert client._determine_action_type("not a dict") == "unknown"
        assert client._determine_action_type({}) == "unknown"
        assert client._determine_action_type({"runs": "nope"}) == "unknown"


class TestDecodeFileContent:
    class FakeContent:
        def __init__(self, content, encoding="base64", sha="abc", path="f.yml"):
            self.content = content
            self.encoding = encoding
            self.sha = sha
            self.path = path

    class FakeRepo:
        def __init__(self, blob_content):
            self._blob_content = blob_content

        def get_git_blob(self, sha):
            class Blob:
                pass

            blob = Blob()
            blob.content = self._blob_content
            return blob

    def test_decodes_inline_content(self):
        import base64

        raw = base64.b64encode("on: push".encode()).decode()
        content = self.FakeContent(raw)
        assert GitHubClient._decode_file_content(content, None) == "on: push"

    def test_falls_back_to_blob_for_large_files(self):
        import base64

        blob_raw = base64.b64encode("big file".encode()).decode()
        content = self.FakeContent(content=None, encoding="none")
        assert GitHubClient._decode_file_content(content, self.FakeRepo(blob_raw)) == "big file"

    def test_non_utf8_raises_clean_error(self):
        import base64

        raw = base64.b64encode(b"\xff\xfe\x00binary").decode()
        with pytest.raises(GitHubClientError, match="UTF-8"):
            GitHubClient._decode_file_content(self.FakeContent(raw), None)
