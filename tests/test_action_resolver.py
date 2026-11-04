# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

from actchain.constants import MAX_DOC_DEPENDENCIES
from actchain.core.action_resolver import ActionResolver
from actchain.core.workflow_parser import WorkflowParser


class StubGitHubClient:
    """Offline stand-in for GitHubClient."""

    def __init__(self, readme=None):
        self.readme = readme

    def get_file_content_optional(self, repo_name, path, ref="main"):
        return self.readme


class TestUsesTraversal:
    def test_finds_nested_uses(self):
        resolver = ActionResolver(StubGitHubClient())
        content = {"runs": {"steps": [{"uses": "actions/cache@v4"}]}, "x": {"uses": "a/b@v1"}}
        assert resolver._extract_uses_dependencies(content) == {"actions/cache@v4", "a/b@v1"}

    def test_survives_self_referential_structures(self):
        # yaml.safe_load can produce self-referential objects via anchors
        # (&a [*a]); the walker must terminate.
        resolver = ActionResolver(StubGitHubClient())
        content = {"uses": "a/b@v1"}
        content["self"] = content
        assert resolver._extract_uses_dependencies(content) == {"a/b@v1"}

    def test_shared_subtrees_are_walked_once(self):
        # A ~1KB YAML file with chained anchors creates 2^n paths through
        # shared nodes; without a visited-set this takes hours.
        resolver = ActionResolver(StubGitHubClient())
        level = {"uses": "shared/action@v1"}
        for _ in range(40):
            level = {"a": level, "b": level}
        assert resolver._extract_uses_dependencies({"runs": level}) == {"shared/action@v1"}

    def test_depth_is_bounded(self):
        resolver = ActionResolver(StubGitHubClient())
        deep = {"uses": "deep/action@v1"}
        for _ in range(200):
            deep = {"nest": deep}
        # The ref sits far below MAX_TRAVERSAL_DEPTH; the walk must stop
        # (and not raise RecursionError) rather than follow it down.
        assert resolver._extract_uses_dependencies(deep) == set()

    def test_over_deep_branch_does_not_hide_other_dependencies(self):
        # One hostile over-deep branch must be skipped, not abort the whole
        # traversal: real dependencies elsewhere must still be found.
        resolver = ActionResolver(StubGitHubClient())
        deep = {"x": 1}
        for _ in range(200):
            deep = {"nest": deep}
        content = {"deep_branch": deep, "runs": {"steps": [{"uses": "real/action@v1"}]}}
        assert resolver._extract_uses_dependencies(content) == {"real/action@v1"}


class TestHeuristicDependencies:
    ACTION = {
        "ref": "docker/build-push-action@v5",
        "type": "unknown",
        "content": {"name": "x"},
    }

    def test_heuristics_disabled_by_default(self):
        resolver = ActionResolver(StubGitHubClient(readme="use foo/bar@v1 and baz/qux@v2"))
        deps = resolver.get_action_dependencies(self.ACTION, WorkflowParser())
        assert deps == set()

    def test_deep_scan_enables_known_co_used_actions(self):
        resolver = ActionResolver(StubGitHubClient(), deep_scan=True)
        deps = resolver.get_action_dependencies(self.ACTION, WorkflowParser())
        assert "docker/setup-buildx-action@v5" in deps
        assert "docker/login-action@v5" in deps

    def test_readme_refs_are_capped(self):
        # A malicious README listing hundreds of refs must not drive
        # unbounded fetching.
        readme = "\n".join(f"evil{i}/repo{i}@v1" for i in range(200))
        resolver = ActionResolver(StubGitHubClient(readme=readme), deep_scan=True)
        deps = resolver._extract_documentation_dependencies("some/action@v1")
        assert len(deps) == MAX_DOC_DEPENDENCIES


class TestSyntheticActions:
    def test_docker_action_data(self):
        resolver = ActionResolver(StubGitHubClient())
        data = resolver.resolve_action("docker://alpine:3.20")
        assert data["type"] == "docker"
        assert data["content"]["runs"]["image"] == "alpine:3.20"

    def test_local_action_data(self):
        resolver = ActionResolver(StubGitHubClient())
        assert resolver.resolve_action("./local/action")["type"] == "local"

    def test_base_ref(self):
        resolver = ActionResolver(StubGitHubClient())
        assert resolver._get_base_ref("a/b@v1") == "a/b"
        assert resolver._get_base_ref("a/b") == "a/b"


class TestSecurityAnalysis:
    def test_flags_token_inputs_and_floating_docker_tags(self):
        resolver = ActionResolver(StubGitHubClient())
        content = {
            "inputs": {"github_token": {"description": "t"}},
            "runs": {"using": "docker", "image": "docker://alpine:latest"},
        }
        warnings = resolver._analyze_security_issues(content, "a/b@v1")
        assert any("token" in w for w in warnings)
        assert any("floating tag" in w for w in warnings)
