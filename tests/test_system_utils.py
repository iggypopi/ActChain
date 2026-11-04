# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

import sys

from actchain.utils.system_utils import SystemUtils

TOOL = "actchain_test_tool"


def _make_executable(directory, name):
    if sys.platform == "win32":
        exe = directory / f"{name}.exe"
        exe.write_bytes(b"MZ")
    else:
        exe = directory / name
        exe.write_text("#!/bin/sh\nexit 0\n")
        exe.chmod(0o755)
    return exe


class TestResolveCommand:
    def test_resolves_from_path(self, tmp_path, monkeypatch):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        exe = _make_executable(bindir, TOOL)
        monkeypatch.setenv("PATH", str(bindir))
        assert SystemUtils.resolve_command(TOOL) == str(exe)

    def test_never_resolves_from_cwd(self, tmp_path, monkeypatch):
        # A malicious scanned repo could plant a binary named like a scanner
        # in the directory the user runs actchain from; it must be ignored
        # even if that directory is on PATH.
        workdir = tmp_path / "work"
        workdir.mkdir()
        _make_executable(workdir, TOOL)
        monkeypatch.chdir(workdir)
        monkeypatch.setenv("PATH", str(workdir))
        assert SystemUtils.resolve_command(TOOL) is None

    def test_missing_command(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PATH", str(tmp_path))
        assert SystemUtils.resolve_command("definitely-not-a-real-tool") is None

    def test_relative_path_entries_are_ignored(self, tmp_path, monkeypatch):
        # A relative PATH entry (e.g. "bin") resolves against the CWD, which
        # may be the untrusted checkout being scanned.
        workdir = tmp_path / "work"
        bindir = workdir / "bin"
        bindir.mkdir(parents=True)
        _make_executable(bindir, TOOL)
        monkeypatch.chdir(workdir)
        monkeypatch.setenv("PATH", "bin")
        assert SystemUtils.resolve_command(TOOL) is None

    def test_path_entries_under_cwd_are_ignored(self, tmp_path, monkeypatch):
        workdir = tmp_path / "work"
        bindir = workdir / "tools"
        bindir.mkdir(parents=True)
        _make_executable(bindir, TOOL)
        monkeypatch.chdir(workdir)
        monkeypatch.setenv("PATH", str(bindir))  # absolute, but inside CWD
        assert SystemUtils.resolve_command(TOOL) is None
