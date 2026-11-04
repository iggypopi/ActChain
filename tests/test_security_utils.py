# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

import logging
import os
from pathlib import Path

from actchain.logging_config import RedactingFilter
from actchain.utils.security_utils import SecurityUtils


class TestSanitizeForLog:
    def test_redacts_classic_github_tokens(self):
        for prefix in ("ghp", "gho", "ghu", "ghs", "ghr"):
            message = f"error with token {prefix}_{'A' * 36} in request"
            sanitized = SecurityUtils.sanitize_for_log(message)
            assert f"{prefix}_" not in sanitized
            assert "[REDACTED]" in sanitized

    def test_redacts_fine_grained_tokens(self):
        message = "using github_pat_" + "a" * 60
        sanitized = SecurityUtils.sanitize_for_log(message)
        assert "github_pat_" not in sanitized

    def test_redacts_authorization_headers(self):
        sanitized = SecurityUtils.sanitize_for_log("Authorization: Bearer abc.def-123")
        assert "abc.def-123" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_redacts_long_base64_blobs(self):
        blob = "A" * 80 + "=="
        assert "[REDACTED]" in SecurityUtils.sanitize_for_log(f"data {blob}")

    def test_keeps_commit_shas(self):
        # 40-char hex strings (commit SHAs) are routine content and must not
        # be over-redacted.
        sha = "a1b2c3d4e5" * 4
        assert sha in SecurityUtils.sanitize_for_log(f"pinned to {sha}")

    def test_truncates_long_messages(self):
        sanitized = SecurityUtils.sanitize_for_log("x " * 2000, max_length=100)
        assert sanitized.endswith("...[TRUNCATED]")


class TestStripControlChars:
    def test_strips_ansi_escape_introducer(self):
        assert "\x1b" not in SecurityUtils.strip_control_chars("\x1b[31mred\x1b[0m")

    def test_strips_bidi_and_zero_width_characters(self):
        # Trojan Source-style reordering and invisible characters must not
        # reach the terminal or logs.
        hostile = "safe‮evil‬​hidden﻿"
        cleaned = SecurityUtils.strip_control_chars(hostile)
        for ch in ("‮", "‬", "​", "﻿"):
            assert ch not in cleaned
        assert "safe" in cleaned and "evil" in cleaned

    def test_keeps_newlines_by_default(self):
        assert SecurityUtils.strip_control_chars("a\nb") == "a\nb"

    def test_neutralizes_newlines_when_requested(self):
        result = SecurityUtils.strip_control_chars("a\r\nb", keep_newlines=False)
        assert "\n" not in result and "\r" not in result
        assert result == "a\\r\\nb"


class TestRedactingFilter:
    def test_filter_redacts_and_neutralizes(self):
        record = logging.LogRecord(
            name="t", level=logging.INFO, pathname=__file__, lineno=1,
            msg="token ghp_%s\nFORGED-RECORD" % ("B" * 36), args=(), exc_info=None,
        )
        assert RedactingFilter().filter(record) is True
        assert "ghp_" not in record.getMessage()
        assert "\n" not in record.getMessage()


class TestTempFiles:
    def test_secure_temp_file_cleanup(self):
        with SecurityUtils.secure_temp_file(suffix=".yml") as path:
            Path(path).write_text("hello", encoding="utf-8")
            assert os.path.exists(path)
        assert not os.path.exists(path)

    def test_secure_temp_dir_file_names_and_cleans_up(self):
        with SecurityUtils.secure_temp_dir_file("action.yml", "name: test") as path:
            p = Path(path)
            assert p.name == "action.yml"
            assert p.read_text(encoding="utf-8") == "name: test"
        assert not p.exists()
        assert not p.parent.exists()

    def test_secure_temp_dir_file_supports_subdirectories(self):
        with SecurityUtils.secure_temp_dir_file(".github/workflows/workflow.yml", "on: push") as path:
            p = Path(path)
            assert p.exists()
            assert p.parent.name == "workflows"
        assert not p.exists()
