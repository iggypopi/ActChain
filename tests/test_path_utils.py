# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

from actchain.utils.path_utils import PathUtils


class TestSanitizeFilename:
    def test_blocks_posix_traversal(self):
        assert PathUtils.sanitize_filename("../../etc/passwd") == "passwd"

    def test_blocks_windows_traversal(self):
        assert PathUtils.sanitize_filename("..\\..\\windows\\evil.json") == "evil.json"

    def test_replaces_invalid_characters(self):
        assert PathUtils.sanitize_filename("a<b>c:d|e?f*g") == "a_b_c_d_e_f_g"

    def test_strips_control_characters(self):
        assert PathUtils.sanitize_filename("re\x00po\x1frt.json") == "report.json"

    def test_windows_reserved_names_are_prefixed(self):
        assert PathUtils.sanitize_filename("CON") == "_CON"
        assert PathUtils.sanitize_filename("con.json") == "_con.json"
        assert PathUtils.sanitize_filename("COM1.txt") == "_COM1.txt"

    def test_strips_trailing_dots_and_spaces(self):
        assert PathUtils.sanitize_filename("report. . .") == "report"

    def test_empty_and_dot_names(self):
        assert PathUtils.sanitize_filename("") == "unnamed_file"
        assert PathUtils.sanitize_filename("..") == "unnamed_file"

    def test_length_is_capped(self):
        assert len(PathUtils.sanitize_filename("x" * 500)) <= 150
