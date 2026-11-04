# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

from actchain.utils.format_utils import FormatUtils


def test_format_duration():
    assert FormatUtils.format_duration(5.0) == "5.0 seconds"
    assert FormatUtils.format_duration(120) == "2.0 minutes"
    assert FormatUtils.format_duration(7200) == "2.0 hours"


def test_format_file_size():
    assert FormatUtils.format_file_size(512) == "512 bytes"
    assert FormatUtils.format_file_size(2048) == "2.0 KB"
    assert FormatUtils.format_file_size(3 * 1024 * 1024) == "3.0 MB"
    assert FormatUtils.format_file_size(5 * 1024 ** 3) == "5.0 GB"
