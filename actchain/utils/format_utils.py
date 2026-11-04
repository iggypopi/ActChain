# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Formatting utilities for ActChain.
"""


class FormatUtils:
    """Utilities for formatting data."""

    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in seconds as human-readable string."""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} minutes"
        else:
            hours = seconds / 3600
            return f"{hours:.1f} hours"

    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Format file size in bytes as human-readable string."""
        if size_bytes < 1024:
            return f"{size_bytes} bytes"
        elif size_bytes < 1024 * 1024:
            kb = size_bytes / 1024
            return f"{kb:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            mb = size_bytes / (1024 * 1024)
            return f"{mb:.1f} MB"
        else:
            gb = size_bytes / (1024 * 1024 * 1024)
            return f"{gb:.1f} GB"
