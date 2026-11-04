# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Path utilities for ActChain.
"""

import re
from pathlib import Path
from typing import Union


# Windows reserved device names: writing to e.g. "CON.json" targets the
# console device regardless of extension.
_WINDOWS_RESERVED = {
    'con', 'prn', 'aux', 'nul',
    *(f'com{i}' for i in range(1, 10)),
    *(f'lpt{i}' for i in range(1, 10)),
}

_MAX_FILENAME_LENGTH = 150


class PathUtils:
    """Utilities for path operations."""

    @staticmethod
    def validate_path(path: Union[str, Path]) -> Path:
        """
        Validate and normalize a file path.

        Args:
            path: File path to validate

        Returns:
            Normalized Path object
        """
        path_obj = Path(path).expanduser().resolve()
        return path_obj

    @staticmethod
    def ensure_directory(path: Union[str, Path]) -> Path:
        """
        Ensure directory exists, create if necessary.

        Args:
            path: Directory path

        Returns:
            Path object for the directory
        """
        path_obj = Path(path)
        path_obj.mkdir(parents=True, exist_ok=True)
        return path_obj

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize a filename derived from untrusted input (workflow names,
        action references) so it is safe to create on any filesystem.

        Handles path traversal, invalid and control characters, Windows
        reserved device names, trailing dots/spaces, and excessive length.

        Args:
            filename: Original filename

        Returns:
            Sanitized filename safe for filesystem operations
        """
        # Strip directory components from both separator styles to prevent
        # path traversal (os.path.basename only handles the native one).
        filename = filename.replace('\\', '/').rsplit('/', 1)[-1]

        # Remove control characters outright.
        filename = re.sub(r'[\x00-\x1f\x7f]', '', filename)

        # Replace characters invalid on common filesystems.
        for char in ['<', '>', ':', '"', '|', '?', '*']:
            filename = filename.replace(char, '_')

        # Windows silently strips trailing dots and spaces, which can cause
        # collisions or unexpected names.
        filename = filename.rstrip(' .')

        # Keep names to a sane length (leaving room for suffixes).
        if len(filename) > _MAX_FILENAME_LENGTH:
            filename = filename[:_MAX_FILENAME_LENGTH]

        # Reserved device names (with or without extension) are not usable
        # as regular files on Windows.
        stem = filename.split('.', 1)[0].lower()
        if stem in _WINDOWS_RESERVED:
            filename = f'_{filename}'

        if not filename or filename in ['.', '..']:
            filename = 'unnamed_file'

        return filename
