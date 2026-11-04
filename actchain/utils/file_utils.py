# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
File utilities for ActChain.
"""

import logging
from pathlib import Path
from typing import Union, Optional

logger = logging.getLogger('actchain.utils.file')


class FileUtils:
    """Utilities for file operations."""

    @staticmethod
    def safe_write_file(content: str, file_path: Union[str, Path]) -> bool:
        """
        Safely write content to a file.

        Args:
            content: Content to write
            file_path: Path to the file

        Returns:
            True if successful, False otherwise
        """
        try:
            path_obj = Path(file_path)
            path_obj.parent.mkdir(parents=True, exist_ok=True)

            with open(path_obj, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Failed to write file {file_path}: {e}")
            return False

    @staticmethod
    def safe_read_file(file_path: Union[str, Path]) -> Optional[str]:
        """
        Safely read content from a file.

        Args:
            file_path: Path to the file

        Returns:
            File content or None if failed
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return None

    @staticmethod
    def get_file_size(file_path: Union[str, Path]) -> int:
        """Get file size in bytes."""
        try:
            return Path(file_path).stat().st_size
        except Exception:
            return 0
