# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Security utilities for ActChain.
"""

import contextlib
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Iterator

logger = logging.getLogger('actchain.utils.security')

# Patterns for secrets that must never reach logs. Each entry is
# (compiled pattern, replacement).
_SECRET_PATTERNS = [
    # Classic GitHub tokens: ghp_ (PAT), gho_ (OAuth), ghu_ (user-to-server),
    # ghs_ (server-to-server), ghr_ (refresh). Lengths vary by generation.
    (re.compile(r'gh[pousr]_[A-Za-z0-9]{16,255}'), '[REDACTED]'),
    # Fine-grained personal access tokens.
    (re.compile(r'github_pat_[A-Za-z0-9_]{22,255}'), '[REDACTED]'),
    # Anthropic API keys (used by the optional AI analysis).
    (re.compile(r'sk-ant-[A-Za-z0-9_-]{20,}'), '[REDACTED]'),
    # HTTP Authorization headers (Basic/Bearer/token).
    (re.compile(r'(?i)\b(authorization\s*[:=]\s*)(?:basic|bearer|token)\s+\S+'),
     r'\1[REDACTED]'),
    # Long base64-like blobs (potential encoded secrets).
    (re.compile(r'[A-Za-z0-9+/]{64,}={0,2}'), '[REDACTED]'),
]

# Characters that can manipulate or spoof terminal/log display:
# - C0 controls (except tab/CR/LF, which callers handle separately)
# - Unicode bidirectional controls (Trojan Source-style reordering)
# - zero-width and BOM characters (invisible content)
_CONTROL_CHARS = re.compile(
    r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f'
    r'​-‏  ‪-‮⁠-⁩﻿]'
)


class SecurityUtils:
    """Security-related utilities."""

    @staticmethod
    @contextlib.contextmanager
    def secure_temp_file(suffix: str = '', prefix: str = 'actchain_') -> Iterator[str]:
        """
        Create a secure temporary file with proper cleanup.

        Args:
            suffix: File suffix
            prefix: File prefix

        Yields:
            Temporary file path
        """
        temp_file = None
        try:
            temp_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix=suffix,
                prefix=prefix,
                delete=False
            )
            temp_file.close()
            yield temp_file.name
        finally:
            if temp_file:
                try:
                    os.unlink(temp_file.name)
                except OSError as e:
                    logger.warning(f"Failed to delete temporary file: {e}")

    @staticmethod
    @contextlib.contextmanager
    def secure_temp_dir_file(filename: str, content: str,
                             prefix: str = 'actchain_') -> Iterator[str]:
        """
        Write ``content`` to ``filename`` inside a fresh private temporary
        directory and yield the file path.

        Some external scanners decide how to analyze a file based on its
        name (for example, zizmor only treats files literally named
        ``action.yml``/``action.yaml`` as actions), so a randomly named
        temporary file is not always usable.

        Args:
            filename: Exact file name to create inside the temp directory
            content: Text content to write (UTF-8)
            prefix: Temp directory prefix

        Yields:
            Absolute path of the created file
        """
        with tempfile.TemporaryDirectory(prefix=prefix) as temp_dir:
            file_path = Path(temp_dir) / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding='utf-8')
            yield str(file_path)

    @staticmethod
    def strip_control_chars(text: str, keep_newlines: bool = True) -> str:
        """
        Remove ASCII control characters (including ANSI escape introducers)
        from text destined for terminals or log files.

        Args:
            text: Original text
            keep_newlines: When False, CR and LF are replaced with visible
                escapes so one message cannot forge extra log records.

        Returns:
            Cleaned text
        """
        cleaned = _CONTROL_CHARS.sub('', text)
        if not keep_newlines:
            cleaned = cleaned.replace('\r', '\\r').replace('\n', '\\n')
        return cleaned

    @staticmethod
    def sanitize_for_log(message: str, max_length: int = 1000) -> str:
        """
        Sanitize a message for logging to prevent secret disclosure.

        Args:
            message: Original message
            max_length: Maximum length of sanitized message

        Returns:
            Sanitized message
        """
        sanitized = message
        for pattern, replacement in _SECRET_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)

        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + '...[TRUNCATED]'

        return sanitized
