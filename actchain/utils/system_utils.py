# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
System utilities for ActChain.
"""

import logging
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger('actchain.utils.system')


class SystemUtils:
    """Utilities for system operations."""

    @staticmethod
    def resolve_command(command: str) -> Optional[str]:
        """
        Resolve a command name to an absolute executable path using PATH,
        explicitly excluding the current working directory.

        On Windows, CreateProcess resolves bare executable names against the
        current directory before PATH. ActChain is routinely run from inside
        a checkout of the (untrusted) repository being audited, so a
        malicious repo could plant e.g. ``zizmor.exe`` at its root and have
        it executed. Resolving against PATH only closes that hole.

        Args:
            command: Bare command name (e.g. "zizmor")

        Returns:
            Absolute path to the executable, or None if not found on PATH
        """
        cwd = Path.cwd()
        if sys.platform == 'win32':
            pathext = os.environ.get('PATHEXT', '.COM;.EXE;.BAT;.CMD')
            extensions = [e.lower() for e in pathext.split(os.pathsep) if e]
        else:
            extensions = ['']

        try:
            cwd_resolved = cwd.resolve()
        except OSError:
            cwd_resolved = cwd

        for entry in os.environ.get('PATH', os.defpath).split(os.pathsep):
            # Skip empty entries (which mean CWD), relative entries (which
            # resolve against the CWD), and anything at or beneath the CWD:
            # all of those would let the scanned checkout supply the binary.
            if not entry:
                continue
            try:
                directory = Path(entry)
                if not directory.is_absolute():
                    continue
                resolved_dir = directory.resolve()
                if resolved_dir == cwd_resolved or cwd_resolved in resolved_dir.parents:
                    continue
            except OSError:
                continue

            for ext in extensions:
                candidate = directory / (
                    command if command.lower().endswith(ext.lower()) or not ext
                    else command + ext
                )
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return str(candidate.resolve())

        return None

    @staticmethod
    def is_command_available(command: str) -> bool:
        """
        Check if a command is available on PATH and runs.

        Args:
            command: Command to check

        Returns:
            True if command is available, False otherwise
        """
        resolved = SystemUtils.resolve_command(command)
        if not resolved:
            return False

        try:
            result = subprocess.run(
                [resolved, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False

    @staticmethod
    def is_docker_available() -> bool:
        """Check if Docker is available on the system."""
        return SystemUtils.is_command_available("docker")

    @staticmethod
    def get_platform_info() -> Dict[str, str]:
        """Get information about the current platform."""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        }

    @staticmethod
    def check_dependencies() -> bool:
        """
        Check if all required dependencies are installed.

        Returns:
            True if all dependencies are available, False otherwise
        """
        if sys.version_info < (3, 10):
            logger.error("Python 3.10 or higher is required")
            return False

        if not SystemUtils.is_command_available("git"):
            logger.error("Git is required but not found")
            return False

        return True

    @staticmethod
    def get_env_var(name: str, default: Optional[str] = None) -> Optional[str]:
        """Get environment variable value."""
        return os.environ.get(name, default)

    @staticmethod
    def create_environment_report() -> Dict[str, Any]:
        """Create a comprehensive environment report."""
        return {
            "platform": SystemUtils.get_platform_info(),
            "dependencies": {
                "git": SystemUtils.is_command_available("git"),
                "docker": SystemUtils.is_docker_available(),
                "zizmor": SystemUtils.is_command_available("zizmor"),
            },
            "environment_variables": {
                "GITHUB_TOKEN": bool(SystemUtils.get_env_var("GITHUB_TOKEN")),
                "ACTCHAIN_LOG_LEVEL": SystemUtils.get_env_var("ACTCHAIN_LOG_LEVEL", "INFO"),
            }
        }
