# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Scanner factory for ActChain.
"""

import logging
from typing import Union, List

from .base import BaseScanner, ScannerError
from .zizmor import ZizmorScanner
from .opengrep import OpenGrepScanner

logger = logging.getLogger('actchain.scanners.factory')


class ScannerFactory:
    """Factory for creating scanner instances."""

    @staticmethod
    def create_scanner(scanner_type: str, min_severity: str = "low") -> BaseScanner:
        """
        Create a scanner instance.

        Args:
            scanner_type: Type of scanner to create
            min_severity: Minimum severity level

        Returns:
            Scanner instance

        Raises:
            ScannerError: If scanner cannot be created
        """
        if scanner_type == "zizmor":
            return ZizmorScanner(min_severity)
        elif scanner_type == "opengrep":
            return OpenGrepScanner(min_severity)
        else:
            raise ScannerError(f"Unknown scanner type: {scanner_type}")


def get_scanner(scanner_type: str = "zizmor", min_severity: str = "low") -> Union[BaseScanner, List[BaseScanner]]:
    """
    Get scanner instance(s) based on the requested type.

    Args:
        scanner_type: Type of scanner ("zizmor", "opengrep", "all")
        min_severity: Minimum severity level

    Returns:
        Scanner instance or list of scanner instances

    Raises:
        ScannerError: If no scanners could be initialized
    """
    scanners = []

    if scanner_type in ["zizmor", "all"]:
        try:
            scanners.append(ScannerFactory.create_scanner("zizmor", min_severity))
            logger.info("Successfully initialized Zizmor scanner")
        except ScannerError as e:
            logger.warning(f"Could not initialize Zizmor scanner: {e}")

    if scanner_type in ["opengrep", "all"]:
        try:
            scanners.append(ScannerFactory.create_scanner("opengrep", min_severity))
            logger.info("Successfully initialized OpenGrep scanner")
        except ScannerError as e:
            logger.warning(f"Could not initialize OpenGrep scanner: {e}")

    if not scanners:
        # Never silently substitute a different scanner than the one the
        # user asked for: a scan that ran with the wrong tool looks like a
        # clean result.
        raise ScannerError(
            f"No scanners could be initialized for '{scanner_type}'. "
            "Check the installation instructions above."
        )

    # Return single scanner if only one, otherwise return list
    return scanners[0] if len(scanners) == 1 else scanners
