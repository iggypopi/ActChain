# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

import pytest

from actchain.scanners import factory
from actchain.scanners.base import ScannerError


class TestGetScanner:
    def test_unknown_type_raises(self):
        with pytest.raises(ScannerError, match="Unknown scanner type"):
            factory.ScannerFactory.create_scanner("nonexistent")

    def test_explicit_scanner_failure_does_not_fall_back(self, monkeypatch):
        # Requesting opengrep and silently getting zizmor would make a scan
        # look clean while the requested tool never ran.
        def failing_create(scanner_type, min_severity="low"):
            raise ScannerError(f"{scanner_type} unavailable")

        monkeypatch.setattr(factory.ScannerFactory, "create_scanner", staticmethod(failing_create))
        with pytest.raises(ScannerError, match="No scanners could be initialized"):
            factory.get_scanner("opengrep")
