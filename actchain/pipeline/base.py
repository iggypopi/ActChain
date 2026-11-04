# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Stage base class and error type for the scan pipeline.
"""

from abc import ABC, abstractmethod

from .context import ScanContext
from .events import EventCallback


class StageError(Exception):
    """A whole-stage failure.

    Stages handle per-item failures internally (recording them via
    ``context.add_error`` and, for scanners, as error reports) and raise
    StageError only when the stage as a whole cannot do its job (e.g. zero
    workflows parseable, scanner binary missing at stage construction).
    """


class Stage(ABC):
    """One pipeline stage. Stages are console-free: progress goes through
    the event callback, never directly to a terminal."""

    name: str = 'stage'
    #: When True, a StageError from this stage aborts the pipeline.
    critical: bool = False

    def enabled(self, context: ScanContext) -> bool:
        """Whether this stage should run for this context (default: yes)."""
        return True

    @abstractmethod
    def run(self, context: ScanContext, emit: EventCallback) -> None:
        """Execute the stage, mutating the shared context."""
