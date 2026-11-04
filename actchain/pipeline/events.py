# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Typed progress events emitted by pipeline stages.

The pipeline is console-free: stages emit these events and the CLI layer
renders them with Rich. Event payload strings may derive from untrusted
repository content — renderers must escape them (display.esc).
"""

from dataclasses import dataclass
from typing import Callable, Optional, Union


@dataclass(frozen=True)
class StageStarted:
    stage: str


@dataclass(frozen=True)
class StageFinished:
    stage: str


@dataclass(frozen=True)
class StageFailed:
    stage: str
    error: str


@dataclass(frozen=True)
class ItemProgress:
    """Fine-grained progress inside a stage (per workflow / action / call)."""

    stage: str
    label: str
    done: int
    total: Optional[int] = None


@dataclass(frozen=True)
class Notice:
    """A user-facing notice (e.g. a workflow that failed to parse)."""

    stage: str
    level: str  # 'info' | 'warning' | 'error'
    title: str
    body: str = ''


ProgressEvent = Union[StageStarted, StageFinished, StageFailed, ItemProgress, Notice]
EventCallback = Callable[[ProgressEvent], None]


def null_callback(_event: ProgressEvent) -> None:
    """No-op callback for headless/test use."""
