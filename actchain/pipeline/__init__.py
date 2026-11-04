# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Staged scan pipeline for ActChain.

A scan is a sequence of stages operating on a shared ScanContext:
discovery -> one stage per scanner tool -> optional AI stages ->
policy gate -> reports -> optional pinning PR. Stages are console-free;
they report progress through typed events consumed by the CLI layer.
"""

from .base import Stage, StageError
from .context import (
    ActionNode,
    GateResult,
    PinPlan,
    PinPlanEntry,
    ScanContext,
    SkippedPin,
    StageErrorRecord,
)
from .events import ItemProgress, Notice, StageFailed, StageFinished, StageStarted
from .pipeline import ScanPipeline

__all__ = [
    'ActionNode',
    'GateResult',
    'ItemProgress',
    'Notice',
    'PinPlan',
    'PinPlanEntry',
    'ScanContext',
    'ScanPipeline',
    'SkippedPin',
    'Stage',
    'StageError',
    'StageErrorRecord',
    'StageFailed',
    'StageFinished',
    'StageStarted',
]
