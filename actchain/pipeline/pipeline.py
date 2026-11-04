# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
The scan pipeline runner.
"""

import logging
from typing import List, Optional

from .base import Stage, StageError
from .context import ScanContext
from .events import EventCallback, StageFailed, StageFinished, StageStarted, null_callback

logger = logging.getLogger('actchain.pipeline')


class ScanPipeline:
    """Runs stages in order over a shared ScanContext.

    Error semantics: a StageError from a non-critical stage is recorded on
    the context and the pipeline continues (fail-closed consumers like the
    policy gate see it in context.errors); a StageError from a critical
    stage aborts the run. Unexpected exceptions are treated as StageErrors
    of the raising stage.
    """

    def __init__(self, stages: List[Stage]):
        self.stages = stages

    def run(self, context: ScanContext, callback: Optional[EventCallback] = None) -> ScanContext:
        emit = callback or null_callback

        for stage in self.stages:
            if not stage.enabled(context):
                logger.debug(f"Stage '{stage.name}' skipped (disabled for this scan)")
                continue

            emit(StageStarted(stage=stage.name))
            try:
                stage.run(context, emit)
            except StageError as e:
                logger.error(f"Stage '{stage.name}' failed: {e}")
                context.add_error(stage.name, '<stage>', str(e))
                emit(StageFailed(stage=stage.name, error=str(e)))
                if stage.critical:
                    raise
                continue
            except Exception as e:  # noqa: BLE001 - isolate unexpected stage bugs
                logger.exception(f"Unexpected error in stage '{stage.name}'")
                context.add_error(stage.name, '<stage>', f'unexpected: {e}')
                emit(StageFailed(stage=stage.name, error=str(e)))
                if stage.critical:
                    raise StageError(f"{stage.name}: {e}") from e
                continue

            emit(StageFinished(stage=stage.name))

        return context
