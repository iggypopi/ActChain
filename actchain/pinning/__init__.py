# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Action pinning for ActChain: pin-plan building and PR creation.

The planner rewrites scanned workflow text so every parser-confirmed
``uses:`` ref points at the exact commit SHA recorded at scan time (never
re-resolved — R2), and the PR module renders a hardened PR body and opens
the pull request via the Git Data API.
"""

from .planner import build_pin_plan
from .pr import PinningPRError, create_pinning_pr, render_pr_body

__all__ = [
    'PinningPRError',
    'build_pin_plan',
    'create_pinning_pr',
    'render_pr_body',
]
