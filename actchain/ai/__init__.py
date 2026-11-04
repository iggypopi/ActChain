# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Optional AI analysis for ActChain (the ``--ai`` flag, ``actchain[ai]`` extra).

Exposes the budgeted Anthropic client plus the two analysis agents: triage
(annotates tool findings in place) and audit (hunts for malicious behavior in
resolved action definitions).
"""

from .audit import audit_actions
from .client import (
    AIAnalysisError,
    AIAuthenticationFailed,
    AIBatchRefused,
    AIBudgetExhausted,
    AIClient,
)
from .triage import triage_findings

__all__ = [
    'AIAnalysisError',
    'AIAuthenticationFailed',
    'AIBatchRefused',
    'AIBudgetExhausted',
    'AIClient',
    'audit_actions',
    'triage_findings',
]
