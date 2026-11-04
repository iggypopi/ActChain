# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
ActChain - GitHub Actions Workflow Security Scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ActChain is a tool to analyze the security of GitHub Actions
workflows and their dependent actions.
"""

__version__ = '0.2.0'
__author__ = 'Igor Stepansky'
__license__ = 'MIT'

# Main components
from .core.github_client import GitHubClient
from .core.workflow_parser import WorkflowParser
from .core.action_resolver import ActionResolver
from .scanners.factory import get_scanner
from .reports.manager import ReportManager

__all__ = [
    'GitHubClient',
    'WorkflowParser',
    'ActionResolver',
    'get_scanner',
    'ReportManager',
]
