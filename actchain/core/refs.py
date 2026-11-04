# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Centralized parsing and validation of GitHub Action references.

A single strict grammar is used everywhere a ref is parsed (resolver, GitHub
client, pinning), so subpath actions (``owner/repo/path@ref``) behave
consistently and malformed/hostile strings are rejected early.
"""

import re
from dataclasses import dataclass
from typing import Optional

# GitHub owner: 1-39 chars, alphanumeric or hyphen, no leading hyphen.
_OWNER = r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?'
# Repository name: GitHub allows letters, digits, '.', '_', '-'.
_REPO = r'[A-Za-z0-9._-]{1,100}'
# Optional subpath inside the repository (composite actions in subfolders).
_SUBPATH = r'(?:/[A-Za-z0-9._-]+)*'
# Git ref: tag, branch (may contain '/'), or commit SHA. No spaces, no '@',
# no YAML/GitHub expression characters.
_REF = r'[A-Za-z0-9._/-]{1,255}'

_ACTION_REF_RE = re.compile(
    rf'^(?P<owner>{_OWNER})/(?P<repo>{_REPO})(?P<subpath>{_SUBPATH})(?:@(?P<ref>{_REF}))?$'
)

_FULL_SHA_RE = re.compile(r'^[0-9a-f]{40}$')
_SHORT_SHA_RE = re.compile(r'^[0-9a-f]{7,39}$')


@dataclass(frozen=True)
class ActionRef:
    """A parsed ``uses:`` reference of the form owner/repo[/subpath][@ref]."""

    owner: str
    repo: str
    subpath: str  # '' or 'path/inside/repo'
    ref: str      # '' when no @ref was given
    raw: str      # the original string

    @property
    def repo_full_name(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def base(self) -> str:
        """owner/repo plus subpath, without the ref."""
        return f"{self.repo_full_name}/{self.subpath}" if self.subpath else self.repo_full_name

    @property
    def is_sha_pinned(self) -> bool:
        return bool(_FULL_SHA_RE.match(self.ref))

    @property
    def is_short_sha(self) -> bool:
        return bool(_SHORT_SHA_RE.match(self.ref))

    @property
    def is_reusable_workflow(self) -> bool:
        """True for job-level reusable workflow refs (owner/repo/.github/workflows/x.yml@ref)."""
        return self.subpath.startswith('.github/workflows/')


def parse_action_ref(raw: str) -> Optional[ActionRef]:
    """
    Parse an action reference against the strict grammar.

    Returns None for anything that is not a plain remote action reference:
    docker:// images, local ./ actions, expression refs (``${{ ... }}``),
    and malformed or hostile strings.
    """
    if not raw or not isinstance(raw, str):
        return None
    if raw.startswith(('docker://', './', '/')):
        return None
    if '${{' in raw or any(c.isspace() for c in raw):
        return None

    match = _ACTION_REF_RE.match(raw)
    if not match:
        return None

    return ActionRef(
        owner=match.group('owner'),
        repo=match.group('repo'),
        subpath=match.group('subpath').lstrip('/'),
        ref=match.group('ref') or '',
        raw=raw,
    )


def is_full_sha(value: str) -> bool:
    """True if value is a full 40-hex commit SHA."""
    return bool(_FULL_SHA_RE.match(value or ''))
