# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Pin-plan builder: textual rewrite of workflow ``uses:`` lines to commit SHAs.

The planner is a pure function over already-scanned data. It never resolves
refs itself (R2): the only SHAs it writes are the ``commit_sha`` values the
GitHub client recorded when the exact action content was fetched and scanned,
so a mutable tag moving after the scan can never be endorsed unseen.

Rewrites are purely textual (R8): the original file formatting, comments and
anchors are preserved, and only the ``@ref`` token of a confirmed step-level
``uses:`` line is replaced. A line-locating regex finds *candidates*; every
candidate is then validated with :func:`actchain.core.refs.parse_action_ref`
and must match a ref the YAML parser extracted for that workflow, which kills
``uses:``-looking text inside ``run:`` scripts and comments.
"""

import difflib
import re
from typing import Any, Dict, List, Optional, Tuple

from ..core.refs import is_full_sha, parse_action_ref
from ..pipeline.context import PinPlan, PinPlanEntry, SkippedPin

# Fixed, non-dynamic skip reasons (rendered verbatim in the PR body).
REASON_REUSABLE_WORKFLOW = 'reusable-workflow (pin manually)'
REASON_NO_REF = 'no ref specified'
REASON_NO_RECORDED_SHA = 'no scanned commit SHA recorded'

# Candidate locator for a block-style step line:
#   [indent][- ]uses: [quote]<token>[quote][spaces][# comment]
# The token charset is deliberately loose — strict validation is done by
# parse_action_ref afterwards, never by this regex.
_BLOCK_USES_RE = re.compile(
    r'^(?P<prefix>[ \t]*(?:-[ \t]+)?uses:[ \t]+)'
    r'(?P<quote>["\'])?'
    r'(?P<token>[^\s"\'#]+)'
    r'(?(quote)(?P=quote))'
    r'(?P<trailing>[ \t]*|[ \t]+#.*)$'
)

# Candidate locator for a flow-mapping step line: "[- ]{ uses: <token> ... }".
_FLOW_USES_RE = re.compile(
    r'^(?P<prefix>[ \t]*(?:-[ \t]+)?\{[ \t]?uses:[ \t]+)'
    r'(?P<quote>["\'])?'
    r'(?P<token>[^\s"\'#,{}]+)'
    r'(?(quote)(?P=quote))'
    r'(?P<suffix>[ \t]*[,}].*)$'
)

# Block scalar header: "key: |" / "key: >" (optionally "- key: |"), with
# optional indentation/chomping indicators and trailing comment. Lines inside
# the scalar are script text, never workflow steps, and must stay untouched.
_BLOCK_SCALAR_HEADER_RE = re.compile(
    r'^(?P<prefix>[ \t]*(?:-[ \t]+)*)'
    r'(?P<key>[^#\n]*?):[ \t]*'
    r'[|>][0-9]*[+-]?[0-9]*[ \t]*(?:#.*)?$'
)


def _block_scalar_key_indent(line: str) -> Optional[int]:
    """Detect a YAML block scalar header and return its key indent.

    For a sequence-entry form (``- run: |``) the key indent is the column of
    the key itself (``run``), i.e. after the dash, so a following sibling key
    at the same depth (``env:``) correctly terminates the scalar.

    Args:
        line: The line text without its line ending.

    Returns:
        The key's column when the line opens a block scalar, else None.
    """
    match = _BLOCK_SCALAR_HEADER_RE.match(line)
    if match is None:
        return None
    return len(match.group('prefix'))


def _indent_width(line: str) -> int:
    """Return the number of leading whitespace characters of a line.

    Args:
        line: The line text without its line ending.

    Returns:
        The leading-whitespace length (YAML forbids tabs in indentation, so
        a plain character count is sufficient).
    """
    return len(line) - len(line.lstrip(' \t'))


def build_pin_plan(
    workflows: List[Dict[str, str]],
    workflow_step_refs: Dict[str, List[str]],
    actions: Dict[str, Dict[str, Any]],
) -> PinPlan:
    """Build the textual pin plan for the scanned workflow files.

    Pure function: no network and no filesystem access. Only SHAs already
    recorded at scan time are written (R2) — refs are never re-resolved.

    Args:
        workflows: Scanned workflow files, each ``{"name", "path", "content"}``.
        workflow_step_refs: Map of workflow path to the raw ``uses:`` refs the
            YAML parser extracted for that file. A candidate line is rewritten
            only if its token is string-equal to one of these refs.
        actions: Map of raw action ref to its resolved action data;
            ``action_data["commit_sha"]`` is the full commit SHA the scanned
            content was fetched at.

    Returns:
        A PinPlan with planned entries, skipped refs, rewritten file contents
        and their scan-time originals (changed files only) and a unified diff
        of all changes.
    """
    plan = PinPlan()

    for workflow in workflows:
        path = workflow.get('path') or ''
        content = workflow.get('content')
        if not path or not isinstance(content, str) or not content:
            continue

        step_refs = set(workflow_step_refs.get(path) or [])
        new_content = _rewrite_workflow(content, path, step_refs, actions, plan)

        if new_content != content:
            plan.new_contents[path] = new_content
            # Scan-time original, so PR creation can verify the repo still
            # matches what was scanned before committing (TOCTOU guard).
            plan.base_contents[path] = content

    plan.diff_text = _build_diff_text(workflows, plan.new_contents)
    return plan


def _rewrite_workflow(
    content: str,
    path: str,
    step_refs: set,
    actions: Dict[str, Dict[str, Any]],
    plan: PinPlan,
) -> str:
    """Rewrite one workflow file line by line, recording entries and skips.

    Args:
        content: Original workflow file text.
        path: Workflow path (used in plan entries).
        step_refs: Raw ``uses:`` refs the parser extracted for this file.
        actions: Resolved action data keyed by raw ref.
        plan: Plan being built; entries/skips are appended in place.

    Returns:
        The rewritten file text (equal to ``content`` when nothing changed).
    """
    lines = content.splitlines(keepends=True)
    scalar_key_indent: Optional[int] = None  # inside a block scalar when set

    for index, raw_line in enumerate(lines):
        line = raw_line.rstrip('\r\n')
        ending = raw_line[len(line):]

        if scalar_key_indent is not None:
            # Inside a run:-style block scalar: blank lines never terminate
            # it, and more-indented lines are scalar content (script text) —
            # untouched even when they look like (or equal) a real step line.
            if not line.strip():
                continue
            if _indent_width(line) > scalar_key_indent:
                continue
            scalar_key_indent = None  # scalar closed; process this line

        if line.strip().startswith('#'):
            continue  # commented-out line

        header_indent = _block_scalar_key_indent(line)
        if header_indent is not None:
            scalar_key_indent = header_indent
            continue

        new_line = _rewrite_line(line, path, index + 1, step_refs, actions, plan)
        if new_line is not None:
            lines[index] = new_line + ending

    return ''.join(lines)


def _match_candidate(line: str) -> Optional[Tuple[str, str, str, str, bool]]:
    """Match a line against the block and flow ``uses:`` locators.

    Args:
        line: The line text without its line ending.

    Returns:
        ``(prefix, quote, token, rest, is_flow)`` for a candidate line, where
        ``rest`` is the trailing text after the token (and closing quote), or
        None when the line is not a ``uses:`` candidate at all.
    """
    match = _BLOCK_USES_RE.match(line)
    if match:
        return (match.group('prefix'), match.group('quote') or '',
                match.group('token'), match.group('trailing'), False)

    match = _FLOW_USES_RE.match(line)
    if match:
        return (match.group('prefix'), match.group('quote') or '',
                match.group('token'), match.group('suffix'), True)

    return None


def _rewrite_line(
    line: str,
    path: str,
    line_number: int,
    step_refs: set,
    actions: Dict[str, Dict[str, Any]],
    plan: PinPlan,
) -> Optional[str]:
    """Apply the pinning decision table (R8) to a single line.

    Args:
        line: Line text without its line ending.
        path: Workflow path for plan records.
        line_number: 1-based line number for plan records.
        step_refs: Parser-confirmed raw refs for this workflow.
        actions: Resolved action data keyed by raw ref.
        plan: Plan being built; entries/skips are appended in place.

    Returns:
        The rewritten line, or None when the line must stay untouched.
    """
    candidate = _match_candidate(line)
    if candidate is None:
        return None
    prefix, quote, token, rest, is_flow = candidate

    parsed = parse_action_ref(token)
    if parsed is None or token not in step_refs:
        # Not a parser-confirmed step ref (e.g. uses:-looking text inside a
        # run: script). Silently ignored — not even a SkippedPin.
        return None

    if parsed.is_sha_pinned:
        return None  # already pinned: idempotent re-runs change nothing

    if parsed.is_reusable_workflow:
        plan.skipped.append(SkippedPin(path, line_number, REASON_REUSABLE_WORKFLOW))
        return None

    if parsed.ref == '':
        plan.skipped.append(SkippedPin(path, line_number, REASON_NO_REF))
        return None

    action_data = actions.get(token)
    sha = action_data.get('commit_sha') if isinstance(action_data, dict) else None
    if not sha or not is_full_sha(str(sha)):
        # R2: we only ever pin SHAs recorded at scan time; anything else
        # (missing, falsy, malformed) means this ref cannot be pinned safely.
        plan.skipped.append(SkippedPin(path, line_number, REASON_NO_RECORDED_SHA))
        return None
    sha = str(sha)

    if sha == parsed.ref:
        return None  # already effectively pinned

    # Replace ONLY the ref substring after '@' within the matched token.
    new_token = token[:len(token) - len(parsed.ref)] + sha
    plan.entries.append(PinPlanEntry(
        workflow_path=path,
        line_number=line_number,
        action_base=parsed.base,
        old_ref=parsed.ref,
        new_sha=sha,
    ))

    rebuilt = f'{prefix}{quote}{new_token}{quote}'
    if is_flow:
        # A trailing comment would break the flow mapping — never append one.
        return rebuilt + rest
    if '#' in rest:
        return rebuilt + rest  # existing comment stays untouched
    return f'{rebuilt}  # {parsed.ref}'


def _build_diff_text(
    workflows: List[Dict[str, str]],
    new_contents: Dict[str, str],
) -> str:
    """Build a unified diff covering every changed workflow file.

    Args:
        workflows: The scanned workflow files (original contents).
        new_contents: Rewritten text per changed workflow path.

    Returns:
        The concatenated ``difflib.unified_diff`` output, one changed file
        after another, joined with newlines ('' when nothing changed).
    """
    diff_lines: List[str] = []
    for workflow in workflows:
        path = workflow.get('path') or ''
        if path not in new_contents:
            continue
        old_text = workflow.get('content') or ''
        diff_lines.extend(difflib.unified_diff(
            old_text.splitlines(),
            new_contents[path].splitlines(),
            fromfile=f'a/{path}',
            tofile=f'b/{path}',
            lineterm='',
        ))
    return '\n'.join(diff_lines)
