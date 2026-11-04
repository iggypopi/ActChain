# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Shared state for a scan pipeline run.

ScanContext.findings is the single source of truth for findings: every
finding gets a stable ``finding_id`` when added, AI triage annotates those
dicts in place, and the consolidated report is generated from this list.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ActionNode:
    """One node of a workflow's resolved action dependency tree (plain data —
    the CLI layer renders Rich trees from this)."""

    ref: str
    depth: int
    # 'resolved' | 'unresolved' | 'docker' | 'local' | 'already_processed'
    # | 'max_depth' | 'limit' | 'error'
    status: str
    children: List['ActionNode'] = field(default_factory=list)
    findings_count: int = 0
    note: str = ''


@dataclass
class StageErrorRecord:
    """A per-item or per-stage error, recorded without aborting the scan."""

    stage: str
    item: str
    message: str


@dataclass
class GateResult:
    """Outcome of the pinning policy gate.

    The gate is monotonic and fail-closed: only raw tool findings and
    AI-audit findings count toward it (AI triage can never exempt a finding),
    and any scan error, discovery truncation, or missing scanner coverage
    fails it.
    """

    evaluated: bool = False
    passed: bool = False
    reasons: List[str] = field(default_factory=list)
    blocking_findings: List[Dict[str, Any]] = field(default_factory=list)
    excluded_findings: int = 0  # findings skipped because pinning remediates them
    threshold: str = 'high'


@dataclass
class PinPlanEntry:
    """One planned rewrite of a workflow ``uses:`` line."""

    workflow_path: str
    line_number: int
    action_base: str   # owner/repo[/subpath]
    old_ref: str       # the mutable ref being replaced
    new_sha: str       # full 40-hex commit SHA recorded at scan time


@dataclass
class SkippedPin:
    """A ``uses:`` entry that could not or should not be pinned."""

    workflow_path: str
    line_number: int
    reason: str  # machine-ish slug + short text; NEVER raw workflow line content


@dataclass
class PinPlan:
    entries: List[PinPlanEntry] = field(default_factory=list)
    skipped: List[SkippedPin] = field(default_factory=list)
    new_contents: Dict[str, str] = field(default_factory=dict)  # workflow_path -> rewritten file text
    # Scan-time ORIGINAL text of each file in new_contents; PR creation
    # verifies the repo still matches before committing (TOCTOU guard).
    base_contents: Dict[str, str] = field(default_factory=dict)
    diff_text: str = ''


@dataclass
class ScanContext:
    """Mutable shared state passed through the pipeline stages."""

    # Inputs
    config: Dict[str, Any]
    github_client: Any = None
    workflow_parser: Any = None
    action_resolver: Any = None
    report_manager: Any = None
    scanners: List[Any] = field(default_factory=list)
    workflows: List[Dict[str, str]] = field(default_factory=list)  # name/path/content

    # Discovery output
    parsed_workflows: Dict[str, Dict[str, Any]] = field(default_factory=dict)   # path -> parsed yaml
    workflow_step_refs: Dict[str, List[str]] = field(default_factory=dict)      # path -> step-level uses refs
    action_nodes: Dict[str, List[ActionNode]] = field(default_factory=dict)     # workflow path -> roots
    actions: Dict[str, Dict[str, Any]] = field(default_factory=dict)            # ref -> action_data (resolved only)
    action_depths: Dict[str, int] = field(default_factory=dict)                 # ref -> first-seen depth
    discovery_truncated: bool = False
    skipped_workflows: List[str] = field(default_factory=list)                  # paths that failed to parse

    # Scan output
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[StageErrorRecord] = field(default_factory=list)

    # AI output
    ai_client: Any = None  # shared AIClient so both AI stages draw on one call budget
    ai_summary: Dict[str, Any] = field(default_factory=dict)

    # Gate / pinning
    gate: Optional[GateResult] = None
    pin_plan: Optional[PinPlan] = None
    pr_url: Optional[str] = None

    # Reporting
    report_paths: Dict[str, Optional[str]] = field(default_factory=dict)

    _finding_counter: int = 0

    # ------------------------------------------------------------------
    def add_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Add a finding, assigning its stable finding_id."""
        self._finding_counter += 1
        finding['finding_id'] = f'f-{self._finding_counter:04d}'
        self.findings.append(finding)
        return finding

    def add_error(self, stage: str, item: str, message: str) -> None:
        self.errors.append(StageErrorRecord(stage=stage, item=item, message=str(message)[:500]))

    def findings_by_id(self) -> Dict[str, Dict[str, Any]]:
        return {f['finding_id']: f for f in self.findings if 'finding_id' in f}

    def malicious_findings(self) -> List[Dict[str, Any]]:
        return [f for f in self.findings if f.get('malicious')]

    def action_count_by_depth(self) -> Dict[int, int]:
        """Distinct RESOLVED actions per first-seen depth (report stat).

        Unresolved refs and docker:// images are not counted here; they show
        up as tree nodes and, under --create-pr, as policy-gate reasons.
        """
        counts: Dict[int, int] = {}
        for depth in self.action_depths.values():
            counts[depth] = counts.get(depth, 0) + 1
        return counts
