# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Report manager for ActChain.
"""

import json
import logging
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set, Any, Optional

from ..constants import REPORT_VERSION
from ..utils.path_utils import PathUtils
from ..utils.file_utils import FileUtils
from ..utils.system_utils import SystemUtils

logger = logging.getLogger('actchain.reports.manager')

# Ordering weight for report sorting (malicious findings are sorted first
# independently of this).
_SEVERITY_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}


class ReportManagerError(Exception):
    """Custom exception for report manager errors."""
    pass


class ReportManager:
    """Manages report generation and storage for ActChain."""

    def __init__(self, output_dir: str):
        """
        Initialize the report manager.

        Args:
            output_dir: Directory to save reports

        Raises:
            ReportManagerError: If initialization fails
        """
        try:
            self.output_dir = PathUtils.validate_path(output_dir)
            self.scan_dir = self._create_scan_directory()
            self.reports: List[Dict[str, Any]] = []

            logger.info(f"Report manager initialized with output directory: {self.scan_dir}")
        except Exception as e:
            raise ReportManagerError(f"Failed to initialize report manager: {e}") from e

    def save_report(self, report: Dict[str, Any], name: str) -> Optional[str]:
        """
        Save a report to a file.

        Args:
            report: Report data
            name: Name for the report

        Returns:
            Path to the saved report or None if failed
        """
        try:
            # Sanitize filename
            safe_name = PathUtils.sanitize_filename(name)
            file_path = self.scan_dir / f"{safe_name}.json"

            # Different raw names can sanitize to the same filename; never
            # silently overwrite another report.
            if file_path.exists():
                file_path = self.scan_dir / f"{safe_name}_{uuid.uuid4().hex[:8]}.json"

            # Save report
            if FileUtils.safe_write_file(json.dumps(report, indent=2), file_path):
                logger.debug(f"Saved report to {file_path}")
                self.reports.append({
                    "name": name,
                    "path": str(file_path),
                    "data": report
                })
                return str(file_path)
            else:
                logger.error(f"Failed to save report {name}")
                return None

        except Exception as e:
            logger.error(f"Error saving report {name}: {e}")
            return None

    def save_workflow_tree(self, tree_text: Any, name: str = "workflow_tree") -> Optional[str]:
        """
        Save the workflow dependency tree representation.

        Args:
            tree_text: Tree text representation or Rich Tree object
            name: Base file name (one file per scanned workflow, so
                multi-workflow scans do not overwrite each other)

        Returns:
            Path to the saved tree file or None if failed
        """
        safe_name = PathUtils.sanitize_filename(name) or "workflow_tree"
        file_path = self.scan_dir / f"{safe_name}.txt"

        # Different workflow names can sanitize to the same filename; never
        # silently overwrite another workflow's tree.
        if file_path.exists():
            file_path = self.scan_dir / f"{safe_name}_{uuid.uuid4().hex[:8]}.txt"

        try:
            # Handle Rich Tree objects
            if hasattr(tree_text, '__rich__') or 'rich.tree.Tree' in str(type(tree_text)):
                content = self._render_rich_tree(tree_text)
            else:
                content = str(tree_text)

            if FileUtils.safe_write_file(content, file_path):
                logger.debug(f"Saved workflow tree to {file_path}")
                return str(file_path)
            else:
                return None

        except Exception as e:
            logger.error(f"Failed to save workflow tree: {e}")
            return None

    def generate_consolidated_report(
            self,
            findings: List[Dict[str, Any]],
            dependencies: List[Dict[str, Any]],
            action_count_by_depth: Dict[int, int],
            workflow: Dict[str, str],
            gate: Optional[Dict[str, Any]] = None,
            ai: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Generate the consolidated report from explicit scan outputs.

        The findings list is the pipeline's single source of truth — it
        already carries finding_id, source_scanner and any AI annotations.

        Args:
            findings: All normalized findings from every scanner/AI stage
            dependencies: [{name, type, depth, findings_count}] per action
            action_count_by_depth: Distinct actions per first-seen depth
            workflow: {"name": ..., "path": ...} of the primary workflow
            gate: Optional pinning policy-gate outcome
            ai: Optional AI analysis summary (model, calls, coverage)

        Returns:
            Path to the consolidated report or None if failed
        """
        file_path = self.scan_dir / "consolidated_report.json"

        try:
            statistics: Dict[str, Any] = {
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
                "dependency_counts": {
                    "total": len(dependencies),
                    "by_depth": {str(d): c for d, c in sorted(action_count_by_depth.items())},
                },
                "scanner_counts": {},
            }
            # Malicious findings first, then by severity — the most
            # decision-relevant entries lead every report format.
            ordered_findings = sorted(
                findings,
                key=lambda f: (
                    not f.get("malicious", False),
                    -_SEVERITY_ORDER.get(str(f.get("severity", "low")).lower(), 1),
                ),
            )
            for finding in ordered_findings:
                self._update_finding_statistics(statistics, finding)

            consolidated: Dict[str, Any] = {
                "meta": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "scan_id": self.scan_dir.name,
                    "total_reports": len(self.reports),
                    "report_version": REPORT_VERSION,
                },
                "workflow": {
                    "name": workflow.get("name", "unknown"),
                    "path": workflow.get("path", "unknown"),
                },
                "findings": ordered_findings,
                "dependencies": dependencies,
                "statistics": statistics,
            }
            if gate is not None:
                consolidated["gate"] = gate
            if ai is not None:
                consolidated["ai"] = ai

            if FileUtils.safe_write_file(json.dumps(consolidated, indent=2), file_path):
                logger.info(f"Generated consolidated report: {file_path}")
                return str(file_path)
            return None

        except Exception as e:
            logger.error(f"Failed to generate consolidated report: {e}")
            return None

    def generate_dependency_graph(
            self,
            processed_actions: Set[str],
            action_count_by_depth: Dict[int, int]
    ) -> Optional[str]:
        """
        Generate a dependency graph visualization.

        Args:
            processed_actions: Set of processed actions
            action_count_by_depth: Action count by depth

        Returns:
            Path to the generated graph file or None if failed
        """
        dot_binary = SystemUtils.resolve_command("dot")
        if not dot_binary:
            logger.warning("Graphviz not installed, cannot generate dependency graph")
            return None

        dot_path = self.scan_dir / "dependency_graph.dot"
        png_path = self.scan_dir / "dependency_graph.png"

        try:
            # Generate DOT file
            dot_content = self._generate_dot_content(processed_actions)
            if not FileUtils.safe_write_file(dot_content, dot_path):
                return None

            # Generate PNG
            try:
                subprocess.run(
                    [dot_binary, "-Tpng", str(dot_path), "-o", str(png_path)],
                    check=True,
                    timeout=60
                )
                logger.info(f"Generated dependency graph: {png_path}")
                return str(png_path)
            except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
                logger.error(f"Failed to run dot: {e}")
                return str(dot_path)

        except Exception as e:
            logger.error(f"Error generating dependency graph: {e}")
            return None

    def _create_scan_directory(self) -> Path:
        """Create a unique scan directory for this run."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_id = str(uuid.uuid4())[:8]
        scan_dir = self.output_dir / f"scan_{timestamp}_{scan_id}"

        try:
            scan_dir.mkdir(parents=True, exist_ok=True)
            return scan_dir
        except Exception as e:
            raise ReportManagerError(f"Failed to create scan directory: {e}") from e

    def _render_rich_tree(self, tree_text: Any) -> str:
        """Render Rich Tree object to string."""
        try:
            from rich.console import Console
            import io

            string_io = io.StringIO()
            console = Console(file=string_io, width=120)
            console.print(tree_text)
            return string_io.getvalue()
        except Exception as e:
            logger.error(f"Failed to render Rich tree: {e}")
            return str(tree_text)

    def _update_finding_statistics(self, statistics: Dict[str, Any], finding: Dict[str, Any]) -> None:
        """Update statistics with finding information."""
        # Update severity counts; unexpected severities count as "low" so
        # totals always match the per-severity breakdown.
        severity = str(finding.get("severity", "low")).lower()
        if severity not in ("critical", "high", "medium", "low"):
            severity = "low"
        statistics["severity_counts"][severity] += 1
        statistics["severity_counts"]["total"] += 1

        # Update scanner counts
        scanner_name = finding.get("source_scanner", "unknown")
        if scanner_name not in statistics["scanner_counts"]:
            statistics["scanner_counts"][scanner_name] = 0
        statistics["scanner_counts"][scanner_name] += 1

    def _generate_dot_content(self, processed_actions: Set[str]) -> str:
        """Generate DOT file content for dependency graph."""
        lines = [
            'digraph DependencyGraph {',
            '  rankdir=LR;',
            '  node [shape=box, style="filled", fillcolor=lightblue];',
            ''
        ]

        # Add nodes. Action refs come from untrusted workflow content, so
        # both the node id and the label must be neutralized before being
        # placed inside DOT string literals.
        for action in sorted(processed_actions):
            node_id = self._sanitize_node_id(action)
            label = self._escape_dot_string(action)
            lines.append(f'  "{node_id}" [label="{label}"];')

        lines.append('}')
        return '\n'.join(lines)

    def _sanitize_node_id(self, action_ref: str) -> str:
        """Sanitize action reference for use as node ID."""
        return re.sub(r'[^a-zA-Z0-9_]', '_', action_ref)

    @staticmethod
    def _escape_dot_string(value: str) -> str:
        """Escape a string for safe inclusion in a double-quoted DOT literal."""
        cleaned = re.sub(r'[\x00-\x1f\x7f]', '', value)
        return cleaned.replace('\\', '\\\\').replace('"', '\\"')
