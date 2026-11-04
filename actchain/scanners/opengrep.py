# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
OpenGrep scanner implementation for ActChain.
"""

import json
import logging
import re
import subprocess
from typing import Any, Dict, List

import yaml

from .base import BaseScanner, ScannerError
from ..constants import SCANNER_TIMEOUT
from ..utils.security_utils import SecurityUtils
from ..utils.system_utils import SystemUtils

logger = logging.getLogger('actchain.scanners.opengrep')


class OpenGrepScanner(BaseScanner):
    """Scanner implementation using OpenGrep for GitHub Actions security scanning."""

    def __init__(self, min_severity: str = "low"):
        """Initialize the OpenGrep scanner."""
        super().__init__(min_severity)
        self.scanner_name = "OpenGrep Scanner"
        self._opengrep_path = self._ensure_opengrep_available()

    @staticmethod
    def _ensure_opengrep_available() -> str:
        """
        Locate the opengrep executable, falling back to a compatible semgrep
        installation (OpenGrep is a fork with a compatible CLI, and
        ``actchain setup --install-all`` installs semgrep).

        Returns:
            Absolute path to the opengrep (or semgrep) executable

        Raises:
            ScannerError: If neither tool is available
        """
        for tool in ("opengrep", "semgrep"):
            tool_path = SystemUtils.resolve_command(tool)
            if not tool_path:
                continue
            try:
                result = subprocess.run(
                    [tool_path, "--version"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10
                )
                if result.returncode == 0:
                    logger.info(f"Found {tool} version: {result.stdout.strip()}")
                    return tool_path

                logger.warning(f"{tool} version check failed with code {result.returncode}")
                if result.stderr:
                    logger.warning(f"{tool} stderr: {result.stderr[:200]}")
            except subprocess.TimeoutExpired:
                logger.warning(f"{tool} version check timed out")
            except (OSError, subprocess.SubprocessError) as e:
                logger.warning(f"Error checking {tool}: {e}")

        logger.error("OpenGrep is required but not installed. Install options:")
        logger.error("1. Download from: https://github.com/opengrep/opengrep/releases")
        logger.error("2. Or install semgrep: pip install semgrep (or 'actchain setup --install-all')")

        raise ScannerError("OpenGrep (or semgrep) is required but not installed. Please install manually.")

    def scan_workflow(self, content: str, path: str) -> Dict[str, Any]:
        """Scan a workflow file using OpenGrep."""
        scan_id = self.generate_scan_id()

        try:
            # Many GitHub Actions rules are scoped to .github/workflows/
            # paths, so stage the temp copy under that layout.
            with SecurityUtils.secure_temp_dir_file(
                '.github/workflows/workflow.yml', content
            ) as temp_file_path:
                findings = self._run_opengrep_scan(temp_file_path, path)

                # Add fallback pattern matching if no findings
                if not findings:
                    findings.extend(self._fallback_pattern_scan(content, path))

            report = self.create_base_report(scan_id, path)
            report["results"]["findings"] = findings
            return report

        except Exception as e:
            logger.error(f"Error scanning workflow with OpenGrep: {e}")
            return self.create_error_report(scan_id, path, str(e))

    def scan_action(self, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan an action using OpenGrep."""
        if not action_data or 'content' not in action_data:
            scan_id = self.generate_scan_id()
            ref = action_data.get("ref", "unknown") if action_data else "unknown"
            return self.create_error_report(scan_id, f"action_{ref}", "No content available")

        scan_id = self.generate_scan_id()
        ref = action_data.get("ref", "unknown")
        path = f"action_{ref}"

        try:
            # Prefer the original action.yml text (real line numbers); fall
            # back to re-serializing the parsed content.
            raw_content = action_data.get('raw_content')
            if not raw_content:
                raw_content = yaml.dump(action_data['content'])

            with SecurityUtils.secure_temp_dir_file('action.yml', raw_content) as temp_file_path:
                findings = self._run_opengrep_scan(temp_file_path, path)

                # Add fallback pattern matching if no findings
                if not findings:
                    findings.extend(self._fallback_action_scan(raw_content, path))

            report = self.create_base_report(scan_id, path)
            report["action"] = ref
            report["type"] = action_data.get("type", "unknown")
            report["results"]["findings"] = findings
            return report

        except Exception as e:
            logger.error(f"Error scanning action with OpenGrep: {e}")
            return self.create_error_report(scan_id, path, str(e))

    def _run_opengrep_scan(self, file_path: str, original_path: str) -> List[Dict[str, Any]]:
        """
        Run OpenGrep scan on a file.

        Raises:
            ScannerError: If opengrep fails to run, so failures surface in
                reports instead of reading as a clean scan.
        """
        logger.info(f"Scanning with OpenGrep: {original_path}")

        cmd = [
            self._opengrep_path, "scan",
            "--config", "p/github-actions",  # Use built-in rules for GitHub Actions
            "--json",
            "--error",  # Exit with code 1 if findings are found
            file_path
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=SCANNER_TIMEOUT
            )
        except subprocess.TimeoutExpired as e:
            raise ScannerError(f"OpenGrep scan timed out for {original_path}") from e
        except (OSError, subprocess.SubprocessError) as e:
            raise ScannerError(f"OpenGrep process error: {e}") from e

        # Exit code 1 means findings were found (because of --error);
        # anything above 1 is a fatal failure and must surface as an error —
        # even when the tool still printed (partial) JSON — rather than read
        # as a clean scan.
        if result.returncode > 1:
            stderr_snippet = (result.stderr or '').strip()[:500]
            raise ScannerError(
                f"OpenGrep exited with code {result.returncode}. "
                f"stderr: {stderr_snippet}"
            )

        return self._parse_opengrep_output(result.stdout, original_path)

    def _parse_opengrep_output(self, output: str, path: str) -> List[Dict[str, Any]]:
        """Parse OpenGrep output into structured findings."""
        findings = []

        if not output or not output.strip():
            logger.warning("Empty OpenGrep output")
            return findings

        # Log output for debugging
        logger.debug(f"OpenGrep raw output (first 500 chars): {output[:500]}")

        try:
            # Try to parse as JSON
            data = json.loads(output)
            logger.debug(f"Successfully parsed OpenGrep JSON with keys: {list(data.keys())}")

            # Fail closed on tool-reported scan errors (per-file skips, parse
            # failures, rule timeouts). OpenGrep reports these in errors[]
            # while still exiting 0/1, so the exit code alone cannot be
            # trusted; an unreported error would read as a clean scan.
            errors = data.get("errors") or []
            hard_errors = [
                e for e in errors
                if not isinstance(e, dict) or e.get("level", "error") == "error"
            ]
            if hard_errors:
                first = hard_errors[0]
                message = first.get("message", str(first)) if isinstance(first, dict) else str(first)
                raise ScannerError(
                    f"OpenGrep reported {len(hard_errors)} scan error(s); first: {message[:200]}"
                )

            parse_failures = 0

            # Check if the output has the expected structure
            if "results" in data:
                for result in data["results"]:
                    # Skip empty results
                    if not result:
                        continue

                    try:
                        # Extract basic info
                        check_id = result.get("check_id", "unknown").split(".")[-1]

                        # Get message and severity
                        extra = result.get("extra", {})
                        message = extra.get("message", "Unknown issue")
                        severity_str = extra.get("severity", "WARNING")

                        # Map severity
                        severity = self._map_opengrep_severity(severity_str)

                        # Location information. The scan ran on a temp copy,
                        # so always report the real path: temp paths would
                        # leak the local username into reports.
                        start = result.get("start", {})
                        line = start.get("line", 0)
                        col = start.get("col", 0)

                        # Create finding only if it meets the minimum severity
                        if self.should_include_finding(severity):
                            findings.append({
                                "rule_id": check_id,
                                "title": f"{check_id} issue",
                                "severity": severity,
                                "description": message,
                                "location": {
                                    "path": path,
                                    "line": line,
                                    "column": col
                                },
                                "recommendation": f"Review and fix the {check_id} issue",
                                "source_scanner": "OpenGrep Scanner"
                            })
                    except Exception as e:
                        logger.error(f"Error processing a finding: {e}")
                        parse_failures += 1
                        continue

            if parse_failures:
                # A finding we could not parse is a finding the user never
                # sees — surface it as a scan error instead of dropping it.
                raise ScannerError(
                    f"{parse_failures} OpenGrep finding(s) could not be parsed"
                )

        except json.JSONDecodeError:
            # If not JSON, try to parse as plain text
            logger.debug("Failed to parse as JSON, trying plain text format")
            findings.extend(self._parse_opengrep_text_output(output, path))

        logger.info(f"Found {len(findings)} OpenGrep findings")
        return findings

    def _parse_opengrep_text_output(self, output: str, path: str) -> List[Dict[str, Any]]:
        """Parse OpenGrep text output as a fallback."""
        findings = []

        # Different formats OpenGrep might output
        formats = [
            # Format: file:line:column: message
            r'(.*?):(\d+):(\d+):(.*?)$',
            # Format: file:line: message
            r'(.*?):(\d+):(.*?)$',
            # Format with rule ID: file:line: [rule] message
            r'(.*?):(\d+):\s+\[(.*?)\](.*?)$'
        ]

        for line in output.strip().split('\n'):
            parsed = False
            for pattern in formats:
                match = re.match(pattern, line)
                if match:
                    try:
                        if len(match.groups()) == 4:  # file:line:column: message
                            _file_path, line_num, col_num, message = match.groups()
                            rule_id = "unknown"
                        elif len(match.groups()) == 3:  # file:line: message or file:line: [rule] message
                            if '[' in match.group(3):  # Has rule ID
                                _file_path, line_num = match.groups()[:2]
                                rule_match = re.search(r'\[(.*?)\](.*)', match.group(3))
                                if rule_match:
                                    rule_id, message = rule_match.groups()
                                else:
                                    rule_id, message = "unknown", match.group(3)
                                col_num = "0"
                            else:  # No rule ID
                                _file_path, line_num, message = match.groups()
                                rule_id = "unknown"
                                col_num = "0"

                        # Default to medium severity
                        severity = "medium"
                        if "error" in message.lower():
                            severity = "high"
                        elif "warning" in message.lower():
                            severity = "medium"

                        # Add finding if it meets the minimum severity
                        if self.should_include_finding(severity):
                            findings.append({
                                "rule_id": rule_id,
                                "title": f"{rule_id} issue",
                                "severity": severity,
                                "description": message.strip(),
                                "location": {
                                    "path": path,
                                    "line": int(line_num),
                                    "column": int(col_num) if col_num.isdigit() else 0
                                },
                                "recommendation": "Review and fix the issue",
                                "source_scanner": "OpenGrep Scanner"
                            })
                        parsed = True
                        break
                    except Exception as e:
                        logger.error(f"Error parsing text output line: {e}")
                        continue

            if not parsed and line.strip():
                logger.debug(f"Unmatched line format: {line}")

        return findings

    @staticmethod
    def _map_opengrep_severity(severity_str: str) -> str:
        """Map OpenGrep severity to our severity levels."""
        if severity_str == "ERROR":
            return "high"
        elif severity_str == "WARNING":
            return "medium"
        elif severity_str == "INFO":
            return "low"
        else:
            return "medium"  # Default

    def _fallback_pattern_scan(self, content: str, path: str) -> List[Dict[str, Any]]:
        """Fallback pattern-based scanning for workflows."""
        findings = []

        # Check for unpinned actions (using @v1, @v2, etc. instead of commit hashes)
        unpinned_pattern = r'uses:\s+([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)@v\d+'
        for i, line in enumerate(content.split('\n')):
            match = re.search(unpinned_pattern, line)
            if match:
                severity = "high"
                if self.should_include_finding(severity):
                    findings.append({
                        "rule_id": "unpinned-github-action",
                        "title": "Unpinned GitHub Action",
                        "severity": severity,
                        "description": f"GitHub Action {match.group(1)} uses version tag instead of commit hash",
                        "location": {
                            "path": path,
                            "line": i + 1,
                            "column": match.start()
                        },
                        "recommendation": "Pin GitHub Actions to specific commit hashes for better security",
                        "source_scanner": "OpenGrep Scanner"
                    })

        # Check for permissions: write-all
        permissions_pattern = r'permissions:\s+write-all'
        for i, line in enumerate(content.split('\n')):
            if re.search(permissions_pattern, line):
                severity = "medium"
                if self.should_include_finding(severity):
                    findings.append({
                        "rule_id": "excessive-permissions",
                        "title": "Excessive Permissions",
                        "severity": severity,
                        "description": "Workflow uses overly broad write-all permissions",
                        "location": {
                            "path": path,
                            "line": i + 1,
                            "column": line.find("permissions")
                        },
                        "recommendation": "Use fine-grained permissions instead of write-all",
                        "source_scanner": "OpenGrep Scanner"
                    })

        # Check for artifact uploads (potential credential persistence)
        artifact_pattern = r'upload-artifact'
        for i, line in enumerate(content.split('\n')):
            if re.search(artifact_pattern, line):
                severity = "medium"
                if self.should_include_finding(severity):
                    findings.append({
                        "rule_id": "artifact-credential-risk",
                        "title": "Artifact Credential Risk",
                        "severity": severity,
                        "description": "Potential credential persistence through GitHub Actions artifacts",
                        "location": {
                            "path": path,
                            "line": i + 1,
                            "column": line.find("upload-artifact")
                        },
                        "recommendation": "Ensure no credentials or sensitive data are persisted in artifacts",
                        "source_scanner": "OpenGrep Scanner"
                    })

        logger.debug(f"Manual pattern matching found {len(findings)} issues")
        return findings

    def _fallback_action_scan(self, content: str, path: str) -> List[Dict[str, Any]]:
        """Fallback pattern-based scanning for actions."""
        findings = []

        # Check for permissions issues
        if 'permissions' in content and 'write-all' in content:
            severity = "medium"
            if self.should_include_finding(severity):
                findings.append({
                    "rule_id": "excessive-permissions",
                    "title": "Excessive Permissions",
                    "severity": severity,
                    "description": "Action uses overly broad permissions",
                    "location": {
                        "path": path,
                        "line": 1,
                        "column": 1
                    },
                    "recommendation": "Use fine-grained permissions instead of write-all",
                    "source_scanner": "OpenGrep Scanner"
                })

        # Check for token usage
        if 'token' in content and 'github.token' in content:
            severity = "medium"
            if self.should_include_finding(severity):
                findings.append({
                    "rule_id": "token-exposure",
                    "title": "Token Exposure Risk",
                    "severity": severity,
                    "description": "GitHub token may be exposed in the action",
                    "location": {
                        "path": path,
                        "line": 1,
                        "column": 1
                    },
                    "recommendation": "Review token usage for security concerns",
                    "source_scanner": "OpenGrep Scanner"
                })

        logger.debug(f"Manual pattern matching found {len(findings)} issues")
        return findings
