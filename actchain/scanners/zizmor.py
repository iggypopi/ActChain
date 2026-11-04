# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Zizmor scanner implementation for ActChain.
"""

import logging
import re
import subprocess
from typing import Any, Dict, List, Optional

import yaml

from .base import BaseScanner, ScannerError
from ..constants import SCANNER_TIMEOUT
from ..utils.security_utils import SecurityUtils
from ..utils.system_utils import SystemUtils

logger = logging.getLogger('actchain.scanners.zizmor')


class ZizmorScanner(BaseScanner):
    """Scanner implementation using Zizmor for GitHub Actions security scanning."""

    def __init__(self, min_severity: str = "low"):
        """Initialize the Zizmor scanner."""
        super().__init__(min_severity)
        self.scanner_name = "Zizmor Scanner"
        self._zizmor_path = self._ensure_zizmor_available()

    @staticmethod
    def _ensure_zizmor_available() -> str:
        """
        Locate the zizmor executable.

        Deliberately does NOT install anything: mutating the user's Python
        environment with an unpinned package as a side effect of running a
        scan would be a consent and supply-chain problem. Users can install
        zizmor explicitly (``pip install zizmor`` or ``actchain setup
        --install-all``).

        Returns:
            Absolute path to the zizmor executable

        Raises:
            ScannerError: If zizmor is not available
        """
        zizmor_path = SystemUtils.resolve_command("zizmor")
        if zizmor_path:
            try:
                result = subprocess.run(
                    [zizmor_path, "--version"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10
                )
                if result.returncode == 0:
                    logger.info(f"Found zizmor version: {result.stdout.strip()}")
                    return zizmor_path
            except (OSError, subprocess.TimeoutExpired, subprocess.SubprocessError):
                pass

        raise ScannerError(
            "Zizmor is required but not available. "
            "Install it with 'pip install zizmor' (or 'actchain setup --install-all') "
            "and make sure it is on your PATH."
        )

    def scan_workflow(self, content: str, path: str) -> Dict[str, Any]:
        """Scan a workflow file using Zizmor."""
        scan_id = self.generate_scan_id()

        try:
            # Zizmor infers the file kind from its name: any .yml that is not
            # action.yml/action.yaml is treated as a workflow.
            with SecurityUtils.secure_temp_dir_file('workflow.yml', content) as temp_file_path:
                findings = self._run_zizmor_scan(temp_file_path, path)

            report = self.create_base_report(scan_id, path)
            report["results"]["findings"] = findings
            return report

        except Exception as e:
            logger.error(f"Error scanning workflow with Zizmor: {e}")
            return self.create_error_report(scan_id, path, str(e))

    def scan_action(self, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan an action using Zizmor."""
        if not action_data or 'content' not in action_data:
            scan_id = self.generate_scan_id()
            ref = action_data.get("ref", "unknown") if action_data else "unknown"
            return self.create_error_report(scan_id, f"action_{ref}", "No content available")

        scan_id = self.generate_scan_id()
        ref = action_data.get("ref", "unknown")
        path = f"action_{ref}"

        try:
            # Zizmor only audits files literally named action.yml/action.yaml
            # as actions, so the temp file must carry that name. Prefer the
            # original file text so audited line numbers match the real file;
            # fall back to re-serializing the parsed content.
            raw_content = action_data.get('raw_content')
            if not raw_content:
                raw_content = yaml.dump(action_data['content'])

            with SecurityUtils.secure_temp_dir_file('action.yml', raw_content) as temp_file_path:
                findings = self._run_zizmor_scan(temp_file_path, path)

            report = self.create_base_report(scan_id, path)
            report["action"] = ref
            report["type"] = action_data.get("type", "unknown")
            report["results"]["findings"] = findings
            return report

        except Exception as e:
            logger.error(f"Error scanning action with Zizmor: {e}")
            return self.create_error_report(scan_id, path, str(e))

    def _run_zizmor_scan(self, file_path: str, original_path: str) -> List[Dict[str, Any]]:
        """
        Run Zizmor scan on a file.

        Raises:
            ScannerError: If zizmor fails to run or reports a fatal error,
                so failures surface in reports instead of reading as a clean
                scan with zero findings.
        """
        logger.info(f"Scanning with Zizmor: {original_path}")
        cmd = [self._zizmor_path, "--format=plain", file_path]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=SCANNER_TIMEOUT
            )
        except subprocess.TimeoutExpired as e:
            raise ScannerError(f"Zizmor scan timed out for {original_path}") from e
        except (OSError, subprocess.SubprocessError) as e:
            raise ScannerError(f"Zizmor process error: {e}") from e

        findings = self._parse_zizmor_output(result.stdout, original_path)

        # Zizmor uses non-zero exit codes when findings exist, so an exit
        # code alone is not an error. An error is: nothing parseable on
        # stdout AND a non-zero exit.
        if not findings and not (result.stdout or '').strip() and result.returncode != 0:
            stderr_snippet = (result.stderr or '').strip()[:500]
            raise ScannerError(
                f"Zizmor exited with code {result.returncode} and no output. "
                f"stderr: {stderr_snippet}"
            )

        return findings

    def _parse_zizmor_output(self, output: str, path: str) -> List[Dict[str, Any]]:
        """Parse Zizmor plain output into structured findings."""
        findings = []

        if not output or not output.strip():
            return findings

        # Pattern to match Zizmor finding headers. Anchored to the start of a
        # line: zizmor's plain output echoes lines of the scanned (untrusted)
        # file inside gutter-prefixed snippets ("  12 | ..."), so an
        # unanchored pattern would let a scanned file forge findings by
        # containing text like "error[fake-rule]: ...".
        finding_pattern = r'^(error|warning|help|note)\[([^\]]+)\]:[ \t]+(.*?)(?=(?:\n\s*-->|\n\n|\Z))'
        # Non-greedy path match so Windows drive letters (C:\...) parse too.
        location_pattern = r'-->\s+(.+?):(\d+):(\d+)'

        matches = re.finditer(finding_pattern, output, re.DOTALL | re.MULTILINE)

        for match in matches:
            try:
                finding_type, audit_id, description = match.groups()
                # Bound attacker-influenced text (the description quotes
                # scanned content).
                description = description.strip()[:2000]

                # Extract location information
                location = self._extract_location(output, match.end(), location_pattern)
                if location:
                    # The scan ran on a temp copy; report the real path.
                    location["path"] = path
                else:
                    location = {"path": path, "line": 0, "column": 0}

                # Map to severity
                severity = self._map_zizmor_severity(finding_type)

                # Only include findings that meet the minimum severity level
                if self.should_include_finding(severity):
                    findings.append({
                        "rule_id": audit_id,
                        "title": f"{audit_id} issue",
                        "severity": severity,
                        "description": description,
                        "location": location,
                        "recommendation": f"Review the {audit_id} usage and fix according to Zizmor recommendations."
                    })
            except Exception as e:
                logger.error(f"Error parsing Zizmor finding: {e}")
                continue

        return findings

    def _extract_location(self, output: str, start_pos: int, pattern: str) -> Optional[Dict[str, Any]]:
        """Extract location information from Zizmor output."""
        location_text = output[start_pos:start_pos + 200]
        location_match = re.search(pattern, location_text)

        if location_match:
            try:
                file_path, line, col = location_match.groups()
                return {
                    "path": file_path.strip(),
                    "line": int(line),
                    "column": int(col)
                }
            except ValueError:
                return None
        return None

    @staticmethod
    def _map_zizmor_severity(finding_type: str) -> str:
        """
        Map Zizmor finding types to severity levels.

        Mapping is based only on the finding type. The finding message is
        attacker-influenced (it quotes scanned content), so it must not be
        allowed to change the reported severity.
        """
        type_mapping = {
            "error": "high",
            "warning": "medium",
            "help": "low",
            "note": "low"
        }
        return type_mapping.get(finding_type, "medium")
