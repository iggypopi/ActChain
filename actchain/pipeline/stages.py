# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
The concrete pipeline stages.

Order for a scan: DiscoveryStage -> one ScannerStage per scanner ->
AITriageStage -> AIAuditStage (both opt-in) -> PolicyGateStage ->
ReportStage -> PinningPRStage. See the Stage base class for error
semantics; see GateResult for the fail-closed gate invariants.
"""

import json
import logging
from collections import Counter
from typing import Dict, List, Optional, Set

from .base import Stage, StageError
from .context import ActionNode, GateResult, ScanContext
from .events import EventCallback, ItemProgress, Notice
from ..constants import (
    MALICIOUS_RULE_IDS,
    MAX_TOTAL_ACTIONS,
    PIN_REMEDIATED_RULE_IDS,
    SEVERITY_LEVELS,
)
from ..core.workflow_parser import WorkflowParseError
from ..utils.file_utils import FileUtils

logger = logging.getLogger('actchain.pipeline.stages')

# Error sources that represent incomplete scan coverage (the policy gate
# fails closed on these; AI-stage problems are advisory and never counted).
_COVERAGE_STAGES_PREFIXES = ('discovery', 'scan:')


def _is_coverage_error(stage_name: str) -> bool:
    return any(stage_name == p or stage_name.startswith(p) for p in _COVERAGE_STAGES_PREFIXES)


class DiscoveryStage(Stage):
    """Parse workflows and recursively resolve the action dependency chain.

    Produces plain-data ActionNode trees plus the ref -> action_data map.
    Per-workflow parse failures are recorded and skipped; the stage fails
    only when no workflow could be parsed at all.
    """

    name = 'discovery'
    critical = True

    def run(self, context: ScanContext, emit: EventCallback) -> None:
        processed: Set[str] = set()
        total = len(context.workflows)

        for index, workflow in enumerate(context.workflows, 1):
            path = workflow['path']
            emit(ItemProgress(stage=self.name, label=f"parsing {workflow['name']}",
                              done=index, total=total))
            try:
                parsed = context.workflow_parser.parse(workflow['content'])
            except WorkflowParseError as e:
                context.skipped_workflows.append(path)
                context.add_error(self.name, path, str(e))
                emit(Notice(stage=self.name, level='warning',
                            title=f"Workflow parsing failed: {workflow['name']}",
                            body=str(e)))
                continue

            context.parsed_workflows[path] = parsed
            refs = context.workflow_parser.extract_actions(parsed)
            context.workflow_step_refs[path] = sorted(refs)

            roots: List[ActionNode] = []
            for ref in sorted(refs):
                roots.append(self._discover(context, ref, 0, processed, emit))
            context.action_nodes[path] = roots

        if not context.parsed_workflows:
            raise StageError("No workflows could be parsed")

    def _discover(self, context: ScanContext, ref: str, depth: int,
                  processed: Set[str], emit: EventCallback) -> ActionNode:
        """Resolve one action and its dependencies into an ActionNode."""
        max_depth = context.config.get('max_depth', 5)

        if ref in processed:
            return ActionNode(ref=ref, depth=depth, status='already_processed')
        if depth >= max_depth:
            return ActionNode(ref=ref, depth=depth, status='max_depth')
        if len(processed) >= MAX_TOTAL_ACTIONS:
            if not context.discovery_truncated:
                logger.warning(
                    f"Reached the limit of {MAX_TOTAL_ACTIONS} resolved actions; "
                    "remaining references will not be scanned."
                )
            context.discovery_truncated = True
            return ActionNode(ref=ref, depth=depth, status='limit')
        if ref.startswith('docker://'):
            return ActionNode(ref=ref, depth=depth, status='docker')

        processed.add(ref)

        try:
            action_data = context.action_resolver.resolve_action(ref)
        except Exception as e:  # noqa: BLE001 - per-item isolation
            context.add_error(self.name, ref, f"resolution error: {e}")
            return ActionNode(ref=ref, depth=depth, status='error', note=str(e)[:200])

        if not action_data:
            return ActionNode(ref=ref, depth=depth, status='unresolved')

        # Depth statistics count RESOLVED actions only (first-seen depth);
        # unresolved refs appear as tree nodes and gate reasons instead.
        context.action_depths.setdefault(ref, depth)
        context.actions[ref] = action_data
        emit(ItemProgress(stage=self.name, label=f"resolved {ref}",
                          done=len(processed), total=None))

        children: List[ActionNode] = []
        if depth < max_depth:
            try:
                dependencies = context.action_resolver.get_action_dependencies(
                    action_data, context.workflow_parser
                )
            except Exception as e:  # noqa: BLE001
                context.add_error(self.name, ref, f"dependency extraction error: {e}")
                dependencies = set()
            for dep in sorted(dependencies):
                children.append(self._discover(context, dep, depth + 1, processed, emit))

        return ActionNode(ref=ref, depth=depth, status='resolved', children=children)


class ScannerStage(Stage):
    """Run one scanner over every parsed workflow and resolved action."""

    critical = False

    def __init__(self, scanner, scanner_index: int):
        self.scanner = scanner
        self.scanner_index = scanner_index
        self.name = f'scan:{scanner.scanner_name}'

    def run(self, context: ScanContext, emit: EventCallback) -> None:
        workflows_by_path = {w['path']: w for w in context.workflows}
        items = list(context.parsed_workflows.keys())
        total = len(items) + len(context.actions)
        done = 0

        for path in items:
            workflow = workflows_by_path[path]
            done += 1
            emit(ItemProgress(stage=self.name, label=workflow['name'], done=done, total=total))
            try:
                report = self.scanner.scan_workflow(workflow['content'], path)
            except Exception as e:  # noqa: BLE001 - per-item isolation
                context.add_error(self.name, path, str(e))
                continue
            self._ingest_report(context, report, item=path,
                                workflow_name=workflow['name'])
            base_name = workflow['name'].replace('.yml', '').replace('.yaml', '')
            context.report_manager.save_report(
                report, f"main_workflow_{base_name}_{self.scanner_index}")

        for ref, action_data in context.actions.items():
            done += 1
            emit(ItemProgress(stage=self.name, label=ref, done=done, total=total))
            try:
                report = self.scanner.scan_action(action_data)
            except Exception as e:  # noqa: BLE001
                context.add_error(self.name, ref, str(e))
                continue
            self._ingest_report(context, report, item=ref)
            depth = context.action_depths.get(ref, 0)
            report_name = f"action_{ref.replace('/', '_')}_depth_{depth}_{self.scanner_index}"
            context.report_manager.save_report(report, report_name)

    def _ingest_report(self, context: ScanContext, report: Dict, item: str,
                       workflow_name: Optional[str] = None) -> None:
        results = report.get('results', {})

        # Fail-closed bookkeeping: a scanner error report means this item was
        # NOT fully scanned; the policy gate must know. Key presence counts —
        # an empty error message is still an error.
        if 'error' in results:
            context.add_error(self.name, item, str(results['error']) or 'scanner error (no message)')

        for finding in results.get('findings', []):
            finding['source_scanner'] = self.scanner.scanner_name
            if workflow_name:
                finding['workflow_name'] = workflow_name
            if finding.get('rule_id') in MALICIOUS_RULE_IDS:
                finding['malicious'] = True
            context.add_finding(finding)


class AITriageStage(Stage):
    """Optional: AI agent that validates/prioritizes the tool findings.

    Verdicts are advisory annotations only — they never remove findings and
    never influence the policy gate (see GateResult). AI failures are
    recorded in ai_summary, not as coverage errors.
    """

    name = 'ai-triage'

    def enabled(self, context: ScanContext) -> bool:
        return bool(context.config.get('ai'))

    def run(self, context: ScanContext, emit: EventCallback) -> None:
        from ..ai import AIAnalysisError, AIClient, triage_findings

        model = context.config.get('ai_model')
        if context.ai_client is None:
            try:
                context.ai_client = AIClient(model)
            except AIAnalysisError as e:
                context.ai_summary['enabled'] = False
                context.ai_summary['error'] = str(e)
                emit(Notice(stage=self.name, level='warning',
                            title='AI analysis unavailable', body=str(e)))
                return
            # Privacy disclosure (R12): say exactly what leaves the machine.
            from ..constants import AI_MAX_ACTIONS_AUDITED
            audited = min(len(context.actions), AI_MAX_ACTIONS_AUDITED)
            emit(Notice(
                stage=self.name, level='info', title='AI analysis enabled',
                body=(f"Sending the tool findings and up to {audited} action "
                      f"definition(s) from the scanned repository to the "
                      f"Anthropic API (model {model}).")))
            context.ai_summary['enabled'] = True
            context.ai_summary['model'] = model

        try:
            summary = triage_findings(
                context.ai_client, context.findings,
                on_progress=lambda msg: emit(ItemProgress(stage=self.name, label=msg, done=0)))
            context.ai_summary['triage'] = summary
        except AIAnalysisError as e:
            context.ai_summary['triage'] = {'enabled': False, 'error': str(e)}
            emit(Notice(stage=self.name, level='warning',
                        title='AI triage unavailable', body=str(e)))
        context.ai_summary['calls'] = getattr(context.ai_client, 'calls_made', 0)


class AIAuditStage(Stage):
    """Optional: AI agent that inspects the action chain content itself for
    malicious behavior. May only ADD findings (never removes or downgrades)."""

    name = 'ai-audit'

    def enabled(self, context: ScanContext) -> bool:
        return bool(context.config.get('ai')) and context.ai_client is not None

    def run(self, context: ScanContext, emit: EventCallback) -> None:
        from ..ai import AIAnalysisError, audit_actions

        try:
            findings, coverage = audit_actions(
                context.ai_client, context.actions, context.action_depths,
                on_progress=lambda msg: emit(ItemProgress(stage=self.name, label=msg, done=0)))
        except AIAnalysisError as e:
            context.ai_summary['audit_coverage'] = {'enabled': False, 'error': str(e)}
            emit(Notice(stage=self.name, level='warning',
                        title='AI audit unavailable', body=str(e)))
            return

        for finding in findings:
            context.add_finding(finding)
        context.ai_summary['audit_coverage'] = coverage
        context.ai_summary['calls'] = getattr(context.ai_client, 'calls_made', 0)

        malicious = [f for f in findings if f.get('malicious')]
        if malicious:
            emit(Notice(stage=self.name, level='error',
                        title=f'AI audit flagged {len(malicious)} potentially malicious action(s)',
                        body='; '.join(f.get('action_ref', '?') for f in malicious[:10])))


class PolicyGateStage(Stage):
    """Evaluate the pinning policy gate and compute the pin plan.

    Runs before ReportStage so every report format carries the verdict.
    Monotonic: raw tool findings and AI-audit findings count; AI triage
    verdicts never exempt anything. Fail-closed: any coverage gap fails it.
    """

    name = 'policy-gate'

    def enabled(self, context: ScanContext) -> bool:
        return bool(context.config.get('create_pr'))

    def run(self, context: ScanContext, emit: EventCallback) -> None:
        threshold = context.config.get('pr_gate_severity', 'high')
        gate = GateResult(evaluated=True, threshold=threshold)
        threshold_level = SEVERITY_LEVELS.get(threshold, 3)

        # Fail-closed coverage checks.
        coverage_errors = [e for e in context.errors if _is_coverage_error(e.stage)]
        if coverage_errors:
            gate.reasons.append(f"{len(coverage_errors)} scan error(s) recorded — coverage incomplete")
        if context.skipped_workflows:
            gate.reasons.append(f"{len(context.skipped_workflows)} workflow(s) could not be parsed")
        if context.discovery_truncated:
            gate.reasons.append("dependency discovery hit the action limit — chain not fully scanned")
        unresolved = self._count_nodes(context, {'unresolved', 'error', 'limit'})
        if unresolved:
            gate.reasons.append(f"{unresolved} action reference(s) could not be resolved/scanned")
        depth_cut = self._count_nodes(context, {'max_depth'})
        if depth_cut:
            gate.reasons.append(
                f"{depth_cut} action reference(s) beyond --max-depth were not scanned — "
                "raise --max-depth to cover the full chain"
            )
        if not context.scanners:
            gate.reasons.append("no scanners ran")

        # When the user opted into AI, the audit becomes part of the expected
        # coverage: a failed/partial audit fails the gate (triage stays
        # advisory either way).
        if context.config.get('ai'):
            gate.reasons.extend(self._ai_coverage_gaps(context))

        # Finding checks (monotonic — ai_triage verdicts deliberately ignored).
        for finding in context.findings:
            if finding.get('rule_id') in PIN_REMEDIATED_RULE_IDS:
                gate.excluded_findings += 1
                continue
            severity_level = SEVERITY_LEVELS.get(str(finding.get('severity', 'low')).lower(), 1)
            if finding.get('malicious') or severity_level >= threshold_level:
                gate.blocking_findings.append(finding)

        if gate.blocking_findings:
            malicious_count = sum(1 for f in gate.blocking_findings if f.get('malicious'))
            if malicious_count:
                gate.reasons.append(f"{malicious_count} finding(s) flagged as malicious")
            gate.reasons.append(
                f"{len(gate.blocking_findings)} blocking finding(s) at or above "
                f"severity '{threshold}'"
            )

        gate.passed = not gate.reasons
        context.gate = gate

        # Compute the pin plan regardless of the verdict (reports and
        # --dry-run show what WOULD be pinned).
        from ..pinning import build_pin_plan

        scanned_workflows = [w for w in context.workflows if w['path'] in context.parsed_workflows]
        context.pin_plan = build_pin_plan(scanned_workflows, context.workflow_step_refs,
                                          context.actions)

        verdict = 'PASSED' if gate.passed else 'BLOCKED'
        emit(Notice(stage=self.name, level='info' if gate.passed else 'warning',
                    title=f'Pinning policy gate: {verdict}',
                    body='; '.join(gate.reasons) if gate.reasons else
                    f"no blocking findings at or above '{threshold}'"))

    @staticmethod
    def _ai_coverage_gaps(context: ScanContext) -> List[str]:
        """Gate reasons for incomplete AI-audit coverage (only when --ai)."""
        reasons: List[str] = []
        summary = context.ai_summary or {}
        coverage = summary.get('audit_coverage') or {}

        if summary.get('error') or not summary.get('enabled'):
            reasons.append("AI analysis was requested but unavailable")
        elif coverage.get('error') or not coverage.get('enabled'):
            reasons.append("AI audit was requested but did not run")
        elif coverage.get('failed_batches'):
            reasons.append(f"AI audit incomplete: {coverage['failed_batches']} batch(es) failed")
        elif any(status in ('failed', 'not_audited')
                 for status in (coverage.get('statuses') or {}).values()):
            reasons.append("AI audit incomplete: some actions were not analyzed")

        if any(e.stage in ('ai-audit', 'ai-triage') for e in context.errors):
            reasons.append("AI stage recorded an unexpected error")
        return reasons

    @staticmethod
    def _count_nodes(context: ScanContext, statuses: Set[str]) -> int:
        count = 0
        stack = [n for roots in context.action_nodes.values() for n in roots]
        while stack:
            node = stack.pop()
            if node.status in statuses:
                count += 1
            stack.extend(node.children)
        return count


class ReportStage(Stage):
    """Generate consolidated JSON, HTML, optional PDF, trees and graph."""

    name = 'report'

    def run(self, context: ScanContext, emit: EventCallback) -> None:
        self._attach_findings_counts(context)

        dependencies = [
            {
                'name': ref,
                'type': context.actions.get(ref, {}).get('type', 'unknown'),
                'depth': depth,
                'findings_count': self._finding_counts(context).get(ref, 0),
            }
            for ref, depth in sorted(context.action_depths.items())
        ]

        primary = context.workflows[0] if context.workflows else {}
        gate_dict = None
        if context.gate:
            gate_dict = {
                'evaluated': context.gate.evaluated,
                'passed': context.gate.passed,
                'threshold': context.gate.threshold,
                'reasons': context.gate.reasons,
                'blocking_findings_count': len(context.gate.blocking_findings),
                'excluded_findings': context.gate.excluded_findings,
            }
            if context.pin_plan:
                plan = context.pin_plan
                gate_dict['pin_plan'] = {
                    'files_changed': len(plan.new_contents),
                    'entries': [
                        {
                            'workflow': e.workflow_path,
                            'line': e.line_number,
                            'action': e.action_base,
                            'old_ref': e.old_ref,
                            'new_sha': e.new_sha,
                        }
                        for e in plan.entries[:100]
                    ],
                    'entries_total': len(plan.entries),
                    'skipped': [
                        {'workflow': s.workflow_path, 'line': s.line_number, 'reason': s.reason}
                        for s in plan.skipped[:50]
                    ],
                    'skipped_total': len(plan.skipped),
                }

        consolidated = context.report_manager.generate_consolidated_report(
            findings=context.findings,
            dependencies=dependencies,
            action_count_by_depth=context.action_count_by_depth(),
            workflow={'name': primary.get('name', 'unknown'), 'path': primary.get('path', 'unknown')},
            gate=gate_dict,
            ai=context.ai_summary or None,
        )
        context.report_paths['consolidated'] = consolidated
        emit(ItemProgress(stage=self.name, label='consolidated report', done=1, total=None))

        if consolidated:
            from ..reports import convert_json_to_html
            try:
                context.report_paths['html'] = convert_json_to_html(consolidated)
            except Exception as e:  # noqa: BLE001
                logger.error(f"Failed to convert JSON to HTML: {e}")
                context.report_paths['html'] = None

            if context.config.get('pdf'):
                from ..reports.pdf_converter import convert_json_to_pdf
                try:
                    context.report_paths['pdf'] = convert_json_to_pdf(consolidated)
                except Exception as e:  # noqa: BLE001
                    logger.error(f"Failed to convert JSON to PDF: {e}")
                    context.report_paths['pdf'] = None
                if not context.report_paths['pdf']:
                    emit(Notice(
                        stage=self.name, level='warning', title='PDF report not generated',
                        body='PDF generation failed — if fpdf2 is missing, install it with: '
                             'pip install "actchain[pdf]"'))

        # Plain-text dependency trees (one file per workflow).
        for path, roots in context.action_nodes.items():
            workflow_name = next((w['name'] for w in context.workflows if w['path'] == path), path)
            text = self._render_tree_text(workflow_name, roots)
            base = workflow_name.replace('.yml', '').replace('.yaml', '')
            context.report_manager.save_workflow_tree(text, f"workflow_tree_{base}")

        if context.config.get('dependency_graph'):
            graph = context.report_manager.generate_dependency_graph(
                set(context.action_depths.keys()), context.action_count_by_depth())
            context.report_paths['graph'] = graph

        # Preview of the pin diff — written whenever a plan was computed, so
        # the exact proposed change is always on disk alongside the reports.
        if context.pin_plan is not None:
            preview_path = context.report_manager.scan_dir / 'pinning_preview.diff'
            FileUtils.safe_write_file(context.pin_plan.diff_text or '(no pinnable refs)\n',
                                      preview_path)
            context.report_paths['pin_preview'] = str(preview_path)

    _counts_cache_key = '_finding_counts_cache'

    def _finding_counts(self, context: ScanContext) -> Dict[str, int]:
        cached = getattr(context, self._counts_cache_key, None)
        if cached is not None:
            return cached
        counts: Counter = Counter()
        for finding in context.findings:
            path = finding.get('location', {}).get('path', '')
            if path.startswith('action_'):
                counts[path[len('action_'):]] += 1
            ref = finding.get('action_ref')
            if ref and not path.startswith('action_'):
                counts[ref] += 1
        setattr(context, self._counts_cache_key, dict(counts))
        return getattr(context, self._counts_cache_key)

    def _attach_findings_counts(self, context: ScanContext) -> None:
        counts = self._finding_counts(context)
        stack = [n for roots in context.action_nodes.values() for n in roots]
        while stack:
            node = stack.pop()
            if node.status == 'resolved':
                node.findings_count = counts.get(node.ref, 0)
            stack.extend(node.children)

    @staticmethod
    def _render_tree_text(workflow_name: str, roots: List[ActionNode]) -> str:
        lines = [f"Workflow: {workflow_name}"]

        def walk(node: ActionNode, indent: int) -> None:
            marker = {
                'resolved': f"[{node.findings_count} issue(s)]" if node.findings_count else "[ok]",
                'unresolved': "[not resolved]",
                'already_processed': "[already processed]",
                'max_depth': "[max depth reached]",
                'limit': "[action limit reached]",
                'docker': "[docker]",
                'error': "[error]",
            }.get(node.status, f"[{node.status}]")
            lines.append(f"{'  ' * indent}- {node.ref} (depth {node.depth}) {marker}")
            for child in node.children:
                walk(child, indent + 1)

        for root in roots:
            walk(root, 1)
        return '\n'.join(lines) + '\n'


class PinningPRStage(Stage):
    """Open the pinning PR when the gate passed (and not a dry run).

    Runs after ReportStage so a PR failure can never lose the reports; the
    PR URL is patched into the consolidated JSON afterwards.
    """

    name = 'pinning-pr'

    def enabled(self, context: ScanContext) -> bool:
        return bool(context.config.get('create_pr')) and not context.config.get('dry_run')

    def run(self, context: ScanContext, emit: EventCallback) -> None:
        gate = context.gate
        plan = context.pin_plan

        if not gate or not gate.evaluated:
            emit(Notice(stage=self.name, level='warning', title='Pinning PR not opened',
                        body='Policy gate was not evaluated.'))
            return
        if not gate.passed:
            emit(Notice(stage=self.name, level='warning', title='Pinning PR not opened',
                        body='Policy gate blocked it: ' + '; '.join(gate.reasons)))
            return
        if not plan or not plan.entries:
            emit(Notice(stage=self.name, level='info', title='Pinning PR not opened',
                        body='Nothing to pin — all scanned actions are already SHA-pinned.'))
            return

        confirm = context.config.get('confirm_callback')
        if confirm is not None and not confirm(plan):
            emit(Notice(stage=self.name, level='info', title='Pinning PR not opened',
                        body='Declined at the confirmation prompt.'))
            return

        from ..pinning import PinningPRError, create_pinning_pr, render_pr_body

        stats = self._stats_from_findings(context)
        body = render_pr_body(
            plan, gate, stats, context.config.get('repo', ''),
            [s.scanner_name for s in context.scanners],
            bool(context.ai_summary.get('enabled')),
        )

        try:
            url = create_pinning_pr(
                context.github_client, plan,
                title='security: pin GitHub Actions to commit SHAs', body=body)
        except PinningPRError as e:
            context.add_error(self.name, '<pr>', str(e))
            emit(Notice(stage=self.name, level='error', title='Pinning PR failed', body=str(e)))
            return

        context.pr_url = url
        emit(Notice(stage=self.name, level='info', title='Pinning PR opened', body=url))
        self._patch_consolidated(context, url)

    @staticmethod
    def _stats_from_findings(context: ScanContext) -> Dict:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        for finding in context.findings:
            severity = str(finding.get('severity', 'low')).lower()
            if severity not in counts:
                severity = 'low'
            counts[severity] += 1
            counts['total'] += 1
        return {'severity_counts': counts}

    @staticmethod
    def _patch_consolidated(context: ScanContext, url: str) -> None:
        path = context.report_paths.get('consolidated')
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            data['pr_url'] = url
            FileUtils.safe_write_file(json.dumps(data, indent=2), path)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Could not record PR URL in consolidated report: {e}")
