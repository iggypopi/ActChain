# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Pipeline unit tests, centered on the policy-gate security invariants:
monotonic (AI triage can never unblock), fail-closed (any coverage gap
blocks), and report integrity (annotations reach the consolidated JSON).
"""

import json
import sys
import types

import pytest

from actchain.pipeline import (
    ActionNode,
    PinPlan,
    PinPlanEntry,
    ScanContext,
    ScanPipeline,
    Stage,
    StageError,
)
from actchain.pipeline.stages import PinningPRStage, PolicyGateStage, ReportStage
from actchain.reports.manager import ReportManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _NamedScanner:
    scanner_name = 'Stub Scanner'


def make_context(tmp_path=None, **config):
    base_config = {'create_pr': True, 'pr_gate_severity': 'high', 'repo': 'o/r'}
    base_config.update(config)
    context = ScanContext(config=base_config)
    context.scanners = [_NamedScanner()]  # non-empty: "scanners ran"
    context.workflows = [{'name': 'ci.yml', 'path': '.github/workflows/ci.yml',
                          'content': 'on: push\njobs: {a: {steps: []}}\n'}]
    context.parsed_workflows = {'.github/workflows/ci.yml': {'on': 'push'}}
    context.workflow_step_refs = {'.github/workflows/ci.yml': []}
    context.action_nodes = {'.github/workflows/ci.yml': []}
    if tmp_path is not None:
        context.report_manager = ReportManager(str(tmp_path / 'reports'))
    return context


@pytest.fixture
def stub_pinning(monkeypatch):
    """Replace the actchain.pinning module with a recording stub."""
    calls = {'plan': 0, 'pr': 0}
    module = types.ModuleType('actchain.pinning')

    def build_pin_plan(workflows, step_refs, actions):
        calls['plan'] += 1
        return PinPlan(entries=[PinPlanEntry(
            workflow_path='.github/workflows/ci.yml', line_number=3,
            action_base='a/b', old_ref='v1', new_sha='a' * 40)])

    class PinningPRError(Exception):
        pass

    def create_pinning_pr(client, plan, title, body):
        calls['pr'] += 1
        return 'https://github.com/o/r/pull/1'

    def render_pr_body(plan, gate, stats, repo, scanners, ai_enabled):
        return 'body'

    module.build_pin_plan = build_pin_plan
    module.create_pinning_pr = create_pinning_pr
    module.render_pr_body = render_pr_body
    module.PinningPRError = PinningPRError
    monkeypatch.setitem(sys.modules, 'actchain.pinning', module)
    return calls


def run_gate(context):
    PolicyGateStage().run(context, lambda e: None)
    return context.gate


# ---------------------------------------------------------------------------
# Policy gate: monotonic
# ---------------------------------------------------------------------------

class TestGateMonotonic:
    def test_ai_triage_false_positive_cannot_unblock(self, stub_pinning):
        # THE invariant: a prompt-injected triage verdict must never remove a
        # real high-severity finding from the gate.
        context = make_context()
        context.add_finding({
            'rule_id': 'template-injection', 'title': 'x', 'severity': 'high',
            'ai_triage': {'verdict': 'likely_false_positive', 'rationale': 'injected'},
        })
        gate = run_gate(context)
        assert not gate.passed
        assert any('blocking finding' in r for r in gate.reasons)

    def test_ai_audit_findings_can_block(self, stub_pinning):
        context = make_context()
        context.add_finding({'rule_id': 'ai-audit', 'title': 'exfil', 'severity': 'critical',
                             'source_scanner': 'AI Audit (Claude)'})
        assert not run_gate(context).passed

    def test_malicious_blocks_regardless_of_severity(self, stub_pinning):
        context = make_context()
        context.add_finding({'rule_id': 'ai-audit', 'title': 'sneaky', 'severity': 'low',
                             'malicious': True})
        gate = run_gate(context)
        assert not gate.passed
        assert any('malicious' in r for r in gate.reasons)

    def test_pin_remediated_rules_are_excluded(self, stub_pinning):
        context = make_context()
        context.add_finding({'rule_id': 'unpinned-github-action', 'title': 'x', 'severity': 'high'})
        context.add_finding({'rule_id': 'unpinned-uses', 'title': 'y', 'severity': 'high'})
        gate = run_gate(context)
        assert gate.passed
        assert gate.excluded_findings == 2

    def test_below_threshold_passes(self, stub_pinning):
        context = make_context()
        context.add_finding({'rule_id': 'some-rule', 'title': 'x', 'severity': 'medium'})
        assert run_gate(context).passed


# ---------------------------------------------------------------------------
# Policy gate: fail-closed
# ---------------------------------------------------------------------------

class TestGateFailClosed:
    def test_scan_error_blocks_even_with_zero_findings(self, stub_pinning):
        context = make_context()
        context.add_error('scan:Zizmor Scanner', 'a/b@v1', 'zizmor crashed')
        gate = run_gate(context)
        assert not gate.passed
        assert any('coverage incomplete' in r for r in gate.reasons)

    def test_ai_stage_errors_do_not_block(self, stub_pinning):
        context = make_context()
        context.add_error('ai-triage', '<stage>', 'AI unavailable')
        assert run_gate(context).passed

    def test_skipped_workflow_blocks(self, stub_pinning):
        context = make_context()
        context.skipped_workflows.append('.github/workflows/broken.yml')
        assert not run_gate(context).passed

    def test_discovery_truncation_blocks(self, stub_pinning):
        context = make_context()
        context.discovery_truncated = True
        assert not run_gate(context).passed

    def test_unresolved_action_blocks(self, stub_pinning):
        context = make_context()
        context.action_nodes['.github/workflows/ci.yml'] = [
            ActionNode(ref='ghost/action@v1', depth=0, status='unresolved')]
        gate = run_gate(context)
        assert not gate.passed
        assert any('could not be resolved' in r for r in gate.reasons)

    def test_no_scanners_blocks(self, stub_pinning):
        context = make_context()
        context.scanners = []
        assert not run_gate(context).passed

    def test_max_depth_truncation_blocks(self, stub_pinning):
        # A chain cut off at --max-depth is unscanned coverage: the gate must
        # refuse rather than endorse content nobody looked at.
        context = make_context()
        context.action_nodes['.github/workflows/ci.yml'] = [
            ActionNode(ref='a/b@v1', depth=0, status='resolved', children=[
                ActionNode(ref='deep/chain@v1', depth=5, status='max_depth')])]
        gate = run_gate(context)
        assert not gate.passed
        assert any('max-depth' in r for r in gate.reasons)

    def test_ai_audit_failure_blocks_when_ai_enabled(self, stub_pinning):
        context = make_context(ai=True)
        context.ai_summary = {
            'enabled': True, 'model': 'claude-opus-5-5',
            'audit_coverage': {'enabled': True, 'audited': 3, 'failed_batches': 1,
                               'statuses': {}},
        }
        gate = run_gate(context)
        assert not gate.passed
        assert any('AI audit incomplete' in r for r in gate.reasons)

    def test_ai_unavailable_blocks_when_ai_enabled(self, stub_pinning):
        context = make_context(ai=True)
        context.ai_summary = {'enabled': False, 'error': 'no key'}
        assert not run_gate(context).passed

    def test_ai_not_requested_means_no_ai_gate(self, stub_pinning):
        context = make_context()  # ai not set
        context.ai_summary = {}
        assert run_gate(context).passed

    def test_clean_scan_passes(self, stub_pinning):
        assert run_gate(make_context()).passed


class TestScannerErrorIngestion:
    def test_empty_error_message_still_counts_as_error(self):
        from actchain.pipeline.stages import ScannerStage

        stage = ScannerStage(_NamedScanner(), 0)
        context = make_context()
        stage._ingest_report(context, {'results': {'error': '', 'findings': []}}, item='a/b@v1')
        assert any(e.stage == 'scan:Stub Scanner' for e in context.errors)


# ---------------------------------------------------------------------------
# PinningPRStage
# ---------------------------------------------------------------------------

class TestPinningPRStage:
    def test_blocked_gate_prevents_pr(self, stub_pinning):
        context = make_context()
        context.add_finding({'rule_id': 'r', 'title': 'x', 'severity': 'critical'})
        run_gate(context)
        PinningPRStage().run(context, lambda e: None)
        assert stub_pinning['pr'] == 0
        assert context.pr_url is None

    def test_confirmation_decline_prevents_pr(self, stub_pinning):
        context = make_context()
        run_gate(context)
        context.config['confirm_callback'] = lambda plan: False
        PinningPRStage().run(context, lambda e: None)
        assert stub_pinning['pr'] == 0

    def test_passed_gate_opens_pr(self, stub_pinning, tmp_path):
        context = make_context(tmp_path)
        run_gate(context)
        ReportStage().run(context, lambda e: None)  # consolidated exists for patching
        PinningPRStage().run(context, lambda e: None)
        assert stub_pinning['pr'] == 1
        assert context.pr_url == 'https://github.com/o/r/pull/1'
        data = json.loads(open(context.report_paths['consolidated'], encoding='utf-8').read())
        assert data['pr_url'] == context.pr_url

    def test_dry_run_disables_stage(self, stub_pinning):
        context = make_context(dry_run=True)
        assert not PinningPRStage().enabled(context)


# ---------------------------------------------------------------------------
# ReportStage
# ---------------------------------------------------------------------------

class TestReportStage:
    def test_ai_annotations_and_gate_reach_consolidated_json(self, stub_pinning, tmp_path):
        context = make_context(tmp_path)
        finding = context.add_finding({'rule_id': 'r', 'title': 'x', 'severity': 'medium',
                                       'source_scanner': 's'})
        finding['ai_triage'] = {'verdict': 'confirmed', 'rationale': 'yes'}
        context.ai_summary = {'enabled': True, 'model': 'claude-opus-5-5', 'calls': 3}
        run_gate(context)
        ReportStage().run(context, lambda e: None)

        data = json.loads(open(context.report_paths['consolidated'], encoding='utf-8').read())
        assert data['findings'][0]['ai_triage']['verdict'] == 'confirmed'
        assert data['findings'][0]['finding_id'] == finding['finding_id']
        assert data['gate']['evaluated'] is True
        assert data['ai']['model'] == 'claude-opus-5-5'

    def test_dry_run_writes_preview_diff(self, stub_pinning, tmp_path):
        context = make_context(tmp_path, dry_run=True)
        run_gate(context)
        ReportStage().run(context, lambda e: None)
        assert context.report_paths.get('pin_preview')

    def test_pin_plan_serialized_into_consolidated(self, stub_pinning, tmp_path):
        context = make_context(tmp_path)
        run_gate(context)
        ReportStage().run(context, lambda e: None)
        data = json.loads(open(context.report_paths['consolidated'], encoding='utf-8').read())
        plan = data['gate']['pin_plan']
        assert plan['entries_total'] == 1
        assert plan['entries'][0]['action'] == 'a/b'
        assert plan['entries'][0]['new_sha'] == 'a' * 40


# ---------------------------------------------------------------------------
# Pipeline error semantics
# ---------------------------------------------------------------------------

class _BoomStage(Stage):
    name = 'boom'

    def __init__(self, critical):
        self.critical = critical

    def run(self, context, emit):
        raise StageError('boom')


class _MarkStage(Stage):
    name = 'mark'

    def run(self, context, emit):
        context.config['marked'] = True


class TestPipelineErrorSemantics:
    def test_non_critical_failure_continues(self):
        context = ScanContext(config={})
        ScanPipeline([_BoomStage(critical=False), _MarkStage()]).run(context)
        assert context.config.get('marked') is True
        assert any(e.stage == 'boom' for e in context.errors)

    def test_critical_failure_aborts(self):
        context = ScanContext(config={})
        with pytest.raises(StageError):
            ScanPipeline([_BoomStage(critical=True), _MarkStage()]).run(context)
        assert context.config.get('marked') is None

    def test_disabled_stage_is_skipped(self):
        class Disabled(_MarkStage):
            def enabled(self, context):
                return False

        context = ScanContext(config={})
        ScanPipeline([Disabled()]).run(context)
        assert context.config.get('marked') is None
