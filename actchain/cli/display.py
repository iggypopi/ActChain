# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Display layer and scan orchestration for the ActChain CLI.

The scan itself runs in the console-free pipeline (actchain.pipeline); this
module selects/fetches workflows, builds the pipeline, renders its typed
progress events with Rich, and presents the results.
"""

import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Union

import click
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.tree import Tree

from ..core import ActionResolver, GitHubClient, GitHubClientError, WorkflowParser
from ..pipeline import (
    ActionNode,
    ItemProgress,
    Notice,
    ScanContext,
    ScanPipeline,
    StageFailed,
    StageFinished,
    StageStarted,
)
from ..pipeline.stages import (
    AIAuditStage,
    AITriageStage,
    DiscoveryStage,
    PinningPRStage,
    PolicyGateStage,
    ReportStage,
    ScannerStage,
)
from ..reports import ReportManager, ReportManagerError
from ..scanners import ScannerError, get_scanner
from ..utils.security_utils import SecurityUtils
from ..utils.system_utils import SystemUtils

console = Console()
logger = logging.getLogger('actchain.cli.display')

_NODE_STATUS_LABELS = {
    'unresolved': '[red](not resolved)[/red]',
    'already_processed': '[dim](already processed)[/dim]',
    'max_depth': '[yellow](max depth reached)[/yellow]',
    'limit': '[yellow](action limit reached)[/yellow]',
    'docker': '[blue](docker)[/blue]',
    'error': '[red](error)[/red]',
}


def esc(value: Any) -> str:
    """
    Make an untrusted value safe for Rich console output.

    Workflow names, paths, action refs, scanner messages and exception text
    all derive from the scanned (untrusted) repository. Rich parses
    [markup] in printed strings, so without escaping a scanned repo could
    inject markup that spoofs scan output; raw control characters could
    manipulate the terminal.
    """
    return rich_escape(SecurityUtils.strip_control_chars(str(value)))


class ActChainDisplay:
    """Handles display and scanning logic for ActChain CLI."""

    def __init__(self):
        """Initialize the display handler."""
        self.console = console
        self._progress: Optional[Progress] = None

    # ------------------------------------------------------------------
    # Environment info (unchanged behavior)
    # ------------------------------------------------------------------
    def show_environment_info(self) -> None:
        """Display environment and dependency information."""
        self.console.print(Panel.fit(
            "[bold blue]GitHub Actions[/bold blue] Workflow Security Scanner\n"
            "[dim]Supply Chain Security Scanner[/dim]",
            title="ActChain",
            border_style="blue"
        ))

        platform_info = SystemUtils.get_platform_info()
        self.console.print(Panel(
            f"[bold]System:[/bold] {esc(platform_info['system'])} {esc(platform_info['release'])}\n"
            f"[bold]Python:[/bold] {esc(platform_info['python_version'])}",
            title="System Information",
            border_style="blue"
        ))

        env_report = SystemUtils.create_environment_report()
        deps_table = Table(show_header=True, box=box.ROUNDED, title="Dependencies", title_style="bold blue")
        deps_table.add_column("Dependency", style="bold")
        deps_table.add_column("Status", justify="center")

        for dep_name, is_available in env_report['dependencies'].items():
            status = "[green]✓ Installed[/green]" if is_available else "[red]✗ Not Found[/red]"
            deps_table.add_row(dep_name.capitalize(), status)

        env_vars = env_report['environment_variables']
        for var_name, is_set in env_vars.items():
            status = "[green]✓ Set[/green]" if is_set else "[red]✗ Not Set[/red]"
            deps_table.add_row(var_name, status)

        self.console.print(deps_table)

        self.console.print(Panel(
            "To scan a GitHub Actions workflow, use:\n"
            "[bold cyan]actchain scan --repo owner/repository[/bold cyan]\n\n"
            "For more options, use [bold]actchain scan --help[/bold]",
            title="Quick Help",
            border_style="blue"
        ))

    # ------------------------------------------------------------------
    # Scan entry point
    # ------------------------------------------------------------------
    def run_scan(self, config: Dict[str, Any], token: str) -> ScanContext:
        """
        Run the full scan pipeline.

        Args:
            config: Configuration dictionary with scan parameters
            token: GitHub token (passed separately so it is never carried
                around or serialized with the rest of the configuration)

        Returns:
            The completed ScanContext (the CLI maps it to an exit code).
        """
        try:
            self._display_header()

            components = self._initialize_components(config, token)
            workflow_info = self._get_workflow_to_scan(components, config)
            workflows = workflow_info if isinstance(workflow_info, list) else [workflow_info]

            self._display_scan_config(config, workflow_info, components)

            context = ScanContext(
                config=config,
                github_client=components['github_client'],
                workflow_parser=components['workflow_parser'],
                action_resolver=components['action_resolver'],
                report_manager=components['report_manager'],
                scanners=components['scanners'],
                workflows=workflows,
            )

            # Interactive confirmation before any write to the scanned repo.
            # click.confirm reads STDIN, so both streams must be terminals;
            # a half-redirected invocation must not silently skip the prompt.
            if (config.get('create_pr') and not config.get('dry_run')
                    and not config.get('assume_yes')
                    and sys.stdin.isatty() and sys.stdout.isatty()):
                config['confirm_callback'] = self._confirm_pin_plan

            pipeline = ScanPipeline(self._build_stages(context))
            self._run_pipeline(pipeline, context)

            self._display_scan_results(context)
            return context

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise

    @staticmethod
    def _build_stages(context: ScanContext) -> List:
        stages: List = [DiscoveryStage()]
        for index, scanner in enumerate(context.scanners):
            stages.append(ScannerStage(scanner, index))
        stages.extend([
            AITriageStage(),
            AIAuditStage(),
            PolicyGateStage(),
            ReportStage(),
            PinningPRStage(),
        ])
        return stages

    # ------------------------------------------------------------------
    # Pipeline event rendering
    # ------------------------------------------------------------------
    def _run_pipeline(self, pipeline: ScanPipeline, context: ScanContext) -> None:
        with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}[/bold blue]"),
                BarColumn(),
                TextColumn("{task.fields[detail]}"),
                console=self.console,
        ) as progress:
            self._progress = progress
            task_ids: Dict[str, Any] = {}

            def handler(event) -> None:
                if isinstance(event, StageStarted):
                    task_ids[event.stage] = progress.add_task(
                        esc(event.stage), total=None, detail='')
                elif isinstance(event, StageFinished):
                    task = task_ids.get(event.stage)
                    if task is not None:
                        progress.update(task, total=1, completed=1, detail='[green]done[/green]')
                elif isinstance(event, StageFailed):
                    task = task_ids.get(event.stage)
                    if task is not None:
                        progress.update(task, total=1, completed=1,
                                        detail=f"[red]failed: {esc(event.error)[:60]}[/red]")
                elif isinstance(event, ItemProgress):
                    task = task_ids.get(event.stage)
                    if task is not None:
                        progress.update(task, completed=event.done, total=event.total,
                                        detail=esc(event.label)[:70])
                elif isinstance(event, Notice):
                    self._render_notice(progress, event)

            try:
                pipeline.run(context, handler)
            finally:
                self._progress = None

    def _render_notice(self, progress: Progress, notice: Notice) -> None:
        style = {'info': 'blue', 'warning': 'yellow', 'error': 'red'}.get(notice.level, 'blue')
        body = esc(notice.body) if notice.body else ''

        if notice.title.startswith('Workflow parsing failed'):
            body = (
                f"[bold red]Error:[/bold red] {body}\n\n"
                "[yellow]Possible causes:[/yellow]\n"
                "• The file might be a workflow template or composite action\n"
                "• The file might be malformed or incomplete\n\n"
                "[cyan]This workflow will be skipped.[/cyan]"
            )

        progress.console.print(Panel(
            body or ' ',
            title=esc(notice.title),
            border_style=style,
        ))

    def _confirm_pin_plan(self, plan) -> bool:
        """TTY confirmation before pushing the pinning branch/PR."""
        progress = self._progress
        if progress is not None:
            progress.stop()
        try:
            table = Table(show_header=True, box=box.ROUNDED,
                          title="Planned pins", title_style="bold blue")
            table.add_column("Workflow")
            table.add_column("Action")
            table.add_column("Old ref")
            table.add_column("Pinned SHA")
            for entry in plan.entries[:20]:
                table.add_row(esc(entry.workflow_path), esc(entry.action_base),
                              esc(entry.old_ref), esc(entry.new_sha[:12]))
            if len(plan.entries) > 20:
                table.add_row("…", f"and {len(plan.entries) - 20} more", "", "")
            self.console.print(table)
            try:
                return click.confirm(
                    f"Open a pull request pinning {len(plan.entries)} action reference(s)?",
                    default=False,
                )
            except (click.Abort, EOFError):
                # EOF/Ctrl-C at the prompt counts as a decline, never a crash.
                return False
        finally:
            if progress is not None:
                progress.start()

    # ------------------------------------------------------------------
    # Setup and workflow selection (behavior unchanged from v0.1)
    # ------------------------------------------------------------------
    def _display_header(self) -> None:
        """Display the scan header."""
        self.console.print(Panel.fit(
            "[bold blue]GitHub Actions[/bold blue] Workflow Security Scanner\n"
            "[dim]Supply Chain Security Scanner[/dim]",
            title="ActChain",
            border_style="blue"
        ))

    def _initialize_components(self, config: Dict[str, Any], token: str) -> Dict[str, Any]:
        """Initialize all required components."""
        components = {}

        with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Initializing...[/bold blue]"),
                console=self.console
        ) as progress:
            task = progress.add_task("Connecting to GitHub", total=1)

            try:
                components['github_client'] = GitHubClient(token, config['repo'])
            except GitHubClientError as e:
                raise Exception(f"Failed to connect to GitHub: {e}") from e

            components['workflow_parser'] = WorkflowParser()
            components['action_resolver'] = ActionResolver(
                components['github_client'],
                deep_scan=config.get('deep_scan', False)
            )

            try:
                scanner_instances = get_scanner(config['scanner'], config['min_severity'])
                components['scanners'] = scanner_instances if isinstance(scanner_instances, list) else [
                    scanner_instances]
            except ScannerError as e:
                raise Exception(f"Failed to initialize scanners: {e}") from e

            try:
                components['report_manager'] = ReportManager(config['output_dir'])
            except ReportManagerError as e:
                raise Exception(f"Failed to initialize report manager: {e}") from e

            progress.update(task, advance=1)

        return components

    def _get_workflow_to_scan(
            self, components: Dict[str, Any], config: Dict[str, Any]
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Get the workflow(s) to scan (either specified or user selected)."""
        github_client = components['github_client']

        if config.get('workflow_path'):
            workflow_path = config['workflow_path']
            self.console.print(f"Fetching workflow: [bold cyan]{esc(workflow_path)}[/bold cyan]")

            try:
                with Progress(
                        SpinnerColumn(),
                        TextColumn("[bold blue]Fetching workflow...[/bold blue]"),
                        console=self.console
                ) as progress:
                    task = progress.add_task("Fetching", total=1)
                    workflow_content = github_client.get_file_content(workflow_path)
                    progress.update(task, advance=1)

                return {
                    "name": os.path.basename(workflow_path),
                    "path": workflow_path,
                    "content": workflow_content
                }
            except GitHubClientError as e:
                raise Exception(f"Failed to fetch workflow: {e}") from e
        elif config.get('scan_all_workflows'):
            return self._get_all_workflows_non_interactive(github_client)
        else:
            return self._select_workflow_interactively(github_client)

    def _get_all_workflows_non_interactive(self, github_client: GitHubClient) -> List[Dict[str, Any]]:
        """Get all workflows without interactive selection (for --scan-all-workflows flag)."""
        self.console.print("Fetching all workflows...")

        try:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]Fetching workflows...[/bold blue]"),
                    console=self.console
            ) as progress:
                task = progress.add_task("Fetching", total=1)
                workflows = github_client.get_workflows()
                progress.update(task, advance=1)
        except GitHubClientError as e:
            raise Exception(f"Failed to fetch workflows: {e}") from e

        if not workflows:
            raise Exception(f"No workflows found in {github_client.repo_name}")

        self.console.print(f"[bold green]Found {len(workflows)} workflows to scan[/bold green]")

        for i, workflow in enumerate(workflows, 1):
            self.console.print(f"  {i}. {esc(workflow['name'])}")

        return self._fetch_all_workflows(github_client, workflows)

    def _select_workflow_interactively(
            self, github_client: GitHubClient
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Let user select workflow(s) interactively."""
        self.console.print("Fetching available workflows...")

        try:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]Fetching workflows...[/bold blue]"),
                    console=self.console
            ) as progress:
                task = progress.add_task("Fetching", total=1)
                workflows = github_client.get_workflows()
                progress.update(task, advance=1)
        except GitHubClientError as e:
            raise Exception(f"Failed to fetch workflows: {e}") from e

        if not workflows:
            raise Exception(f"No workflows found in {github_client.repo_name}")

        table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED,
                      title="Available Workflows", title_style="bold blue")
        table.add_column("#", style="dim", width=4)
        table.add_column("Workflow Name", style="cyan")
        table.add_column("Path", style="dim")

        table.add_row("0", "[bold green]Scan All Workflows[/bold green]", f"[dim]({len(workflows)} workflows)[/dim]")

        for i, workflow in enumerate(workflows, 1):
            table.add_row(str(i), esc(workflow['name']), esc(workflow['path']))

        self.console.print(table)

        max_selection = len(workflows)
        selection = click.prompt(
            f"Select a workflow to scan (0 for all, 1-{max_selection})",
            type=int,
            default=1
        )

        if selection < 0 or selection > max_selection:
            raise Exception("Invalid workflow selection")

        if selection == 0:
            self.console.print(f"[bold green]Selected:[/bold green] All {len(workflows)} workflows")
            return self._fetch_all_workflows(github_client, workflows)
        else:
            selected_workflow = workflows[selection - 1]
            self.console.print(f"[bold green]Selected:[/bold green] {esc(selected_workflow['name'])}")
            return self._fetch_single_workflow(github_client, selected_workflow)

    def _fetch_all_workflows(
            self, github_client: GitHubClient, workflows: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """Fetch content for all workflows."""
        workflow_data = []

        with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Fetching workflows...[/bold blue]"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=self.console
        ) as progress:
            task = progress.add_task("Fetching", total=len(workflows))

            for workflow in workflows:
                try:
                    content = github_client.get_file_content(workflow['path'])
                    workflow_data.append({
                        "name": workflow['name'],
                        "path": workflow['path'],
                        "content": content
                    })
                    progress.update(task, advance=1, description=f"Fetched {esc(workflow['name'])}")
                except GitHubClientError as e:
                    logger.warning(f"Failed to fetch workflow {workflow['name']}: {e}")
                    progress.update(task, advance=1, description=f"Failed to fetch {esc(workflow['name'])}")
                    continue

        if not workflow_data:
            raise Exception("Failed to fetch any workflows")

        return workflow_data

    def _fetch_single_workflow(self, github_client: GitHubClient, workflow: Dict[str, str]) -> Dict[str, Any]:
        """Fetch content for a single workflow."""
        try:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]Fetching selected workflow...[/bold blue]"),
                    console=self.console
            ) as progress:
                task = progress.add_task("Fetching", total=1)
                workflow_content = github_client.get_file_content(workflow['path'])
                progress.update(task, advance=1)
        except GitHubClientError as e:
            raise Exception(f"Failed to fetch selected workflow: {e}") from e

        return {
            "name": workflow['name'],
            "path": workflow['path'],
            "content": workflow_content
        }

    def _display_scan_config(self, config: Dict[str, Any], workflow_info: Union[Dict[str, Any], List[Dict[str, Any]]],
                             components: Dict[str, Any]) -> None:
        """Display scan configuration."""
        if isinstance(workflow_info, list):
            workflow_display = f"{len(workflow_info)} workflows"
            self.console.print(f"[bold green]✓[/bold green] Selected: [bold cyan]{workflow_display}[/bold cyan]")
        else:
            self.console.print(
                f"[bold green]✓[/bold green] Selected: [bold cyan]{esc(workflow_info['name'])}[/bold cyan]")

        scanner_names = [s.scanner_name for s in components.get('scanners', [])]
        scanner_display = ', '.join(scanner_names) if scanner_names else config.get('scanner', 'Unknown')

        lines = [
            "[bold]Scan Configuration:[/bold]",
            f"• Maximum Dependency Depth: {config['max_depth']}",
            f"• Scanner(s): {esc(scanner_display)}",
            f"• Minimum Severity: {esc(config['min_severity'])}",
            f"• Deep Scan (heuristic dependencies): {'Enabled' if config.get('deep_scan') else 'Disabled'}",
            f"• AI Analysis: {'Enabled (' + esc(config.get('ai_model', '')) + ')' if config.get('ai') else 'Disabled'}",
            f"• Reports: JSON, HTML{', PDF' if config.get('pdf') else ''}",
            f"• Dependency Graph: {'Yes' if config.get('dependency_graph') else 'No'}",
        ]
        if config.get('create_pr'):
            mode = 'dry run (no push)' if config.get('dry_run') else 'enabled'
            lines.append(f"• Pinning PR: {mode} (gate severity: {esc(config.get('pr_gate_severity', 'high'))})")

        self.console.print(Panel.fit('\n'.join(lines), title="Configuration", border_style="blue"))

    # ------------------------------------------------------------------
    # Result rendering
    # ------------------------------------------------------------------
    def _display_scan_results(self, context: ScanContext) -> None:
        """Display scan results and summary."""
        malicious = context.malicious_findings()
        if malicious:
            self._display_malicious_alert(malicious)

        if len(context.workflows) > 1:
            self.console.print(f"\n[bold]Scanned {len(context.parsed_workflows)} of "
                               f"{len(context.workflows)} workflows:[/bold]")
            for workflow in context.workflows:
                skipped = workflow['path'] in context.skipped_workflows
                marker = "[yellow](skipped — parse failure)[/yellow]" if skipped else ""
                self.console.print(f"  • {esc(workflow['name'])} {marker}")

        self.console.print("\n[bold]Supply Chain Dependency Trees:[/bold]")
        for path, roots in context.action_nodes.items():
            name = next((w['name'] for w in context.workflows if w['path'] == path), path)
            self.console.print(self._render_action_tree(name, roots))

        self.console.print(Panel("[bold green]Scan Complete![/bold green]", border_style="green"))

        statistics = self._load_statistics(context.report_paths.get('consolidated'))
        tables = self._create_summary_tables(statistics, context)
        self.console.print(Columns(tables[:2], expand=True))
        if len(tables) > 2:
            self.console.print(tables[2])

        if context.ai_summary:
            self._display_ai_summary(context)
        if context.gate and context.gate.evaluated:
            self._display_gate_result(context)

        self._display_report_paths(context.report_paths, context.pr_url)

    def _display_malicious_alert(self, malicious: List[Dict[str, Any]]) -> None:
        lines = []
        for finding in malicious[:10]:
            where = finding.get('action_ref') or finding.get('location', {}).get('path', 'unknown')
            lines.append(
                f"[bold red]•[/bold red] {esc(finding.get('title', 'untitled'))} — "
                f"[bold]{esc(where)}[/bold] [dim]({esc(finding.get('source_scanner', '?'))})[/dim]"
            )
        if len(malicious) > 10:
            lines.append(f"[dim]… and {len(malicious) - 10} more — see the reports.[/dim]")
        self.console.print(Panel(
            '\n'.join(lines),
            title=f"🚨 MALICIOUS BEHAVIOR DETECTED — {len(malicious)} finding(s)",
            border_style="red",
        ))

    def _render_action_tree(self, workflow_name: str, roots: List[ActionNode]) -> Tree:
        tree = Tree(f"[bold]Workflow: {esc(workflow_name)} [dim]({len(roots)} actions)[/dim][/bold]")

        def add(parent, node: ActionNode) -> None:
            safe_ref = esc(node.ref)
            if node.status == 'resolved':
                icon = "❌ " if node.findings_count else "✓ "
                info = f"[red]({node.findings_count} issues)[/red]" if node.findings_count else ""
                branch = parent.add(f"{icon}[green]{safe_ref}[/green] [dim](depth: {node.depth})[/dim] {info}")
                if node.children:
                    deps = branch.add("[cyan]Dependencies:[/cyan]")
                    for child in node.children:
                        add(deps, child)
            else:
                label = _NODE_STATUS_LABELS.get(node.status, f"[dim]({esc(node.status)})[/dim]")
                parent.add(f"{safe_ref} {label}")

        for root in roots:
            add(tree, root)
        return tree

    def _display_ai_summary(self, context: ScanContext) -> None:
        summary = context.ai_summary
        if not summary.get('enabled'):
            if summary.get('error'):
                self.console.print(f"[yellow]AI analysis unavailable:[/yellow] {esc(summary['error'])}")
            return

        lines = [f"[bold]Model:[/bold] {esc(summary.get('model', '?'))}  "
                 f"[bold]API calls:[/bold] {summary.get('calls', 0)}"]
        triage = summary.get('triage') or {}
        if triage.get('findings_triaged') is not None:
            verdicts = triage.get('verdict_counts', {})
            verdict_text = ', '.join(f"{k}: {v}" for k, v in sorted(verdicts.items())) or 'none'
            lines.append(f"[bold]Triage:[/bold] {triage['findings_triaged']} finding(s) — {esc(verdict_text)}")
        coverage = summary.get('audit_coverage') or {}
        if coverage.get('audited') is not None:
            lines.append(
                f"[bold]Audit:[/bold] {coverage.get('audited', 0)} action(s) audited, "
                f"{coverage.get('truncated', 0)} truncated, "
                f"{coverage.get('skipped_cap', 0) + coverage.get('skipped_namespace', 0)} skipped")
        self.console.print(Panel('\n'.join(lines), title="AI Analysis", border_style="magenta"))

    def _display_gate_result(self, context: ScanContext) -> None:
        gate = context.gate
        plan = context.pin_plan
        if gate.passed:
            body = [f"[green]PASSED[/green] — no blocking findings at or above '{esc(gate.threshold)}'"]
        else:
            body = ["[yellow]BLOCKED[/yellow] — the pinning PR was not opened:"]
            body.extend(f"  • {esc(reason)}" for reason in gate.reasons)
        if gate.excluded_findings:
            body.append(f"[dim]{gate.excluded_findings} unpinned-action finding(s) excluded "
                        f"(pinning is their fix).[/dim]")
        if plan:
            body.append(f"Pin plan: {len(plan.entries)} reference(s) to pin, "
                        f"{len(plan.skipped)} skipped.")
        if context.config.get('dry_run') and context.report_paths.get('pin_preview'):
            body.append(f"Dry run — preview diff: {esc(context.report_paths['pin_preview'])}")
        self.console.print(Panel('\n'.join(body), title="Pinning Policy Gate",
                                 border_style="green" if gate.passed else "yellow"))

    def _load_statistics(self, consolidated_path: Optional[str]) -> Dict[str, Any]:
        """Load statistics from consolidated report."""
        default_stats = {
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "scanner_counts": {}
        }

        if not consolidated_path:
            return default_stats

        try:
            with open(consolidated_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
                return report_data.get("statistics", default_stats)
        except Exception as e:
            logger.error(f"Failed to load statistics: {e}")
            return default_stats

    def _create_summary_tables(self, statistics: Dict[str, Any], context: ScanContext) -> List[Table]:
        """Create summary tables for display."""
        tables = []

        findings_table = Table(show_header=True, box=box.ROUNDED, title="Security Findings", title_style="bold red")
        findings_table.add_column("Severity", style="bold")
        findings_table.add_column("Count", justify="right")

        severity_counts = statistics.get("severity_counts", {})
        for severity in ["Critical", "High", "Medium", "Low"]:
            count = severity_counts.get(severity.lower(), 0)
            color = {"Critical": "red", "High": "orange3", "Medium": "yellow", "Low": "green"}[severity]
            findings_table.add_row(severity, f"[bold {color}]{count}[/bold {color}]")

        total = severity_counts.get("total", 0)
        findings_table.add_row("Total", f"[bold]{total}[/bold]")
        tables.append(findings_table)

        scanner_table = Table(show_header=True, box=box.ROUNDED, title="Scanners Used", title_style="bold blue")
        scanner_table.add_column("Scanner", style="bold")
        scanner_table.add_column("Findings", justify="right")

        scanner_counts = statistics.get("scanner_counts", {})
        for scanner, count in scanner_counts.items():
            scanner_table.add_row(esc(scanner), str(count))
        tables.append(scanner_table)

        deps_table = Table(show_header=True, box=box.ROUNDED, title="Dependency Statistics", title_style="bold blue")
        deps_table.add_column("Metric", style="bold")
        deps_table.add_column("Value")

        action_count_by_depth = context.action_count_by_depth()
        deps_table.add_row("Workflows Scanned", str(len(context.parsed_workflows)))
        deps_table.add_row("Total Dependencies", str(len(context.action_depths)))
        deps_table.add_row("Maximum Depth", str(max(action_count_by_depth.keys()) if action_count_by_depth else 0))

        for depth, count in sorted(action_count_by_depth.items()):
            deps_table.add_row(f"Actions at Depth {depth}", str(count))
        tables.append(deps_table)

        return tables

    def _display_report_paths(self, reports: Dict[str, Optional[str]], pr_url: Optional[str]) -> None:
        """Display generated report paths."""
        reports_table = Table.grid(padding=(0, 1))
        reports_table.add_column(no_wrap=True)
        reports_table.add_column()

        rows = [
            ('consolidated', 'Consolidated JSON report'),
            ('html', 'HTML report'),
            ('pdf', 'PDF report'),
            ('graph', 'Dependency graph'),
            ('pin_preview', 'Pinning preview diff'),
        ]
        for key, label in rows:
            if reports.get(key):
                reports_table.add_row(
                    "[bold green]✓[/bold green]",
                    f"{label}: [bold]{esc(os.path.abspath(reports[key]))}[/bold]"
                )

        if pr_url:
            reports_table.add_row("[bold green]✓[/bold green]",
                                  f"Pinning PR: [bold]{esc(pr_url)}[/bold]")

        self.console.print(Panel(
            reports_table,
            title="Generated Reports",
            border_style="green"
        ))
