# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
CLI commands for ActChain.
"""

import os
import re
import subprocess
import sys
import click
from rich.console import Console
from rich.table import Table
from rich import box

from .. import __version__
from ..constants import (
    AI_DEFAULT_MODEL, AI_MODEL_PATTERN, DEFAULT_MAX_DEPTH, DEFAULT_MIN_SEVERITY,
    DEFAULT_OUTPUT_DIR, EXIT_MALICIOUS, PR_GATE_SEVERITY_DEFAULT, SCANNER_TYPES
)
from ..logging_config import configure_logging
from ..utils.path_utils import PathUtils
from ..utils.system_utils import SystemUtils
from .display import ActChainDisplay, esc

console = Console()

_REPO_PATH_RE = re.compile(
    r'^/?(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?$'
)


def _parse_github_remote(url: str) -> 'str | None':
    """
    Extract owner/repo from a git remote URL, accepting ONLY github.com as
    the host (a lookalike host like notgithub.com or an enterprise mirror
    must not be silently scanned as a github.com repository).
    """
    url = (url or '').strip()
    if '://' in url:  # https://github.com/owner/repo(.git)
        rest = url.split('://', 1)[1]
        host, _, path = rest.partition('/')
        host = host.rsplit('@', 1)[-1]  # strip userinfo
    elif '@' in url and ':' in url:  # git@github.com:owner/repo(.git)
        host_part = url.rsplit('@', 1)[1]
        host, _, path = host_part.partition(':')
    else:
        return None

    if host.split(':', 1)[0].lower() != 'github.com':
        return None

    match = _REPO_PATH_RE.match(path)
    if not match:
        return None
    return f"{match.group('owner')}/{match.group('repo')}"


def _infer_repo_from_git() -> 'str | None':
    """Infer owner/repo from the current directory's origin remote."""
    git = SystemUtils.resolve_command('git')
    if not git:
        return None
    try:
        result = subprocess.run(
            [git, 'config', '--get', 'remote.origin.url'],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return _parse_github_remote(result.stdout)


def _github_token_from_gh() -> 'str | None':
    """Fall back to the GitHub CLI's stored token (gh auth token)."""
    gh = SystemUtils.resolve_command('gh')
    if not gh:
        return None
    try:
        result = subprocess.run(
            [gh, 'auth', 'token'],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    token = result.stdout.strip()
    return token or None


class CLIError(Exception):
    """Custom exception for CLI errors."""
    pass


@click.group()
@click.version_option(version=__version__)
def cli():
    """ActChain - Analyze GitHub Actions workflows and their dependencies for security issues."""
    pass


@cli.command()
@click.option('--repo', '-r', default=None,
              help='GitHub repository in the format "owner/repo". When omitted, inferred '
                   'from the current directory\'s "origin" git remote.')
@click.option('--token', '-t', envvar='GITHUB_TOKEN',
              help='GitHub personal access token. Prefer the GITHUB_TOKEN environment '
                   'variable: a token passed on the command line can end up in your '
                   'shell history and is visible in the process list. When neither is '
                   'set, the GitHub CLI token (gh auth token) is used if available.')
@click.option('--output-dir', '-o', default=DEFAULT_OUTPUT_DIR, envvar='ACTCHAIN_OUTPUT_DIR',
              show_default=True, help='Directory to save scan reports (env: ACTCHAIN_OUTPUT_DIR)')
@click.option('--workflow-path', help='Path to a specific workflow file to scan')
@click.option('--scan-all-workflows', is_flag=True,
              help='Scan all workflows in the repository without interactive selection')
@click.option('--max-depth', type=int, default=DEFAULT_MAX_DEPTH, help='Maximum depth for recursive scanning')
@click.option('--scanner', type=click.Choice(SCANNER_TYPES), default='all',
              help='Scanner to use (all: use all available scanners, zizmor: Zizmor only, opengrep: OpenGrep only)')
@click.option('--min-severity', type=click.Choice(['critical', 'high', 'medium', 'low']),
              default=DEFAULT_MIN_SEVERITY, help='Minimum severity level')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--debug', '-d', is_flag=True, help='Enable debug mode')
@click.option('--deep-scan', is_flag=True,
              help='Also follow heuristic dependencies (commonly co-used actions and '
                   'references found in action READMEs). These are guesses, not declared '
                   'dependencies, and may fetch additional repositories.')
@click.option('--dependency-graph', is_flag=True, help='Generate dependency graph')
@click.option('--ai', is_flag=True,
              help='Enable AI analysis: one agent triages the tool findings, another '
                   'audits the action chain content for malicious behavior. OPT-IN: this '
                   'sends scanned workflow/action content and findings to the Anthropic '
                   'API. Requires ANTHROPIC_API_KEY and pip install "actchain[ai]".')
@click.option('--ai-model', default=AI_DEFAULT_MODEL, show_default=True,
              help='Claude model used for AI analysis')
@click.option('--pdf', is_flag=True,
              help='Also generate a PDF report (requires pip install "actchain[pdf]")')
@click.option('--create-pr', is_flag=True,
              help='After a clean scan, open a pull request pinning the scanned actions '
                   'to their verified commit SHAs. Implies --scan-all-workflows and '
                   'requires a token with contents:write and pull-requests:write. The '
                   'PR only opens when the policy gate passes (see --pr-gate-severity).')
@click.option('--pr-gate-severity', type=click.Choice(['critical', 'high', 'medium', 'low']),
              default=PR_GATE_SEVERITY_DEFAULT, show_default=True,
              help='Block the pinning PR when any finding at or above this severity '
                   'exists. The gate also fails closed on scan errors or incomplete '
                   'coverage; AI triage can never unblock it.')
@click.option('--dry-run', is_flag=True,
              help='With --create-pr: compute and preview the pin plan and gate verdict '
                   'without pushing anything')
@click.option('--yes', 'assume_yes', is_flag=True,
              help='Skip the interactive confirmation before opening the PR')
@click.option('--full', is_flag=True, help='Shortcut for --scan-all-workflows --pdf')
def scan(repo, token, output_dir, workflow_path, scan_all_workflows, max_depth, scanner, min_severity,
         verbose, debug, deep_scan, dependency_graph, ai, ai_model, pdf, create_pr,
         pr_gate_severity, dry_run, assume_yes, full):
    """Scan GitHub Actions workflows and their dependencies."""

    # Configure logging. Explicit --verbose/--debug flags win over the
    # ACTCHAIN_LOG_LEVEL environment variable.
    env_log_level = None if (verbose or debug) else SystemUtils.get_env_var('ACTCHAIN_LOG_LEVEL')
    configure_logging(verbose or debug,
                      log_file=f"{output_dir}/actchain_debug.log" if debug else None,
                      log_level=env_log_level)

    # Flag composition and coherence checks.
    if full:
        if workflow_path:
            console.print("[bold red]Error:[/bold red] --full implies --scan-all-workflows; "
                          "it cannot be combined with --workflow-path")
            sys.exit(1)
        scan_all_workflows = True
        pdf = True
    if (dry_run or assume_yes) and not create_pr:
        console.print("[bold red]Error:[/bold red] --dry-run/--yes only make sense with --create-pr")
        sys.exit(1)
    if not ai and ai_model != AI_DEFAULT_MODEL:
        console.print("[dim]Note: --ai-model has no effect without --ai.[/dim]")
    if not create_pr and pr_gate_severity != PR_GATE_SEVERITY_DEFAULT:
        console.print("[dim]Note: --pr-gate-severity has no effect without --create-pr.[/dim]")
    if create_pr:
        if workflow_path:
            console.print("[bold red]Error:[/bold red] --create-pr scans and pins ALL workflows; "
                          "it cannot be combined with --workflow-path")
            sys.exit(1)
        if min_severity != 'low':
            console.print("[bold red]Error:[/bold red] --create-pr requires --min-severity low "
                          "(the default) so the policy gate sees every finding")
            sys.exit(1)
        scan_all_workflows = True
    if ai and not re.match(AI_MODEL_PATTERN, ai_model or ''):
        console.print(f"[bold red]Error:[/bold red] Invalid --ai-model value: {esc(ai_model)}")
        sys.exit(1)
    if pdf:
        import importlib.util
        if importlib.util.find_spec('fpdf') is None:
            console.print('[bold red]Error:[/bold red] PDF reports require the "pdf" extra: '
                          'pip install "actchain[pdf]"')
            sys.exit(1)

    # Repository: explicit flag wins; otherwise infer from the local checkout.
    if not repo:
        repo = _infer_repo_from_git()
        if repo:
            console.print(f"[dim]Repository inferred from git remote: {esc(repo)}[/dim]")
        else:
            console.print("[bold red]Error:[/bold red] No --repo given and the current "
                          "directory has no GitHub 'origin' remote")
            console.print("[yellow]Example:[/yellow] actchain scan --repo owner/repository")
            sys.exit(1)
    if '/' not in repo:
        console.print("[bold red]Error:[/bold red] Repository must be in 'owner/repo' format")
        console.print("[yellow]Example:[/yellow] --repo microsoft/actions")
        sys.exit(1)

    # Token: env/flag, then the GitHub CLI's stored token.
    if not token:
        token = _github_token_from_gh()
        if token:
            console.print("[dim]Using the GitHub CLI token (gh auth token).[/dim]")
    if not token:
        console.print("[bold red]Error:[/bold red] GitHub token is required. Set GITHUB_TOKEN environment variable.")
        console.print("\n[yellow]To get a GitHub token:[/yellow]")
        console.print("1. Go to https://github.com/settings/tokens")
        console.print("2. Generate a new token with 'repo' scope")
        console.print("3. Set it as environment variable: export GITHUB_TOKEN='your_token'")
        sys.exit(1)

    # Validate conflicting options
    if workflow_path and scan_all_workflows:
        console.print("[bold red]Error:[/bold red] Cannot use --workflow-path and --scan-all-workflows together")
        console.print("[yellow]Choose either:[/yellow]")
        console.print("  • --workflow-path to scan a specific workflow")
        console.print("  • --scan-all-workflows to scan all workflows")
        console.print("  • Neither to get interactive selection")
        sys.exit(1)

    # Show scanner information if using 'all'
    if scanner == 'all':
        _show_scanner_availability(verbose or debug)

    # Ensure output directory exists
    try:
        output_dir = str(PathUtils.validate_path(output_dir))
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Cannot create output directory: {e}")
        sys.exit(1)

    # Create configuration. The token is deliberately NOT part of this dict:
    # the config travels through the whole pipeline (and may be logged or
    # displayed); the token is handed only to the GitHub client.
    config = {
        'repo': repo,
        'output_dir': output_dir,
        'workflow_path': workflow_path,
        'scan_all_workflows': scan_all_workflows,
        'max_depth': max_depth,
        'scanner': scanner,
        'min_severity': min_severity,
        'verbose': verbose,
        'debug': debug,
        'deep_scan': deep_scan,
        'dependency_graph': dependency_graph,
        'ai': ai,
        'ai_model': ai_model,
        'pdf': pdf,
        'create_pr': create_pr,
        'pr_gate_severity': pr_gate_severity,
        'dry_run': dry_run,
        'assume_yes': assume_yes,
    }

    # Show information about scan mode
    if scan_all_workflows:
        console.print("[bold blue]Mode:[/bold blue] Scanning all workflows in repository")
    elif workflow_path:
        console.print(f"[bold blue]Mode:[/bold blue] Scanning specific workflow: {esc(workflow_path)}")
    else:
        console.print("[bold blue]Mode:[/bold blue] Interactive workflow selection")

    # Initialize and run scan
    try:
        display = ActChainDisplay()
        context = display.run_scan(config, token)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {esc(e)}")
        if debug:
            import traceback
            console.print("\n[bold red]Traceback:[/bold red]")
            console.print(esc(traceback.format_exc()))
        sys.exit(1)

    # Exit-code contract (documented in the README): 2 when malicious
    # behavior was detected, 1 on operational errors (a whole stage failed,
    # the consolidated report is missing, or the requested PR failed),
    # 0 otherwise. A gate-blocked PR is a clean policy outcome -> 0.
    if context.malicious_findings():
        sys.exit(EXIT_MALICIOUS)
    stage_failures = any(e.item in ('<stage>', '<pr>') for e in context.errors)
    if stage_failures or not context.report_paths.get('consolidated'):
        console.print("[bold red]Scan completed with operational errors — see output above.[/bold red]")
        sys.exit(1)


@cli.command()
def info():
    """Display information about the environment and dependencies."""
    display = ActChainDisplay()
    display.show_environment_info()


def _show_scanner_availability(verbose: bool = False):
    """Show which scanners are available when using 'all' option."""
    if not verbose:
        return

    console.print("\n[bold blue]Scanner Availability Check:[/bold blue]")

    scanner_table = Table(show_header=True, box=box.ROUNDED, title="Scanners", title_style="bold blue")
    scanner_table.add_column("Scanner", style="bold")
    scanner_table.add_column("Status", justify="center")
    scanner_table.add_column("Notes")

    # Check Zizmor
    try:
        from ..scanners.factory import ScannerFactory
        ScannerFactory.create_scanner("zizmor")
        scanner_table.add_row("Zizmor", "[green]✓ Available[/green]", "GitHub Actions security scanner")
    except Exception as e:
        scanner_table.add_row("Zizmor", "[red]✗ Not Available[/red]", f"Error: {esc(str(e)[:50])}...")

    # Check OpenGrep/Semgrep
    try:
        ScannerFactory.create_scanner("opengrep")
        scanner_table.add_row("OpenGrep/Semgrep", "[green]✓ Available[/green]", "Static analysis tool")
    except Exception as e:
        scanner_table.add_row("OpenGrep/Semgrep", "[red]✗ Not Available[/red]", f"Error: {esc(str(e)[:50])}...")

    console.print(scanner_table)
    console.print()


@cli.command()
@click.option('--install-all', is_flag=True, help='Install all optional scanner dependencies')
def setup(install_all):
    """Set up ActChain and install optional dependencies."""
    console.print("[bold blue]ActChain Setup[/bold blue]\n")

    # Check current environment
    env_report = SystemUtils.create_environment_report()

    # Show platform info
    platform_info = env_report['platform']
    console.print(f"[bold]Platform:[/bold] {platform_info['system']} {platform_info['release']}")
    console.print(f"[bold]Python:[/bold] {platform_info['python_version']}\n")

    # Show dependency status
    deps_table = Table(show_header=True, box=box.ROUNDED, title="Dependencies", title_style="bold blue")
    deps_table.add_column("Dependency", style="bold")
    deps_table.add_column("Status", justify="center")
    deps_table.add_column("Action Needed")

    dependencies = env_report['dependencies']

    for dep_name, is_available in dependencies.items():
        if is_available:
            deps_table.add_row(dep_name.capitalize(), "[green]✓ Installed[/green]", "None")
        else:
            if dep_name == "zizmor":
                deps_table.add_row(dep_name.capitalize(), "[red]✗ Missing[/red]", "pip install zizmor")
            elif dep_name == "docker":
                deps_table.add_row(dep_name.capitalize(), "[red]✗ Missing[/red]", "Install Docker")
            else:
                deps_table.add_row(dep_name.capitalize(), "[red]✗ Missing[/red]", f"Install {dep_name}")

    console.print(deps_table)

    # Check environment variables
    env_vars = env_report['environment_variables']
    console.print("\n[bold]Environment Variables:[/bold]")
    for var_name, is_set in env_vars.items():
        status = "[green]✓ Set[/green]" if is_set else "[red]✗ Not Set[/red]"
        console.print(f"  {var_name}: {status}")

    if not env_vars.get('GITHUB_TOKEN'):
        console.print("\n[yellow]Warning:[/yellow] GITHUB_TOKEN not set. You'll need to provide it via --token option.")
        console.print("To set it: export GITHUB_TOKEN='your_token_here'")

    # Install optional dependencies if requested
    if install_all:
        console.print("\n[bold blue]Installing Optional Dependencies...[/bold blue]")
        _install_optional_dependencies()
    else:
        console.print("\n[dim]Tip: Use --install-all to install optional scanner dependencies[/dim]")


def _install_optional_dependencies():
    """Install optional dependencies for enhanced scanning."""
    import subprocess

    # Only Python packages are installed here, and only because the user
    # explicitly passed --install-all.
    optional_packages = [
        ("zizmor", "GitHub Actions security scanner"),
        ("semgrep", "OpenGrep/Semgrep scanner support"),
    ]

    for package, description in optional_packages:
        try:
            console.print(f"Installing {package} ({description})...")
            subprocess.run([sys.executable, "-m", "pip", "install", package],
                           check=True, capture_output=True)
            console.print(f"[green]✓[/green] Successfully installed {package}")
        except subprocess.CalledProcessError as e:
            console.print(f"[red]✗[/red] Failed to install {package}: {esc(e)}")
        except Exception as e:
            console.print(f"[red]✗[/red] Error installing {package}: {esc(e)}")

    # The pip "graphviz" package only provides Python bindings; the `dot`
    # binary used for graph rendering must come from a system package.
    console.print(
        "\n[dim]Note: dependency graphs additionally require the Graphviz system package "
        "(https://graphviz.org/download/ — e.g. 'apt install graphviz', 'brew install graphviz' "
        "or 'choco install graphviz').[/dim]"
    )


@cli.command()
@click.argument('scanner_type', type=click.Choice(['zizmor', 'opengrep', 'all']),
                default='all', required=False)
def test_scanner(scanner_type):
    """Test if a specific scanner is working correctly (default: all)."""
    console.print(f"[bold blue]Testing {scanner_type} scanner(s)...[/bold blue]\n")

    try:
        from ..scanners.factory import get_scanner

        # Get scanner(s)
        scanners = get_scanner(scanner_type, "low")
        if not isinstance(scanners, list):
            scanners = [scanners]

        # Test each scanner
        for scanner in scanners:
            console.print(f"Testing {scanner.scanner_name}...")

            # Create a simple test workflow
            test_workflow = """
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Test step
        run: echo "Hello World"
"""

            try:
                result = scanner.scan_workflow(test_workflow, "test.yml")
                if "error" in result.get("results", {}):
                    console.print(f"[red]✗[/red] {scanner.scanner_name} failed: {esc(result['results']['error'])}")
                else:
                    findings_count = len(result.get("results", {}).get("findings", []))
                    console.print(f"[green]✓[/green] {scanner.scanner_name} working (found {findings_count} findings)")
            except Exception as e:
                console.print(f"[red]✗[/red] {scanner.scanner_name} error: {esc(e)}")

    except Exception as e:
        console.print(f"[red]Error:[/red] Failed to test scanner: {esc(e)}")


@cli.command()
@click.option('--repo', '-r', required=True, help='GitHub repository in the format "owner/repo"')
@click.option('--token', '-t', envvar='GITHUB_TOKEN',
              help='GitHub personal access token (prefer the GITHUB_TOKEN environment variable)')
def list_workflows(repo, token):
    """List all workflows in a repository."""
    if not token:
        console.print("[bold red]Error:[/bold red] GitHub token is required. Set GITHUB_TOKEN environment variable.")
        sys.exit(1)

    if not repo or '/' not in repo:
        console.print("[bold red]Error:[/bold red] Repository must be in 'owner/repo' format")
        sys.exit(1)

    try:
        from ..core.github_client import GitHubClient

        console.print(f"[bold blue]Fetching workflows from {repo}...[/bold blue]")

        # Initialize GitHub client
        github_client = GitHubClient(token, repo)
        workflows = github_client.get_workflows()

        if not workflows:
            console.print(f"[yellow]No workflows found in {repo}[/yellow]")
            return

        # Display workflows table
        table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED,
                      title=f"Workflows in {repo}", title_style="bold blue")
        table.add_column("#", style="dim", width=4)
        table.add_column("Workflow Name", style="cyan")
        table.add_column("Path", style="dim")

        for i, workflow in enumerate(workflows, 1):
            table.add_row(str(i), esc(workflow['name']), esc(workflow['path']))

        console.print(table)
        console.print(f"\n[bold]Total workflows found:[/bold] {len(workflows)}")
        console.print(
            "\n[dim]Tip: Use 'actchain scan --repo {repo} --scan-all-workflows' to scan all workflows[/dim]".format(
                repo=esc(repo)))

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {esc(e)}")
        sys.exit(1)
