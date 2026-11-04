# ActChain - Complete Project Documentation

*Last Updated: November 2026*

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture Overview](#architecture-overview)
3. [Project Structure](#project-structure)
4. [Core Concepts](#core-concepts)
5. [Module Documentation](#module-documentation)
6. [Development Guide](#development-guide)
7. [Configuration and Settings](#configuration-and-settings)
8. [Troubleshooting](#troubleshooting)
9. [Extension Guide](#extension-guide)

## 📖 Project Overview

### What is ActChain?

ActChain is a comprehensive security analysis tool for GitHub Actions workflows and their dependencies. It performs deep supply chain scanning to identify security vulnerabilities, misconfigurations, and compliance issues in CI/CD pipelines.

### Key Features

- **Staged Scan Pipeline**: Explicit, console-free stages with typed progress events
- **Deep Dependency Analysis**: Recursively scans GitHub Actions and their dependencies
- **Multi-Scanner Support**: Integrates Zizmor and OpenGrep/Semgrep scanners
- **Opt-In AI Analysis**: Finding triage and malicious-behavior audit via the Anthropic API
- **Policy-Gated Pinning PRs**: Pull requests pinning actions to the commit SHAs that were scanned
- **Supply Chain Visualization**: Generates dependency graphs and trees
- **Multi-Format Reporting**: JSON, HTML and optional PDF reports with detailed findings
- **Configurable Scanning**: Adjustable depth, severity filtering, and scanner selection

### Design Philosophy

1. **Modular Architecture**: Clear separation of concerns across modules
2. **Extensibility**: Easy to add new scanners, report formats, and features
3. **Security First**: Built-in security practices and safe handling of sensitive data
4. **User Experience**: Rich CLI with helpful error messages and progress tracking
5. **Type Safety**: Comprehensive type hints for better maintainability

## 🏗️ Architecture Overview

### High-Level Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Layer     │    │  Scan Pipeline  │    │    External     │
│                 │    │ (actchain/      │    │   Dependencies  │
├─────────────────┤    │  pipeline)      │    ├─────────────────┤
│ • Commands      │───▶├─────────────────┤───▶│ • GitHub API    │
│ • Display/Rich  │    │ • Discovery     │    │ • Zizmor        │
│ • Workflow      │    │ • Scanners      │    │ • OpenGrep      │
│   selection     │    │ • AI stages     │    │ • Anthropic API │
└─────────────────┘    │ • Gate/Reports  │    │   (--ai only)   │
                       │ • Pinning PR    │    │ • Graphviz      │
                       └─────────────────┘    └─────────────────┘
```

The CLI layer (`cli/display.py`) selects and fetches workflows, builds the
stage list, and renders the pipeline's typed progress events with Rich. The
pipeline itself is console-free and mutates a shared `ScanContext`.

### Scan Pipeline

Stages run in this order (`actchain/pipeline/stages.py`):

1. **`discovery`** (critical) — parses workflows and recursively resolves the
   action chain into plain-data `ActionNode` trees; per-workflow parse
   failures are recorded and skipped.
2. **`scan:<scanner>`** (one stage per scanner) — runs the scanner over every
   parsed workflow and resolved action; scanner errors are recorded as
   coverage gaps, never dropped.
3. **`ai-triage`** (opt-in, `--ai`) — annotates tool findings with advisory
   AI verdicts; never removes findings.
4. **`ai-audit`** (opt-in, `--ai`) — audits action definitions for malicious
   behavior; may only add findings.
5. **`policy-gate`** (`--create-pr` only) — evaluates the monotonic,
   fail-closed pinning gate and computes the pin plan, before reporting so
   every format carries the verdict.
6. **`report`** — consolidated JSON, HTML, optional PDF, per-workflow tree
   files, optional graph, and the pinning preview diff.
7. **`pinning-pr`** (`--create-pr`, not `--dry-run`) — opens the PR after the
   reports, so a PR failure can never lose them.

Error semantics: stages isolate per-item failures into `context.errors`; a
`StageError` from a non-critical stage is recorded and the run continues
(fail-closed consumers such as the policy gate see it); only a critical stage
(discovery) aborts the pipeline.

## 📁 Project Structure

### Root Level Files

```
ActChain/
├── .github/                   # CI, CodeQL and Dependabot configuration
├── .gitignore                 # Git ignore patterns
├── README.md                  # User-facing documentation
├── Documentation.md           # This comprehensive guide
├── SECURITY.md                # Vulnerability disclosure policy
├── CONTRIBUTING.md            # Contribution guide
├── CHANGELOG.md               # Release history
├── requirements.in            # Abstract dependencies (secure floors)
├── requirements.txt           # Hash-pinned lockfile
├── pyproject.toml             # Package configuration and metadata
└── tests/                     # Test suite
```

### Main Package Structure

```
actchain/
├── __init__.py               # Package initialization and main exports
├── constants.py              # Project-wide constants and configuration
├── logging_config.py         # Logging setup and configuration
├── ai/                       # Optional AI triage & audit (--ai)
├── cli/                      # Command-line interface
├── core/                     # Core business logic
├── pipeline/                 # Staged scan pipeline
├── pinning/                  # Pin-plan builder and pinning PR
├── scanners/                 # Security scanners
├── reports/                  # Report generation
└── utils/                    # Utility functions
```

## 🧠 Core Concepts

### 1. Workflow Scanning Process

**Workflow**: A GitHub Actions YAML file that defines CI/CD automation
**Action**: A reusable unit of code that performs a specific task
**Dependency**: An action that another action depends on (directly or transitively)
**Supply Chain**: The complete tree of all actions and their dependencies

### 2. Dependency Resolution

ActChain builds a dependency tree by:
1. Parsing workflow files to extract action references
2. Fetching action definitions from GitHub
3. Analyzing composite actions for nested dependencies
4. Recursively following the dependency chain
5. Detecting circular dependencies and handling edge cases

### 3. Security Scanning

Multiple scanners analyze different aspects:
- **Static Analysis**: Code patterns and configurations
- **Permission Analysis**: Excessive or unnecessary permissions
- **Dependency Security**: Known vulnerabilities in dependencies
- **Best Practices**: Adherence to security guidelines

### 4. Report Generation

Results are consolidated into:
- **JSON Reports**: Machine-readable structured data (schema v1.1, see below)
- **HTML Reports**: Human-readable static reports
- **PDF Reports**: Optional executive summary (`--pdf`)
- **Dependency Graphs**: Visual representations of the supply chain

### 5. Pinning Policy Gate

With `--create-pr`, the scan ends in a gate decision: the pinning PR opens
only when no counted finding reaches `--pr-gate-severity` *and* coverage was
complete. The gate is **monotonic** (AI triage verdicts are advisory
annotations; only raw tool findings and AI-audit findings count) and
**fail-closed** (any scan error, skipped workflow, unresolved ref, discovery
cutoff or incomplete AI coverage blocks it). Findings that pinning itself
remediates (`unpinned-uses`-style rules) are excluded. See `GateResult` in
`actchain/pipeline/context.py`.

## 📚 Module Documentation

### CLI Module (`actchain/cli/`)

**Purpose**: Handles all user interaction and command-line interface

#### `cli/main.py`
- **Function**: Main entry point for the CLI application
- **Key Features**: 
  - ASCII logo display
  - Dependency checking
  - Error handling and graceful exit
- **Entry Point**: Called when user runs `actchain` command

#### `cli/commands.py`
- **Function**: Defines CLI commands and their parameters
- **Key Commands**:
  - `scan`: Main scanning command with all options
  - `info`: Environment and dependency information
  - `setup`: Check the environment; `--install-all` installs scanner packages
  - `test-scanner`: Verify that scanners run correctly
  - `list-workflows`: List workflows in a repository
- **Validation**: Input validation and user guidance

#### `cli/display.py`
- **Function**: All UI display logic and scanning orchestration
- **Key Features**:
  - Progress tracking with Rich library
  - Interactive workflow selection
  - Error display with helpful suggestions
  - Results presentation and formatting
- **Integration**: Coordinates between all other modules

### Core Module (`actchain/core/`)

**Purpose**: Core business logic and GitHub API interaction

#### `core/github_client.py`
- **Function**: GitHub API client for fetching workflows and actions
- **Key Features**:
  - Authentication handling
  - Rate limiting awareness
  - Caching for performance
  - Error handling with retry logic
- **Security**: Safe token handling and log sanitization

#### `core/workflow_parser.py`
- **Function**: Parses GitHub Actions YAML workflows
- **Key Features**:
  - YAML parsing and validation
  - Action reference extraction
  - Composite action support
  - Permission analysis
- **Error Handling**: Detailed error messages for malformed workflows

#### `core/action_resolver.py`
- **Function**: Resolves action references and builds dependency trees
- **Key Features**:
  - Action content fetching
  - Dependency extraction from multiple sources
  - Caching for performance
  - Security analysis of action configurations
- **Intelligence**: Known dependency patterns for popular actions

#### `core/refs.py`
- **Function**: Centralized parsing and validation of action references
- **Key Features**:
  - Single strict grammar for `owner/repo[/subpath][@ref]`, shared by the
    resolver, GitHub client and pinning
  - Rejects `docker://`, local, expression and malformed refs early
  - Classifies refs: SHA-pinned, short SHA, reusable workflow

### Pipeline Module (`actchain/pipeline/`)

**Purpose**: The staged scan pipeline — console-free scan orchestration

#### `pipeline/context.py`
- **Function**: `ScanContext`, the mutable shared state passed through stages
- **Key Features**:
  - `findings` is the single source of truth; every finding gets a stable
    `finding_id` when added
  - Plain-data `ActionNode` dependency trees (the CLI renders Rich trees from them)
  - `GateResult` (monotonic, fail-closed gate outcome) and `PinPlan` dataclasses

#### `pipeline/base.py` and `pipeline/pipeline.py`
- **Function**: The `Stage` ABC and the `ScanPipeline` runner
- **Error Semantics**: per-item failures are recorded without aborting; a
  `StageError` from a non-critical stage is recorded and the run continues;
  only a critical stage (discovery) aborts the pipeline

#### `pipeline/events.py`
- **Function**: Typed progress events (`StageStarted/Finished/Failed`,
  `ItemProgress`, `Notice`)
- **Design**: stages emit events, the CLI display layer renders them (and
  escapes untrusted payload strings)

#### `pipeline/stages.py`
- **Function**: The concrete stages, in scan order (see Architecture Overview)
- **Key Features**:
  - `PolicyGateStage` evaluates the fail-closed gate and computes the pin plan
    before reporting, so every report format carries the verdict
  - `PinningPRStage` runs after `ReportStage`, so a PR failure can never lose
    the reports; the PR URL is patched into the consolidated JSON

### AI Module (`actchain/ai/`) — optional

**Purpose**: Opt-in AI analysis (`--ai`), installed via the `ai` extra

#### `ai/client.py`
- **Function**: `AIClient`, a budgeted wrapper around the Anthropic Messages API
- **Key Features**:
  - Lazy `anthropic` import; the SDK resolves `ANTHROPIC_API_KEY` itself (env only)
  - Hard cap of 12 API requests per scan (`AI_MAX_CALLS_PER_SCAN`)
  - Structured-output requests; SDK errors mapped to constructed
    `AIAnalysisError` messages (raw exception text never reaches the console)

#### `ai/triage.py`
- **Function**: Agent A — advisory triage of tool findings
- **Key Features**:
  - Annotates findings in place (`ai_triage`: verdict + rationale); never
    removes or re-ranks them
  - Prompt-injection hardening: verdicts validated against the whitelist and
    the finding IDs actually sent; everything else is dropped and counted

#### `ai/audit.py`
- **Function**: Agent B — malicious-behavior audit of action definitions
- **Key Features**:
  - Dedupes by content, skips `actions/`/`github/` namespaces, orders
    deepest-first then unpinned-first, caps at 30 actions per scan
  - May only add findings (`source_scanner: "AI Audit (Claude)"`); the
    `malicious` flag requires at least medium model confidence
  - Records honest per-action coverage statuses (audited, truncated, skipped,
    failed, not_audited) that the policy gate consumes

### Pinning Module (`actchain/pinning/`)

**Purpose**: Pin-plan building and pinning PR creation

#### `pinning/planner.py`
- **Function**: `build_pin_plan` — pure textual rewrite of workflow `uses:` lines
- **Key Features**:
  - Writes only the commit SHAs recorded when the content was scanned (never
    re-resolves refs)
  - Preserves formatting and comments; rewrites only parser-confirmed step
    refs (ignores `uses:`-looking text inside `run:` scripts and comments)
  - Skips reusable workflows, already-pinned refs and refs without a recorded
    SHA, with fixed reason strings

#### `pinning/pr.py`
- **Function**: Hardened PR body rendering and branch/commit/PR creation
- **Key Features**:
  - No raw workflow line content in the PR body; every dynamic value is
    validated and rendered inside length-capped code spans
  - TOCTOU guard: every changed file is verified byte-for-byte against its
    scan-time content at the base commit before anything is created
  - One commit via the Git Data API on a fresh
    `actchain/pin-actions-<timestamp>` branch; never force-pushes

### Scanners Module (`actchain/scanners/`)

**Purpose**: Security scanner implementations and management

#### `scanners/base.py`
- **Function**: Abstract base class defining scanner interface
- **Key Features**:
  - Common scanner functionality
  - Severity filtering
  - Report structure standardization
- **Design Pattern**: Template method pattern for consistent behavior

#### `scanners/zizmor.py`
- **Function**: Zizmor scanner implementation
- **Key Features**:
  - GitHub Actions specific security rules
  - Fast and accurate scanning
  - Clear installation instructions when missing (never auto-installs)
- **Output Parsing**: Converts Zizmor output to standardized format

#### `scanners/opengrep.py`
- **Function**: OpenGrep/Semgrep scanner implementation
- **Key Features**:
  - Advanced static analysis
  - Extensive rule sets
  - Fallback pattern matching
- **Integration**: Uses built-in GitHub Actions rule sets

#### `scanners/factory.py`
- **Function**: Scanner factory and management
- **Key Features**:
  - Scanner instantiation
  - Error handling for missing scanners
  - Support for multiple scanner execution
- **Extensibility**: Easy addition of new scanners

### Reports Module (`actchain/reports/`)

**Purpose**: Report generation and output formatting

#### `reports/manager.py`
- **Function**: Manages report generation and storage
- **Key Features**:
  - Unique scan directory creation
  - Consolidated report generation
  - Dependency graph generation
  - Statistics aggregation
- **Organization**: Creates timestamped scan directories

#### `reports/html_converter.py`
- **Function**: Converts JSON reports to static HTML
- **Key Features**:
  - Severity-based color coding and grouping
  - Malicious-behavior banner, pinning-gate section and AI analysis card
  - All untrusted content HTML-escaped
  - Responsive design

#### `reports/pdf_converter.py`
- **Function**: Converts the consolidated JSON report to an executive PDF
  (optional `pdf` extra, `fpdf2`)
- **Key Features**:
  - Summary page: severity totals, scanners, AI status, malicious banner,
    gate verdict
  - Full detail for malicious/critical/high findings; medium/low capped at 25
    each; dependency appendix capped at 50 rows
  - All attacker-influenced text sanitized and length-capped; a PDF failure
    never breaks the scan

#### Consolidated report schema (v1.1)

Top-level fields of `consolidated_report.json`:

- `meta` — timestamp, scan_id, total_reports, `report_version` (`"1.1"`)
- `workflow` — name/path of the primary scanned workflow
- `findings` — all normalized findings, malicious first then by severity;
  each carries a stable `finding_id` (`f-0001`…) and `source_scanner`, plus
  `ai_triage` (advisory verdict + rationale), `malicious`, `confidence` and
  `action_ref` where applicable
- `dependencies` — `{name, type, depth, findings_count}` per resolved action
- `statistics` — severity, scanner and dependency counts
- `gate` (with `--create-pr`) — evaluated/passed/threshold/reasons, blocking
  and excluded counts, and `pin_plan` (entries, skipped, files changed)
- `ai` (with `--ai`) — model, call count, triage summary, audit coverage
- `pr_url` — patched in after the pinning PR is opened

### Utils Module (`actchain/utils/`)

**Purpose**: Utility functions organized by concern

#### `utils/path_utils.py`
- **Function**: Path operations and validation
- **Key Features**: Path normalization, directory creation, filename sanitization

#### `utils/file_utils.py`
- **Function**: Safe file operations
- **Key Features**: Secure read/write operations, error handling, encoding management

#### `utils/system_utils.py`
- **Function**: System operations and environment detection
- **Key Features**: Command availability checking, platform info, dependency validation

#### `utils/format_utils.py`
- **Function**: Data formatting utilities
- **Key Features**: Human-readable duration and file size formatting

#### `utils/security_utils.py`
- **Function**: Security-related utilities
- **Key Features**: Secure temporary files, log sanitization, secret detection

## 🛠️ Development Guide

### Setting Up Development Environment

1. **Clone and Setup**:
   ```bash
   git clone https://github.com/iggypopi/ActChain.git
   cd ActChain
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   pip install -e ".[dev,ai,pdf]"
   ```

2. **Environment Variables**:
   ```bash
   export GITHUB_TOKEN="your_github_token_here"
   export ANTHROPIC_API_KEY="..."     # Optional: only for --ai
   export ACTCHAIN_LOG_LEVEL="DEBUG"  # Optional: for development
   ```

### Code Quality Standards

- **Type Hints**: All functions must have comprehensive type hints
- **Docstrings**: All public functions must have detailed docstrings
- **Error Handling**: Use custom exception classes for different error types
- **Logging**: Use appropriate log levels; secrets are centrally redacted by
  `RedactingFilter`, but never log tokens or raw repository content anyway
- **Testing**: Write tests for new functionality (`tests/`, run with `pytest`)

### Adding New Features

#### Adding a New Scanner

1. **Create Scanner Class** (`actchain/scanners/new_scanner.py`):
   ```python
   from .base import BaseScanner
   
   class NewScanner(BaseScanner):
       def __init__(self, min_severity: str = "low"):
           super().__init__(min_severity)
           self.scanner_name = "New Scanner"
       
       def scan_workflow(self, content: str, path: str) -> Dict[str, Any]:
           # Implementation here
           pass
       
       def scan_action(self, action_data: Dict[str, Any]) -> Dict[str, Any]:
           # Implementation here
           pass
   ```

2. **Register in Factory** (`actchain/scanners/factory.py`):
   ```python
   from .new_scanner import NewScanner

   # Add to create_scanner method
   elif scanner_type == "newscanner":
       return NewScanner(min_severity)
   ```

3. **Update Constants** (`actchain/constants.py`):
   ```python
   SCANNER_TYPES = ['zizmor', 'opengrep', 'newscanner', 'all']
   ```

4. **Security invariants**: resolve the scanner binary with
   `SystemUtils.resolve_command`, never by bare name; raise `ScannerError`
   on execution failure (never return an empty, clean-looking result); and
   report locations against the original path, not temp files.

#### Adding a New Report Format

1. **Create Converter** (`actchain/reports/new_format_converter.py`):
   ```python
   def convert_json_to_new_format(json_path: str) -> Optional[str]:
       # Implementation here
       pass
   ```

2. **Integrate in the ReportStage** (`actchain/pipeline/stages.py`): convert
   the consolidated JSON after it is written, guarded by a config flag — the
   `pdf` handling there is the template:
   ```python
   if context.config.get('new_format'):
       context.report_paths['new_format'] = convert_json_to_new_format(consolidated)
   ```

#### Adding a Pipeline Stage

1. **Subclass `Stage`** (`actchain/pipeline/base.py`): set `name`, implement
   `run(context, emit)`, and override `enabled(context)` for opt-in stages.
   Set `critical = True` only if the pipeline cannot continue without it.
2. **Emit, don't print**: stages are console-free — report progress through
   typed events (`ItemProgress`, `Notice`); the CLI layer renders and escapes
   them.
3. **Isolate per-item failures**: record them with `context.add_error(...)`
   and raise `StageError` only when the whole stage cannot run.
4. **Register the stage** in `ActChainDisplay._build_stages`
   (`actchain/cli/display.py`) at the right point in the order.
5. **Mind the policy gate**: errors recorded under the `discovery` or
   `scan:*` stage names count as coverage gaps and fail the pinning gate.
   New stages must never swallow failures silently, and must never add a way
   for the gate to pass that it would otherwise fail (it is monotonic and
   fail-closed by design).

### Testing Strategy

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete scanning workflows
- **Security Tests**: Verify secure handling of sensitive data

### Performance Considerations

- **Caching**: Implement caching for expensive operations (GitHub API calls)
- **Concurrency**: Consider async operations for I/O-bound tasks
- **Memory Management**: Handle large dependency trees efficiently
- **Rate Limiting**: Respect GitHub API rate limits

## ⚙️ Configuration and Settings

### Environment Variables

- `GITHUB_TOKEN`: Required for GitHub API access (preferred over `--token`);
  when neither is set, the GitHub CLI token (`gh auth token`) is tried
- `ANTHROPIC_API_KEY`: Required for `--ai`; read by the Anthropic SDK from the
  environment only (never a CLI flag) and redacted from log output
- `ACTCHAIN_LOG_LEVEL`: Optional logging level (DEBUG, INFO, WARNING, ERROR)
- `ACTCHAIN_OUTPUT_DIR`: Optional default output directory (overridden by `--output-dir`)

### Configuration Files

ActChain currently uses command-line arguments for configuration. Future versions might support:
- `~/.actchain/config.yaml`: User-level configuration
- `.actchain.yaml`: Project-level configuration

### Default Settings

```python
# From actchain/constants.py
DEFAULT_MAX_DEPTH = 5          # Maximum dependency depth
DEFAULT_MIN_SEVERITY = 'low'   # Minimum severity to report
DEFAULT_OUTPUT_DIR = './actchain_reports'  # Default output location
SCANNER_TIMEOUT = 300          # Scanner timeout in seconds

# Safety limits for untrusted content
MAX_TOTAL_ACTIONS = 250        # Cap on distinct actions resolved per scan
MAX_DOC_DEPENDENCIES = 10      # Cap on README-derived refs (--deep-scan)
MAX_TRAVERSAL_DEPTH = 50       # Cap on YAML nesting depth walked
MAX_TRAVERSAL_NODES = 10000    # Cap on YAML nodes walked

# AI analysis (--ai)
AI_DEFAULT_MODEL = 'claude-opus-5-5'
AI_MAX_ACTIONS_AUDITED = 30    # Actions sent to the audit agent per scan
AI_MAX_CALLS_PER_SCAN = 12     # Hard cap on Anthropic API requests per scan

# Pinning policy gate
PR_GATE_SEVERITY_DEFAULT = 'high'
```

## 🔧 Troubleshooting

### Common Issues

#### 1. "Workflow must have an 'on' trigger"
**Cause**: File is not a complete GitHub Actions workflow
**Solution**: Verify the file has `on:` and `jobs:` sections, might be a template or composite action

#### 2. "Scanner not found"
**Cause**: Scanner dependencies not installed
**Solution**: Install the scanner manually (`pip install zizmor` / `pip install semgrep`,
or download OpenGrep from its releases page), or run `actchain setup --install-all`

#### 3. "Rate limit exceeded"
**Cause**: Too many GitHub API requests
**Solution**: Wait for rate limit reset or use authenticated token with higher limits

#### 4. "Permission denied"
**Cause**: Invalid or insufficient GitHub token permissions
**Solution**: Ensure token has `repo` scope and repository access (for
`--create-pr` it also needs `contents:write` and `pull-requests:write`)

#### 5. "AI analysis unavailable"
**Cause**: `--ai` without the optional dependency or the API key
**Solution**: `pip install "actchain[ai]"` and set `ANTHROPIC_API_KEY`

### Debug Mode

Enable debug mode for detailed troubleshooting:
```bash
actchain scan --repo owner/repo --debug
```

This provides:
- Detailed logging to file
- Step-by-step execution traces
- API request/response information
- Error stack traces

### Log Files

- **Console Logs**: Real-time progress and errors
- **Debug Logs**: `{output_dir}/actchain_debug.log` (when --debug is used)
- **Scanner Logs**: Individual scanner outputs in scan directories

## 🚀 Extension Guide

### Architecture Principles for Extensions

1. **Single Responsibility**: Each module should have one clear purpose
2. **Open/Closed Principle**: Open for extension, closed for modification
3. **Dependency Injection**: Pass dependencies rather than creating them
4. **Interface Segregation**: Use specific interfaces rather than large ones
5. **Composition over Inheritance**: Prefer composition for flexibility

### Extension Points

#### 1. New Scanner Types
- Implement `BaseScanner` interface
- Add to factory pattern
- Update constants and CLI options

#### 2. New Report Formats
- Create converter functions
- Integrate with report manager
- Add CLI options for new formats

#### 3. New Data Sources
- Extend GitHub client or create new clients
- Implement standard data interfaces
- Add authentication mechanisms

#### 4. New Analysis Types
- Create analysis modules in core/
- Integrate with action resolver
- Add configuration options

### Best Practices for Extensions

- **Error Handling**: Use specific exception types
- **Logging**: Use appropriate log levels and modules
- **Configuration**: Use constants file for settings
- **Documentation**: Document all new functionality
- **Testing**: Write comprehensive tests
- **Backward Compatibility**: Maintain existing interfaces

### Future Enhancement Ideas

1. **Additional Scanners**: CodeQL, Snyk, custom rules
2. **More Report Formats**: SARIF, XML
3. **Native Lockfile Mode**: `gh actions-lock` integration for the pinning PR (v0.3)
4. **Real-time Monitoring**: Webhook-based scanning
5. **IDE Integrations**: VS Code extension, GitHub App
6. **Database Storage**: Persistent storage for scan history
7. **API Interface**: REST API for programmatic access
8. **Custom Rules**: User-defined security rules
9. **Team Features**: Multi-user environments, role-based access

---

## 📝 Quick Reference

### Key Files to Remember

- **Entry Point**: `actchain/cli/main.py`
- **Scan Orchestration**: `actchain/cli/display.py` (builds and runs the pipeline)
- **Pipeline Stages**: `actchain/pipeline/stages.py`
- **Configuration**: `actchain/constants.py`
- **GitHub API**: `actchain/core/github_client.py`
- **Scanning**: `actchain/scanners/factory.py`
- **Reports**: `actchain/reports/manager.py`

### Common Development Tasks

- **Add Scanner**: Modify `scanners/` directory
- **Add Pipeline Stage**: Modify `pipeline/stages.py` + `cli/display.py`
- **Change CLI**: Modify `cli/commands.py`
- **Update Constants**: Edit `constants.py`
- **Fix Bug**: Check relevant module in organized structure
- **Add Tests**: Create in `tests/` directory

### Important Concepts

- **Dependency Tree**: Hierarchical structure of action dependencies
- **Supply Chain**: Complete set of actions and their relationships
- **Composite Actions**: Actions that contain other actions
- **Security Findings**: Issues discovered by scanners (and, with `--ai`, the AI audit)
- **Consolidated Report**: Combined results from all scanners
- **Policy Gate**: Monotonic, fail-closed check deciding whether the pinning PR opens

---

*This documentation should serve as your complete reference guide for understanding, maintaining, and extending the ActChain project. Keep it updated as the project evolves!*