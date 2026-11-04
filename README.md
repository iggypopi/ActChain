# ActChain - GitHub Actions Security Scanner

[![CI](https://github.com/iggypopi/ActChain/actions/workflows/ci.yml/badge.svg)](https://github.com/iggypopi/ActChain/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

ActChain is a security analysis tool for GitHub Actions workflows and their dependencies. It provides deep supply chain scanning capabilities to identify security vulnerabilities, misconfigurations, and compliance issues in your CI/CD pipelines.

## 🚀 Features

### Supply Chain Scanning
- **Deep Dependency Analysis**: Recursively analyze actions and their dependencies to any specified depth
- **Staged Pipeline**: discovery → one stage per scanner → optional AI analysis → policy gate → reports → pinning PR, with per-item fault isolation
- **Multi-Scanner Support**: Integrated support for Zizmor and OpenGrep/Semgrep scanners
- **Comprehensive Coverage**: Scan composite actions, reusable workflows, and Docker actions
- **Dependency Visualization**: Generate dependency trees and Graphviz graphs of your supply chain

### Security Analysis
- **Vulnerability Detection**: Identify security issues throughout the dependency chain
- **Configuration Assessment**: Detect misconfigurations and excessive permissions
- **Best Practice Validation**: Ensure adherence to GitHub Actions security best practices
- **Severity-Based Filtering**: Focus on issues that matter most with configurable severity levels

### AI Analysis (Opt-In)
- **Finding triage**: a Claude agent reviews every tool finding and annotates it as confirmed, likely false positive, or needs review — annotations never remove findings
- **Malicious-behavior audit**: a second agent reads the action definitions in the chain and can add findings, including a malicious flag
- **Strictly opt-in**: nothing is sent to the Anthropic API unless you pass `--ai` (see "AI Analysis & Privacy" below)

### Pinning Pull Requests
- **One command**: `--create-pr` opens a pull request pinning every scanned action to the exact commit SHA whose content was scanned
- **Policy gate**: the PR opens only when the scan is clean — the gate is monotonic and fail-closed (see "Pinning Pull Requests" below)
- **Preview first**: `--dry-run` computes the full pin plan and gate verdict without writing anything

### Reporting
- **Multi-Format Reports**: JSON for automation, static HTML for humans, optional executive PDF (`--pdf`)
- **Consolidated Analysis**: Single report combining findings from scanners and AI, with the gate verdict
- **Dependency Graphs**: Visual representation of your action dependencies (requires Graphviz)

### Hardened Against Malicious Repos
ActChain treats everything it scans as untrusted input: traversal of parsed
YAML is bounded, dependency resolution is capped, terminal/HTML/DOT output is
escaped, scan failures surface as errors instead of clean results, and log
output is filtered for token-shaped strings.

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- Git
- A GitHub personal access token
- Optional: [Graphviz](https://graphviz.org/download/) for dependency graphs,
  [OpenGrep](https://github.com/opengrep/opengrep/releases) for the second scanner

### Install from source
```bash
pip install git+https://github.com/iggypopi/ActChain.git
```

or from a clone:

```bash
git clone https://github.com/iggypopi/ActChain.git
cd ActChain
pip install .
```

The `zizmor` scanner is installed automatically as a Python dependency.
OpenGrep must be installed separately (see `actchain setup`).

### Optional extras

```bash
pip install "actchain[ai]"    # AI analysis (--ai) via the Anthropic API
pip install "actchain[pdf]"   # PDF reports (--pdf)
pip install "actchain[full]"  # both
```

## 🔧 Quick Start

### 1. Set up your GitHub token
```bash
export GITHUB_TOKEN="your_github_token_here"
```

> Prefer the environment variable over `--token`: command-line arguments can
> end up in your shell history and are visible in the process list. When
> neither is set, ActChain falls back to the GitHub CLI token
> (`gh auth token`) and says so.

### 2. Basic workflow scan
```bash
actchain scan --repo owner/repository
```

Inside a clone of the repository you can omit `--repo`; it is inferred from
the `origin` git remote (github.com remotes only).

### 3. Full scan with a pinning PR
```bash
# Preview first: all workflows + PDF report, pin plan and gate verdict, no writes
actchain scan --repo owner/repository --full --create-pr --dry-run

# Then open the PR (add --ai when ANTHROPIC_API_KEY is set)
actchain scan --repo owner/repository --full --create-pr
```

### 4. Advanced scanning with custom options
```bash
actchain scan \
  --repo owner/repository \
  --scanner all \
  --min-severity medium \
  --max-depth 10 \
  --dependency-graph \
  --output-dir ./reports
```

## 📋 Usage

### Scan Command
```bash
actchain scan [OPTIONS]
```

**Options:**
- `--repo, -r`: GitHub repository in "owner/repo" format. When omitted,
  inferred from the current directory's `origin` git remote (github.com only)
- `--token, -t`: GitHub personal access token (prefer the `GITHUB_TOKEN` env
  var). When neither is set, the GitHub CLI token (`gh auth token`) is used
  if available
- `--workflow-path`: Path to specific workflow file to scan
- `--scan-all-workflows`: Scan all workflows without interactive selection
- `--output-dir, -o`: Directory to save reports (default: `./actchain_reports`, env: `ACTCHAIN_OUTPUT_DIR`)
- `--max-depth`: Maximum depth for dependency scanning (default: 5)
- `--scanner`: Scanner to use: `zizmor`, `opengrep`, or `all` (default: `all`)
- `--min-severity`: Minimum severity level: `critical`, `high`, `medium`, `low` (default: `low`)
- `--verbose, -v`: Enable verbose output
- `--debug, -d`: Enable debug mode with logging to a file
- `--deep-scan`: Also follow heuristic dependencies (commonly co-used actions
  and references found in action READMEs). These are guesses, not declared
  dependencies, and may fetch additional repositories.
- `--dependency-graph`: Generate dependency graph visualization
- `--ai`: Enable AI analysis (finding triage + malicious-behavior audit).
  Opt-in: sends scanned content and findings to the Anthropic API; requires
  `ANTHROPIC_API_KEY` and the `ai` extra
- `--ai-model`: Claude model used for AI analysis (default: `claude-opus-5-5`)
- `--pdf`: Also generate a PDF report (requires the `pdf` extra)
- `--create-pr`: After a clean scan, open a pull request pinning the scanned
  actions to their verified commit SHAs. Implies `--scan-all-workflows`,
  requires `--min-severity low` (the default) and a token with
  `contents:write` and `pull-requests:write` permissions
- `--pr-gate-severity`: Block the pinning PR when any finding at or above this
  severity exists (default: `high`). The gate also fails closed on scan errors
  or incomplete coverage; AI triage can never unblock it
- `--dry-run`: With `--create-pr`: compute and preview the pin plan and gate
  verdict without pushing anything
- `--yes`: Skip the interactive confirmation before opening the PR
- `--full`: Shortcut for `--scan-all-workflows --pdf`

### Other Commands
```bash
actchain info                           # Show environment and dependency status
actchain setup [--install-all]          # Check setup; optionally install scanner packages
actchain test-scanner [zizmor|opengrep|all]  # Verify scanners work (default: all)
actchain list-workflows --repo owner/repo    # List workflows in a repository
```

### Configuration Examples

```bash
# Comprehensive security audit
actchain scan --repo myorg/myrepo --scanner all --min-severity high --max-depth 15 --dependency-graph --verbose

# Focused critical issues scan
actchain scan --repo myorg/myrepo --min-severity critical --scanner zizmor

# Specific workflow analysis
actchain scan --repo myorg/myrepo --workflow-path .github/workflows/ci.yml --max-depth 8

# Everything: all workflows, PDF, AI analysis, pinning PR
actchain scan --repo myorg/myrepo --full --ai --create-pr
```

## 📌 Pinning Pull Requests

`actchain scan --create-pr` rewrites every mutable `uses:` reference
(`owner/repo@v4`, branch refs, short SHAs) to the exact commit SHA whose
content this scan fetched and verified — refs are never re-resolved — and
opens a single pull request with the changes.

The PR only opens when the **policy gate** passes:

- Any finding at or above `--pr-gate-severity` (default `high`) blocks it;
  malicious-flagged findings always block, regardless of severity.
- The gate is **fail-closed**: scan errors, workflows that failed to parse,
  unresolved action references, dependency-discovery cutoffs (`--max-depth`
  or the action cap) and failed or partial AI coverage (when `--ai` ran) all
  block it.
- The gate is **monotonic**: AI triage verdicts are advisory and can never
  unblock it; the AI audit can only add blockers.
- Unpinned-action findings do not block — pinning is their fix.

Safety properties:

- In an interactive terminal you are shown the pin table and asked to confirm
  before anything is pushed (`--yes` skips the prompt).
- `--dry-run` computes the plan, the gate verdict and `pinning_preview.diff`
  with zero writes.
- The PR is one commit on a fresh `actchain/pin-actions-<timestamp>` branch,
  never force-pushed, and creation aborts if any workflow file changed since
  the scan.
- Reusable-workflow references are listed in the PR as not pinned (pin them
  manually); `docker://` images and local `./` actions are never rewritten.
- A gate-blocked PR is a normal policy outcome: the scan still exits `0` and
  every report states why no PR was opened.

The PR body also recommends GitHub's native workflow dependency lockfile
(`gh actions-lock`) as a complementary hardening step.

## 🤖 AI Analysis & Privacy

AI analysis is **strictly opt-in** (`--ai`) and needs
`pip install "actchain[ai]"` plus an `ANTHROPIC_API_KEY` environment variable
(never a CLI flag). Two agents run against the scan:

1. **Triage** annotates every tool finding with an advisory verdict —
   `confirmed`, `likely_false_positive` or `needs_review` — plus a short
   rationale. Verdicts never remove findings and never loosen the pinning gate.
2. **Audit** reads the action definition files themselves (up to 30 per scan,
   deepest and least-pinned first; heavily reviewed `actions/` and `github/`
   namespaces are skipped) and hunts for malicious behavior. It can only *add*
   findings, labeled `AI Audit (Claude)`, including a `malicious` flag.

What leaves your machine: the tool findings (sanitized, whitelisted fields)
and up to 30 action definition files from the scanned repository, sent to the
Anthropic API. A runtime notice states exactly what is sent before the first
call. Your `GITHUB_TOKEN` is never included, and usage is capped at 12 API
requests per scan.

Invariant: **AI output can only make the pinning gate stricter, never
looser.** AI failures degrade gracefully — the scan completes without AI and
the report says so — except under `--create-pr`, where incomplete AI coverage
fails the gate (fail-closed).

## 🚦 Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Scan completed — including a gate-blocked pinning PR, which is a policy outcome, not an error |
| `1`  | Operational error: a pipeline stage failed, the consolidated report is missing, or the requested PR could not be created |
| `2`  | Malicious finding(s) detected (takes precedence over `1`) |

Malicious classification currently comes from the AI audit (`--ai`); the
`MALICIOUS_RULE_IDS` constant is an empty extension point for scanner rules
that should carry the same weight.

## 🔍 Scanning Capabilities

### Dependency Types Analyzed
- **Standard GitHub Actions**: Regular published actions from GitHub Marketplace
- **Composite Actions**: Actions that combine multiple steps or other actions
- **Reusable Workflows**: GitHub workflows called by other workflows
- **Local Actions**: Actions defined within the same repository
- **Docker Actions**: Actions that run within Docker containers

### Security Risks Detected
- **Unpinned Dependencies**: Actions not pinned to specific commit hashes
- **Excessive Permissions**: Actions requesting more permissions than necessary
- **Command/Code Injection**: Potential injection vulnerabilities in workflows
- **Vulnerable Inputs**: Unsafe handling of inputs or environment variables
- **Transitive Vulnerabilities**: Security issues in nested dependencies
- **Configuration Issues**: Misconfigurations in workflow and action definitions

### Scanner Integration

#### Zizmor Scanner
- Specialized GitHub Actions security scanner
- Built-in rules for common vulnerabilities
- Installed automatically with ActChain

#### OpenGrep/Semgrep Scanner
- Advanced static analysis capabilities
- Extensive rule sets for security patterns
- Installed separately: download [OpenGrep](https://github.com/opengrep/opengrep/releases),
  or install semgrep (`pip install semgrep` or `actchain setup --install-all`) —
  ActChain uses either binary

## 📊 Report Formats

- **JSON report** (schema v1.1) for automation: every finding carries a stable
  `finding_id` plus, when present, its `ai_triage` annotation and `malicious`
  flag; top-level `gate` (verdict + pin plan), `ai` (model, calls, coverage)
  and `pr_url` fields
- **HTML report** with severity-grouped findings, a malicious-behavior banner,
  the pinning gate verdict with planned pins, and an AI analysis section
- **PDF report** (`--pdf`): a concise executive summary — severity totals,
  scanners, AI status, malicious banner, gate verdict; full detail for
  malicious/critical/high findings, capped lists for the rest
- **Terminal output**: dependency trees, summary tables, a red alert panel for
  malicious findings, and panels for the AI summary, gate verdict and report
  paths
- **Dependency trees** (one text file per scanned workflow), optional
  **Graphviz graphs**, and `pinning_preview.diff` whenever `--create-pr` ran

> Reports contain repository names, file paths and finding excerpts.
> The default output directory is git-ignored; avoid committing reports.

## 🏗️ Project Structure

```
ActChain/
├── pyproject.toml              # Package metadata and dependencies
├── requirements.in             # Abstract dependencies (secure floors)
├── requirements.txt            # Hash-pinned lockfile
├── Documentation.md            # Developer documentation
├── SECURITY.md                 # Vulnerability disclosure policy
├── tests/                      # Test suite
└── actchain/                   # Main package
    ├── constants.py            # Constants and safety limits
    ├── logging_config.py       # Logging with central secret redaction
    ├── ai/                     # Opt-in AI triage & audit (Anthropic API)
    ├── cli/                    # Command-line interface
    ├── core/                   # GitHub client, workflow parsing, resolution
    ├── pipeline/               # Staged scan pipeline (stages, events, context)
    ├── pinning/                # Pin-plan builder and pinning PR creation
    ├── scanners/               # Zizmor/OpenGrep integrations
    ├── reports/                # JSON/HTML/PDF/graph report generation
    └── utils/                  # File, path, system and security utilities
```

## 🛡️ Security

- See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy and
  a description of how ActChain handles your token and data (spoiler: no
  telemetry, everything stays local).
- ActChain's own CI pins all GitHub Actions to commit SHAs — the same
  practice `--create-pr` automates.

### Action Security Best Practices
- **Pin to Commit Hashes**: Always use specific commit hashes instead of version tags
- **Minimal Permissions**: Use fine-grained permissions instead of `write-all`
- **Input Validation**: Validate and sanitize all action inputs
- **Secret Management**: Properly handle secrets and tokens
- **Least Privilege**: Apply the principle of least privilege to all permissions

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup, quality checks, and security invariants to maintain.

## 📄 License

ActChain is licensed under the MIT License — see [LICENSE](LICENSE).

### Third-Party Dependencies

- **[zizmor](https://github.com/zizmorcore/zizmor)** — MIT License — GitHub Actions security scanner by William Woodruff
- **[OpenGrep](https://github.com/opengrep/opengrep)** — LGPL-2.1 License — static analysis tool (fork of the Semgrep community engine)
- **[PyGithub](https://github.com/PyGithub/PyGithub)** — LGPL-3.0 License — GitHub API library
- **[Rich](https://github.com/Textualize/rich)** — MIT License — terminal formatting library
- **[Click](https://github.com/pallets/click)** — BSD-3-Clause License — command line interface
- **[PyYAML](https://github.com/yaml/pyyaml)** — MIT License — YAML parser
- **[fpdf2](https://github.com/py-pdf/fpdf2)** — LGPL-3.0 License — PDF generation (optional `pdf` extra)
- **[Anthropic SDK](https://github.com/anthropics/anthropic-sdk-python)** — MIT License — Claude API client (optional `ai` extra)

See the [NOTICE](NOTICE) file for complete third-party license information.

### Disclaimer

ActChain is an independent open source project and is not affiliated with or
endorsed by GitHub, Inc., the zizmor project, Semgrep, Inc., Anthropic, PBC,
or any other third-party organizations whose tools or services may be
integrated with or referenced by ActChain. GitHub Actions is a trademark of
GitHub, Inc.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/iggypopi/ActChain/issues)
- **Security**: report privately via [SECURITY.md](SECURITY.md)
- **Documentation**: [Documentation.md](Documentation.md)

## 🚧 Roadmap

- [ ] Native `actions.lock` generation (`gh actions-lock` integration) — v0.3
- [ ] SARIF output format
- [ ] JSON output from scanners instead of text parsing
- [ ] Support for GitLab CI/CD pipelines
- [ ] Enhanced rule customization
- [ ] Custom scanner plugin system

## Author

**[Igor Stepansky](https://github.com/iggypopi)**

---

**Made with ❤️ for the DevSecOps community**

*ActChain helps secure your software supply chain by providing comprehensive visibility into GitHub Actions workflows and their dependencies.*
