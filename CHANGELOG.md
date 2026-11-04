# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-04

### Added
- Staged scan pipeline (`actchain.pipeline`): discovery → one stage per
  scanner → optional AI triage/audit → policy gate → reports → pinning PR;
  console-free, with typed progress events rendered by the CLI
- Opt-in AI analysis (`--ai`, `--ai-model`; `ai` extra, `ANTHROPIC_API_KEY`):
  advisory triage of tool findings plus a malicious-behavior audit of action
  definitions that can add findings
- Malicious-finding classification with a red terminal alert, report banners
  and exit code 2
- Pinning pull requests (`--create-pr`, `--pr-gate-severity`, `--dry-run`,
  `--yes`) behind a monotonic, fail-closed policy gate; pins use the commit
  SHAs recorded at scan time, and changed files are re-verified before commit
- PDF report (`--pdf`; `pdf` extra) with an executive summary layout
- `--full` shortcut (`--scan-all-workflows --pdf`), `--repo` inference from
  the `origin` remote, and `gh auth token` fallback for the GitHub token
- Consolidated report v1.1: `finding_id`, `ai_triage`, `malicious`, `gate`
  (with pin plan), `ai` and `pr_url` fields
- `pinning_preview.diff` written alongside the reports whenever `--create-pr`
  ran
- Centralized action-ref grammar (`actchain.core.refs`); resolved action data
  records the commit SHA the scanned content was fetched at

### Changed
- Scan orchestration moved from the CLI display layer into the pipeline; the
  CLI now renders typed pipeline events
- Exit codes are a documented contract: 0 success (including a gate-blocked
  PR), 1 operational error, 2 malicious findings
- HTML and terminal output gained malicious-behavior, policy-gate and AI
  sections
- Packaging moved from `setup.py` to `pyproject.toml`, with `ai`/`pdf`/`full`
  extras and a `py.typed` marker

## [0.1.0] - 2026-11-04

Initial version (published together with 0.2.0 in the first public release).

### Added
- Recursive GitHub Actions workflow and action dependency scanning
- Zizmor and OpenGrep scanner integrations
- JSON and HTML reports, dependency trees and optional Graphviz graphs
- `scan`, `info`, `setup`, `test-scanner` and `list-workflows` CLI commands
- Security hardening for untrusted repository content: bounded YAML
  traversal, capped dependency resolution, Rich markup/control-character
  escaping, DOT escaping, central log redaction of token-shaped strings
- Test suite, CI (lint, tests, dependency audit, build), CodeQL and
  Dependabot configuration
