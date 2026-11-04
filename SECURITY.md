# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |

## Reporting a Vulnerability

Please **do not** open a public issue for security vulnerabilities.

Instead, use [GitHub private vulnerability reporting](https://github.com/iggypopi/ActChain/security/advisories/new)
to report it privately. You can expect an initial response within 7 days.

Please include:

- A description of the issue and its impact
- Steps to reproduce (a minimal workflow/action file if relevant)
- The ActChain version and scanner versions involved

## Scope notes for researchers

ActChain analyzes **untrusted repository content** (workflow YAML, action
definitions, scanner output). Anything that lets scanned content execute code
on the analyst's machine, exfiltrate the GitHub token, or falsify scan
results/reports is in scope and very welcome.

## Data handling

- ActChain communicates with the GitHub API (via PyGithub/requests) to fetch
  the workflows and actions you ask it to scan. Without `--ai`, it talks to
  nothing else.
- **AI analysis (`--ai`) is strictly opt-in** and sends data to the Anthropic
  API: the tool findings (sanitized, whitelisted fields) and up to 30 action
  definition files from the scanned repository. A runtime notice states what
  is being sent before the first call. Your GitHub token is never included.
- `ANTHROPIC_API_KEY` is read from the environment only (never a CLI flag),
  and log output is filtered for Anthropic-key-shaped strings.
- Your GitHub token is read from `--token` or the `GITHUB_TOKEN` environment
  variable (with `gh auth token` as a fallback), passed to the GitHub client
  (and inherited by scanner subprocesses via the environment); it is never
  written to reports or logs, and log output is additionally filtered for
  token-shaped strings.
- All reports are written locally to the output directory you choose. There
  is no telemetry.
- Reports can contain repository names, file paths and workflow excerpts —
  treat the output directory accordingly and avoid committing it.

## Pinning PR safety

`--create-pr` is the only feature that writes to a scanned repository, and it
is guarded in depth: the policy gate is monotonic and fail-closed (AI output
can only make it stricter; any scan error or coverage gap blocks it); only
commit SHAs recorded when the content was scanned are ever written (refs are
never re-resolved); every changed file is verified byte-for-byte against its
scan-time content before the commit is created (TOCTOU guard); interactive
runs require explicit confirmation before any push; and `--dry-run` previews
the full plan with zero writes. The PR is a single commit on a fresh branch
and is never force-pushed.

## Known dependency advisories

- `pynacl` (transitive, via PyGithub) is flagged by GHSA-mrfv-m5wm-5w6w
  (bundled libsodium point-validation issue). ActChain does not call the
  affected API; the pin will be bumped when a fixed release ships.
