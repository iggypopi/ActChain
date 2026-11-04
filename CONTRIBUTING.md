# Contributing to ActChain

Thanks for your interest in contributing!

## Development setup

```bash
git clone https://github.com/iggypopi/ActChain.git
cd ActChain
python -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e ".[dev,ai,pdf]"
```

## Quality checks

Run these before opening a pull request (CI runs flake8 and pytest; mypy is
currently advisory):

```bash
flake8 actchain/ tests/ --max-line-length=120 --extend-ignore=E203,W503
pytest --cov=actchain
mypy actchain/
```

## Tests

The suite grew substantially in v0.2.0 (291 tests) and runs with plain
`pytest`. Pipeline tests build a `ScanContext` directly and run stages
against it; gate/PR tests reuse the `stub_pinning` fixture in
`tests/test_pipeline.py`, which replaces `actchain.pinning` with a recording
stub so nothing ever touches the network.

## Dependencies

- Abstract dependencies (with minimum-secure floors) live in
  `pyproject.toml` and `requirements.in`.
- `requirements.txt` is a hash-pinned lockfile. Regenerate it with:

  ```bash
  uv pip compile requirements.in -o requirements.txt --generate-hashes --universal --python-version 3.10
  ```

- CI runs `pip-audit` against the lockfile; Dependabot keeps both pip and
  GitHub Actions dependencies current.

## Security

ActChain's input (workflow YAML, action definitions, scanner output) is
untrusted. When touching code that handles it, keep these invariants:

- No `shell=True`; external tools are resolved to absolute paths via
  `SystemUtils.resolve_command` (never invoked by bare name).
- Anything printed to the terminal goes through `display.esc()`
  (Rich markup + control-character escaping).
- Anything written into HTML goes through `html.escape`; anything written
  into DOT goes through `ReportManager._escape_dot_string`.
- Log output is centrally redacted (`RedactingFilter`); never log tokens or
  raw workflow content.
- Traversals of parsed YAML must be bounded (see `MAX_TRAVERSAL_*`).
- The pinning policy gate is monotonic and fail-closed — AI output and new
  code paths may only make it stricter.

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Pull requests

- Create a feature branch, keep changes focused.
- Add tests for new functionality.
- Update documentation (README.md / Documentation.md) as needed.
- By contributing, you agree your contributions are licensed under the MIT
  License.

## Adding a new scanner

1. Create a scanner class in `actchain/scanners/` inheriting `BaseScanner`
2. Implement `scan_workflow` and `scan_action`
3. Register it in `actchain/scanners/factory.py`
4. Add it to `SCANNER_TYPES` in `actchain/constants.py`
5. Add tests and documentation

## Releases

Releases are built with `python -m build`. When publishing to PyPI, use
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) from a
GitHub Actions workflow rather than long-lived API tokens.
