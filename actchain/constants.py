# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Constants and configuration for ActChain.
"""

# Scanning configuration
DEFAULT_MAX_DEPTH = 5
DEFAULT_MIN_SEVERITY = 'low'
DEFAULT_OUTPUT_DIR = './actchain_reports'

# Severity levels (higher number = more severe)
SEVERITY_LEVELS = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
    'unknown': 0
}

# Heuristic companion actions for popular actions. These are NOT declared
# dependencies: they are actions commonly used together with the key action.
# They are only consulted when --deep-scan is enabled, and findings derived
# from them should be read as "commonly co-used", not as supply-chain edges.
KNOWN_ACTION_DEPENDENCIES = {
    "docker/build-push-action": [
        "docker/setup-buildx-action",
        "docker/login-action",
        "docker/metadata-action"
    ],
    "actions/cache": [
        "actions/cache/save",
        "actions/cache/restore"
    ],
    "github/super-linter": [
        "actions/checkout"
    ],
    "cycjimmy/semantic-release-action": [
        "actions/checkout",
        "actions/setup-node"
    ],
    "actions/dependency-review-action": [
        "actions/checkout"
    ],
}

# File patterns
WORKFLOW_FILE_EXTENSIONS = ['.yml', '.yaml']
TEMP_FILE_PREFIX = 'actchain_'

# Regular expressions
ACTION_REF_PATTERN = r'([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)@([a-zA-Z0-9_.-]+)'
USES_PATTERN = r'uses:\s+([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)@([a-zA-Z0-9_.-]+)'
UNPINNED_ACTION_PATTERN = r'uses:\s+([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)@v\d+'

# Scanner configuration
SCANNER_TYPES = ['zizmor', 'opengrep', 'all']
SCANNER_TIMEOUT = 300  # 5 minutes

# Safety limits when traversing untrusted content
MAX_TOTAL_ACTIONS = 250        # cap on distinct actions resolved per scan
MAX_DOC_DEPENDENCIES = 10      # cap on README-derived refs per action (--deep-scan)
MAX_TRAVERSAL_DEPTH = 50       # cap on nesting depth when walking parsed YAML
MAX_TRAVERSAL_NODES = 10000    # cap on nodes visited when walking parsed YAML

# Report configuration
REPORT_VERSION = '1.1'
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB

# ---------------------------------------------------------------------------
# AI analysis (optional, --ai)
# ---------------------------------------------------------------------------
AI_DEFAULT_MODEL = 'claude-opus-5-5'
AI_MODEL_PATTERN = r'^claude-[a-z0-9.-]+$'
AI_MAX_ACTIONS_AUDITED = 30        # per-scan cap on actions sent to the audit agent
AI_MAX_FILES_PER_AUDIT_CALL = 8    # per-request caps keep cost and context bounded
AI_MAX_BYTES_PER_AUDIT_CALL = 64 * 1024
AI_MAX_FINDINGS_PER_TRIAGE_CALL = 80
AI_MAX_BYTES_PER_TRIAGE_CALL = 48 * 1024
AI_MAX_CALLS_PER_SCAN = 12         # hard cap on API requests per scan
AI_FILE_HEAD_BYTES = 8 * 1024      # head+tail truncation of large action files
AI_FILE_TAIL_BYTES = 4 * 1024
# Actions under these namespaces are heavily reviewed; the audit budget is
# spent on less-known actions first (they are still scanned by the tools).
AI_SKIP_NAMESPACES = ('actions/', 'github/')

# ---------------------------------------------------------------------------
# Pinning PR policy gate
# ---------------------------------------------------------------------------
PR_GATE_SEVERITY_DEFAULT = 'high'
# Findings these rules produce are remediated BY pinning, so they do not
# block the pinning PR (everything else does).
PIN_REMEDIATED_RULE_IDS = frozenset({
    'unpinned-uses',
    'unpinned-github-action',
})
# Scanner rules that indicate active compromise rather than misconfiguration.
# AI-audit findings flagged malicious are tagged independently of this list.
MALICIOUS_RULE_IDS = frozenset()

# Exit codes (documented in README)
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_MALICIOUS = 2
