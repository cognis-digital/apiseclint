"""APISECLINT — Lint OpenAPI specs for security gaps.

Defensive analysis tool: scans OpenAPI 2.0/3.x specifications you own for
common API security weaknesses (missing authn/authz, no rate limiting,
sensitive data exposure, weak schemes, etc.). No network access, no attack
capability — pure static analysis of artifacts you provide.
"""
from .core import (
    Finding,
    Severity,
    LintReport,
    lint_spec,
    load_spec,
    render_table,
    render_json,
    render_html,
)

TOOL_NAME = "apiseclint"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "Severity",
    "LintReport",
    "lint_spec",
    "load_spec",
    "render_table",
    "render_json",
    "render_html",
    "TOOL_NAME",
    "TOOL_VERSION",
]
