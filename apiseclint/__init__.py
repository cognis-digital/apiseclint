"""APISECLINT — Lint OpenAPI specs for security gaps (authz, rate-limit, data exposure)."""
from apiseclint.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
