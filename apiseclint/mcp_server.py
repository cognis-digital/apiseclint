"""APISECLINT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import sys

from apiseclint.core import lint_spec, load_spec, render_json


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-apiseclint[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "error: MCP extra not installed. "
            "Run: pip install 'cognis-apiseclint[mcp]'",
            file=sys.stderr,
        )
        return 1

    app = FastMCP("apiseclint")

    @app.tool()
    def apiseclint_scan(spec_text: str) -> str:
        """Lint an OpenAPI spec (JSON or YAML text) for security gaps.

        Returns JSON findings including auth, rate limiting, and data
        exposure issues.
        """
        if not spec_text or not spec_text.strip():
            return render_json(
                lint_spec(
                    {"openapi": "?", "info": {"title": "empty", "version": "?"},
                     "paths": {}},
                    source="<empty>",
                )
            )
        try:
            spec = load_spec(spec_text)
        except (ValueError, TypeError) as exc:
            import json as _json
            return _json.dumps({"tool": "apiseclint", "error": str(exc),
                                "findings": []})
        return render_json(lint_spec(spec, source="<mcp>"))

    app.run()
    return 0
