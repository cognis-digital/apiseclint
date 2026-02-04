"""APISECLINT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from apiseclint.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-apiseclint[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-apiseclint[mcp]'")
        return 1
    app = FastMCP("apiseclint")

    @app.tool()
    def apiseclint_scan(target: str) -> str:
        """Lint OpenAPI specs for security gaps (authz, rate-limit, data exposure). Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
