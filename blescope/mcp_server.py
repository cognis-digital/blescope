"""BLESCOPE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from blescope.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-blescope[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-blescope[mcp]'")
        return 1
    app = FastMCP("blescope")

    @app.tool()
    def blescope_scan(target: str) -> str:
        """Sniff and decode BLE GATT traffic, fingerprint device profiles, and assert on insecure pairing/characteristics in CI against a capture.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
