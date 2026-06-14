"""BLESCOPE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json as _json
from blescope.core import analyze_capture as _analyze_capture, load_capture as _load_capture


def scan(text: str) -> dict:
    """Parse *text* as a capture and return the analysis result dict."""
    capture = _load_capture(text)
    return _analyze_capture(capture).to_dict()


def to_json(result: dict) -> str:
    """Serialize an analysis result dict to a JSON string."""
    return _json.dumps(result, indent=2)

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
        """Sniff and decode BLE GATT traffic, fingerprint device profiles,
        and assert on insecure pairing/characteristics in CI. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
