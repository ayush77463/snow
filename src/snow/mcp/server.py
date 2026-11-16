"""FastMCP server initialization and tool registration for SNOW.

Exposes the standardized MCP interface to AI hosts via stdio transport.
Guarantees strict stdout isolation: stdout is exclusively reserved for MCP
protocol messages; all application logging routes to sys.stderr.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

from mcp.server.fastmcp import FastMCP
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.tools import register_all_tools

logger = logging.getLogger(__name__)


def create_snow_mcp_server(
    bridge: Optional[SnowMcpBridge] = None,
    server_name: str = "SNOW",
) -> FastMCP:
    """Instantiate and configure the official SNOW FastMCP server.

    Registers all 16 static MCP tools and connects them to the IPC bridge.
    Does not start any network listeners or duplicate core services.
    """
    mcp_bridge = bridge or SnowMcpBridge()
    server = FastMCP(
        name=server_name,
        instructions=(
            "SNOW is a headless cross-device AI capability bridge connecting Windows "
            "and Android. Use these tools to query system status and execute permitted operations."
        ),
    )

    # Attach bridge reference
    server.bridge = mcp_bridge  # type: ignore[attr-defined]

    # Register all 16 static tools
    register_all_tools(server, mcp_bridge)

    logger.debug("SNOW FastMCP server created and 16 static tools registered.")
    return server
