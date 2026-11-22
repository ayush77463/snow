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

    Registers all 24 static MCP tools and connects them to the IPC bridge.
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

    # Register all static tools
    register_all_tools(server, mcp_bridge)

    @server.resource("snow://mesh/topology")
    async def mesh_topology_resource() -> str:
        import json
        from snow.security.context import ExecutionContext, ExecutionPrincipal
        ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="fastmcp_resource")
        result = await mcp_bridge.snow_mesh_topology(ctx=ctx)
        return json.dumps(result, indent=2)

    logger.debug("SNOW FastMCP server created and static tools/resources registered.")
    return server
