"""Executable entry point for the SNOW MCP server subprocess.

Launched by AI hosts (e.g. Antigravity, Claude Desktop, MCP Inspector) via:
    python -m snow.mcp

STRICT STDOUT ISOLATION MANDATE:
stdout is strictly reserved for MCP JSON-RPC protocol frames.
All application diagnostics and logs are exclusively routed to sys.stderr.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from snow.mcp.server import create_snow_mcp_server


def setup_mcp_logging() -> None:
    """Configure standard logging to write strictly and exclusively to sys.stderr."""
    # Ensure stdout is in binary/clean mode with zero unbuffered logging pollution
    log_level_str = os.environ.get("SNOW_LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    # Remove all existing root handlers to prevent stdout leaks
    root_logger = logging.getLogger()
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(log_level)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)


async def _async_main() -> None:
    """Asynchronous entry point executing the FastMCP stdio server loop."""
    logger = logging.getLogger("snow.mcp")
    logger.info("Initializing SNOW MCP stdio server...")

    server = create_snow_mcp_server()

    try:
        await server.run_stdio_async()
    except (asyncio.CancelledError, KeyboardInterrupt):
        logger.info("SNOW MCP stdio server shutting down gracefully.")
    except Exception as exc:
        logger.critical("Unhandled fatal exception in SNOW MCP server: %s", exc, exc_info=True)
        sys.exit(1)


def main() -> None:
    """Subprocess main entry point."""
    setup_mcp_logging()
    try:
        asyncio.run(_async_main())
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    main()
