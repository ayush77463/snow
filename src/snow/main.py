"""Application entry point for SNOW Desktop Core.

CRITICAL ARCHITECTURAL DIRECTIVE (MCP stdio Isolation):
-------------------------------------------------------
The MCP (Model Context Protocol) stdio transport strictly reserves standard
output (`stdout`) exclusively for MCP JSON-RPC protocol frames.

Emitting ordinary text, print() statements, or diagnostic logs to `stdout`
corrupts the JSON-RPC stream and immediately crashes AI host communication.

Therefore:
- Application logging is explicitly configured to output to `sys.stderr`.
- `print()` is prohibited across the desktop core.
- `stdout` remains completely untouched by the application.
"""

import asyncio
import logging
import signal
import sys
from typing import Optional

from snow.core.config import CoreConfig
from snow.core.server import SnowCoreServer


def configure_logging(level_name: str = "INFO") -> None:
    """Configure the root logger to output exclusively to sys.stderr.

    Ensures that stdout remains untouched and reserved for MCP JSON-RPC communication.
    """
    numeric_level = getattr(logging, level_name.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    root_logger.handlers.clear()
    root_logger.addHandler(handler)


async def _async_main() -> int:
    """Asynchronous entry point that manages server lifecycle and shutdown signals."""
    config = CoreConfig.from_env()
    configure_logging(config.log_level)
    logger = logging.getLogger("snow.main")

    server = SnowCoreServer(config)
    loop = asyncio.get_running_loop()

    def _signal_handler(signum: int, frame) -> None:
        try:
            sig_name = signal.Signals(signum).name
        except (ValueError, AttributeError):
            sig_name = str(signum)
        logger.info("Received termination signal (%s); signaling shutdown.", sig_name)

        # Defensive check: ensure event loop is running and active before scheduling callback
        if loop.is_running() and not loop.is_closed():
            loop.call_soon_threadsafe(server.request_shutdown)
        else:
            logger.debug("Event loop is closed or not running; signal dispatch skipped.")

    # Register termination signals (Windows compatible)
    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None), getattr(signal, "SIGBREAK", None)):
        if sig is not None:
            try:
                signal.signal(sig, _signal_handler)
            except (ValueError, AttributeError, OSError):
                pass

    try:
        await server.run()
    except asyncio.CancelledError:
        logger.debug("Core server task received cancellation.")
    except Exception as exc:
        logger.critical("Unhandled exception in core server: %s", exc, exc_info=True)
        return 1
    finally:
        await server.stop()

    return 0


def main() -> int:
    """Main CLI entry point for SNOW Desktop Core."""
    try:
        return asyncio.run(_async_main())
    except KeyboardInterrupt:
        # Handles Ctrl+C in standard Windows interactive console
        logger = logging.getLogger("snow.main")
        logger.info("Received KeyboardInterrupt (Ctrl+C). Core shutdown complete.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
