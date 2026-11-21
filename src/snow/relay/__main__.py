"""Entrypoint for running the SNOW Relay Service: python -m snow.relay."""

import asyncio
import logging
import sys

from snow.relay.config import RelayConfig
from snow.relay.server import SnowRelayServer


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )
    config = RelayConfig.from_env()
    server = SnowRelayServer(config=config)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(server.start())
        print(f"[+] SNOW Relay Server running on {config.host}:{config.port}", file=sys.stderr)
        print("    Press Ctrl+C to terminate.", file=sys.stderr)
        loop.run_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        loop.run_until_complete(server.stop())
        loop.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
