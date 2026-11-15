"""Mock device client for testing the SNOW WebSocket server.

Simulates a client (such as an Android device or test runner) connecting
to the SNOW Desktop Core over WebSocket using SNOW Device Protocol v1.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from snow.protocol import ErrorCode, MessageType, SnowMessage, validate_raw_message

# Configure logging strictly to sys.stderr to preserve stdout isolation
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] mock_device: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("mock_device")


class MockDeviceClient:
    """Mock client implementing SNOW Device Protocol v1."""

    def __init__(self, host: str, port: int, heartbeat_interval: float = 15.0) -> None:
        self.host = host
        self.port = port
        self.url = f"ws://{host}:{port}"
        self.heartbeat_interval = heartbeat_interval
        self._stop_event = asyncio.Event()

    def stop(self) -> None:
        """Signal client to terminate."""
        self._stop_event.set()

    async def run(self) -> None:
        """Connect to the SNOW WebSocket server and run the event loop."""
        logger.info("Connecting to SNOW WebSocket server at %s...", self.url)
        try:
            async with connect(self.url) as ws:
                logger.info("Successfully connected to %s", self.url)

                # Send initial ping to verify handshake and correlation ID
                ping_req = SnowMessage.create_request("ping", {"sender": "mock_device"})
                await ws.send(ping_req.to_json())
                logger.info("Sent initial ping request [id=%s]", ping_req.id)

                # Launch concurrent receiver and heartbeat sender tasks
                heartbeat_task = asyncio.create_task(self._heartbeat_loop(ws))
                receiver_task = asyncio.create_task(self._receiver_loop(ws))

                # Wait until stopped or a task finishes/fails
                stop_waiter = asyncio.create_task(self._stop_event.wait())
                done, pending = await asyncio.wait(
                    [heartbeat_task, receiver_task, stop_waiter],
                    return_when=asyncio.FIRST_COMPLETED,
                )

                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except (asyncio.CancelledError, ConnectionClosed):
                        pass

        except ConnectionClosed as exc:
            code = exc.rcvd.code if exc.rcvd is not None else (exc.sent.code if exc.sent is not None else 1006)
            reason = exc.rcvd.reason if exc.rcvd is not None else (exc.sent.reason if exc.sent is not None else "closed")
            logger.warning("Connection closed: %s (code=%s)", reason, code)
        except OSError as exc:
            logger.error("Failed to connect to %s: %s", self.url, exc)
        finally:
            logger.info("Mock device client exited.")

    async def _heartbeat_loop(self, ws) -> None:
        """Periodically transmit heartbeat messages to keep connection active."""
        try:
            while not self._stop_event.is_set():
                await asyncio.sleep(self.heartbeat_interval)
                hb = SnowMessage.create_heartbeat()
                await ws.send(hb.to_json())
                logger.info("Transmitted heartbeat [id=%s]", hb.id)
        except asyncio.CancelledError:
            pass

    async def _receiver_loop(self, ws) -> None:
        """Listen for and process server messages."""
        try:
            async for raw in ws:
                try:
                    msg = validate_raw_message(raw)
                except Exception as exc:
                    logger.warning("Received invalid message from server: %s", exc)
                    continue

                if msg.type == MessageType.RESPONSE:
                    logger.info("Received RESPONSE for [correlation_id=%s]: %s",
                                msg.correlation_id, msg.payload)
                elif msg.type == MessageType.HEARTBEAT_ACK:
                    logger.info("Received HEARTBEAT_ACK for [correlation_id=%s]",
                                msg.correlation_id)
                elif msg.type == MessageType.ERROR:
                    err_data = msg.error or {}
                    err_code = err_data.get("code", "UNKNOWN")
                    err_text = err_data.get("message", "")
                    logger.warning("Received ERROR [code=%s, correlation_id=%s]: %s",
                                   err_code, msg.correlation_id, err_text)
                elif msg.type == MessageType.REQUEST:
                    await self._handle_server_request(ws, msg)
                else:
                    logger.info("Received message type=%s [id=%s]", msg.type, msg.id)
        except ConnectionClosed:
            raise
        except asyncio.CancelledError:
            pass

    async def _handle_server_request(self, ws, msg: SnowMessage) -> None:
        """Handle incoming request from the server."""
        payload = msg.payload or {}
        action = payload.get("action")
        logger.info("Server requested action: %s", action)

        if action == "ping":
            resp = SnowMessage.create_response(
                correlation_id=msg.id,
                payload={"status": "success", "action": "pong"},
            )
            await ws.send(resp.to_json())
        elif action == "echo":
            resp = SnowMessage.create_response(
                correlation_id=msg.id,
                payload={"status": "success", "echo": payload.get("data")},
            )
            await ws.send(resp.to_json())
        else:
            err = SnowMessage.create_error(
                code=ErrorCode.UNSUPPORTED_ACTION,
                message=f"Mock device does not support action '{action}'",
                correlation_id=msg.id,
            )
            await ws.send(err.to_json())


def main() -> None:
    """CLI entry point for mock device."""
    parser = argparse.ArgumentParser(description="SNOW Mock Device Client")
    parser.add_argument("--host", default="127.0.0.1", help="SNOW Core server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="SNOW Core server port (default: 8765)")
    parser.add_argument("--interval", type=float, default=15.0, help="Heartbeat interval in seconds (default: 15.0)")
    args = parser.parse_args()

    client = MockDeviceClient(args.host, args.port, args.interval)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _sig_handler() -> None:
        logger.info("Shutdown signal received; stopping client...")
        client.stop()

    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is not None:
            try:
                loop.add_signal_handler(sig, _sig_handler)
            except (NotImplementedError, RuntimeError):
                # Windows event loop may not support add_signal_handler
                pass

    try:
        loop.run_until_complete(client.run())
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received; stopping...")
        client.stop()
    finally:
        loop.close()


if __name__ == "__main__":
    main()
