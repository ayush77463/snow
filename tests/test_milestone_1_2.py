"""Automated verification suite for Phase 1, Sub-Milestone 1.2: WebSocket Server and SNOW Device Protocol v1.

Test Coverage:
- Message serialization, deserialization, and schema validation.
- Rejection of invalid JSON, missing fields, unsupported versions, invalid types, and oversized messages.
- ConnectionManager client tracking, lifecycle, and stale detection.
- Live WebSocket server lifecycle on loopback with dynamic port allocation (port 0).
- Request/response correlation ID matching for 'ping' action.
- Heartbeat request and heartbeat_ack handling.
- Unsupported action error handling.
- Malformed message error reporting without server crash.
- Multiple simultaneous client connections.
- Stale connection reaper timeout.
- Graceful cleanup upon abrupt client disconnect.
"""

import asyncio
import json
import socket
import unittest
import uuid

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from snow.core.config import CoreConfig
from snow.network.connection_manager import ConnectionManager
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import (
    DEFAULT_MAX_MESSAGE_SIZE,
    ErrorCode,
    MessageType,
    PROTOCOL_VERSION,
)
from snow.protocol.models import SnowMessage, current_iso_timestamp
from snow.protocol.validator import ProtocolValidationError, validate_raw_message


class TestProtocolModels(unittest.TestCase):
    """Unit tests for protocol message construction and serialization."""

    def test_create_request_message(self):
        """Verify request message factory generates valid structure."""
        msg = SnowMessage.create_request("ping", {"test_key": "test_val"})
        self.assertEqual(msg.version, PROTOCOL_VERSION)
        self.assertEqual(msg.type, MessageType.REQUEST)
        self.assertTrue(len(msg.id) > 0)
        self.assertIsNotNone(msg.timestamp)
        self.assertIsNone(msg.correlation_id)
        self.assertEqual(msg.payload, {"action": "ping", "data": {"test_key": "test_val"}})
        self.assertIsNone(msg.error)

        # JSON round-trip
        serialized = msg.to_json()
        parsed = json.loads(serialized)
        self.assertEqual(parsed["type"], "request")
        self.assertEqual(parsed["payload"]["action"], "ping")

    def test_create_response_message(self):
        """Verify response message factory links correlation_id correctly."""
        req_id = "request-uuid-1234"
        msg = SnowMessage.create_response(correlation_id=req_id, payload={"status": "success"})
        self.assertEqual(msg.type, MessageType.RESPONSE)
        self.assertEqual(msg.correlation_id, req_id)
        self.assertEqual(msg.payload, {"status": "success"})
        self.assertIsNone(msg.error)

    def test_create_error_message(self):
        """Verify error message factory includes code and description."""
        msg = SnowMessage.create_error(
            code=ErrorCode.UNSUPPORTED_ACTION,
            message="Action 'reboot' is not supported.",
            correlation_id="req-999",
        )
        self.assertEqual(msg.type, MessageType.ERROR)
        self.assertEqual(msg.correlation_id, "req-999")
        self.assertEqual(msg.error["code"], "UNSUPPORTED_ACTION")
        self.assertIn("not supported", msg.error["message"])

    def test_create_heartbeat_and_ack(self):
        """Verify heartbeat and heartbeat_ack message pairs."""
        hb = SnowMessage.create_heartbeat()
        self.assertEqual(hb.type, MessageType.HEARTBEAT)
        self.assertIsNone(hb.correlation_id)

        ack = SnowMessage.create_heartbeat_ack(correlation_id=hb.id)
        self.assertEqual(ack.type, MessageType.HEARTBEAT_ACK)
        self.assertEqual(ack.correlation_id, hb.id)


class TestProtocolValidator(unittest.TestCase):
    """Unit tests for message deserialization and strict schema validation."""

    def test_validate_valid_request(self):
        """Verify valid request JSON is correctly deserialized."""
        valid_id = str(uuid.uuid4())
        valid_json = json.dumps({
            "version": 1,
            "type": "request",
            "id": valid_id,
            "timestamp": current_iso_timestamp(),
            "payload": {"action": "ping", "data": {}}
        })
        msg = validate_raw_message(valid_json)
        self.assertEqual(msg.type, MessageType.REQUEST)
        self.assertEqual(msg.id, valid_id)
        self.assertEqual(msg.payload["action"], "ping")

    def test_reject_invalid_json(self):
        """Verify malformed JSON raises INVALID_JSON error."""
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message("{invalid json payload")
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_JSON)

    def test_reject_non_dict_root(self):
        """Verify non-object JSON roots (lists, strings, numbers) are rejected."""
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(["not", "an", "object"]))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_PAYLOAD)

    def test_reject_missing_required_fields(self):
        """Verify missing version, type, id, or timestamp raises appropriate errors."""
        base = {
            "version": 1,
            "type": "heartbeat",
            "id": str(uuid.uuid4()),
            "timestamp": current_iso_timestamp(),
        }

        # Missing version
        d = dict(base)
        del d["version"]
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(d))
        self.assertEqual(ctx.exception.code, ErrorCode.UNSUPPORTED_VERSION)

        # Missing type
        d = dict(base)
        del d["type"]
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(d))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_MESSAGE_TYPE)

        # Missing id
        d = dict(base)
        del d["id"]
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(d))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_MESSAGE_ID)

        # Missing timestamp
        d = dict(base)
        del d["timestamp"]
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(d))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_TIMESTAMP)

    def test_reject_unsupported_version(self):
        """Verify protocol version != 1 is rejected."""
        d = {
            "version": 2,
            "type": "heartbeat",
            "id": str(uuid.uuid4()),
            "timestamp": current_iso_timestamp(),
        }
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(d))
        self.assertEqual(ctx.exception.code, ErrorCode.UNSUPPORTED_VERSION)

    def test_reject_invalid_message_type(self):
        """Verify unrecognized message types are rejected."""
        d = {
            "version": 1,
            "type": "telemetry_push",
            "id": str(uuid.uuid4()),
            "timestamp": current_iso_timestamp(),
        }
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(d))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_MESSAGE_TYPE)

    def test_reject_oversized_message(self):
        """Verify messages exceeding max_size raise OVERSIZED_MESSAGE."""
        huge_payload = "x" * 2000
        d = {
            "version": 1,
            "type": "request",
            "id": str(uuid.uuid4()),
            "timestamp": current_iso_timestamp(),
            "payload": {"action": "ping", "data": {"blob": huge_payload}}
        }
        raw = json.dumps(d)
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(raw, max_size=1024)
        self.assertEqual(ctx.exception.code, ErrorCode.OVERSIZED_MESSAGE)

    def test_reject_response_without_correlation_id(self):
        """Verify response messages without correlation_id are rejected."""
        d = {
            "version": 1,
            "type": "response",
            "id": str(uuid.uuid4()),
            "timestamp": current_iso_timestamp(),
            "payload": {"status": "success"},
        }
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(d))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_CORRELATION_ID)

    def test_strict_uuidv4_validation(self):
        """Verify strict UUIDv4 validation for message IDs and correlation IDs."""
        valid_v4 = str(uuid.uuid4())
        valid_corr = str(uuid.uuid4())

        # 1. Valid UUIDv4 is accepted
        req = {
            "version": 1,
            "type": "request",
            "id": valid_v4,
            "timestamp": current_iso_timestamp(),
            "payload": {"action": "ping"},
        }
        msg = validate_raw_message(json.dumps(req))
        self.assertEqual(msg.id, valid_v4)

        # 2. Malformed UUID string is rejected
        req["id"] = "not-a-valid-uuid"
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(req))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_MESSAGE_ID)

        # 3. Arbitrary non-UUID string is rejected
        req["id"] = "12345"
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(req))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_MESSAGE_ID)

        # 4. Non-v4 UUID (UUIDv1) is rejected
        req["id"] = str(uuid.uuid1())
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(req))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_MESSAGE_ID)

        # 5. Non-v4 UUID (UUIDv5) is rejected
        req["id"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, "example.com"))
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(req))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_MESSAGE_ID)

        # 6. Valid correlation_id (UUIDv4) is accepted
        resp = {
            "version": 1,
            "type": "response",
            "id": valid_v4,
            "correlation_id": valid_corr,
            "timestamp": current_iso_timestamp(),
            "payload": {"status": "success"},
        }
        resp_msg = validate_raw_message(json.dumps(resp))
        self.assertEqual(resp_msg.correlation_id, valid_corr)

        # 7. Invalid correlation_id (non-UUID) is rejected
        resp["correlation_id"] = "invalid-correlation-id"
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(resp))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_CORRELATION_ID)

        # 8. Invalid correlation_id (UUIDv1) is rejected
        resp["correlation_id"] = str(uuid.uuid1())
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(resp))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_CORRELATION_ID)

    def test_strict_utc_timestamp_validation(self):
        """Verify strict UTC ISO-8601 timestamp validation."""
        valid_id = str(uuid.uuid4())
        base = {
            "version": 1,
            "type": "heartbeat",
            "id": valid_id,
        }

        # 1. Valid UTC ISO timestamp with 'Z' suffix is accepted
        base["timestamp"] = "2026-11-15T12:00:00Z"
        msg = validate_raw_message(json.dumps(base))
        self.assertEqual(msg.timestamp, "2026-11-15T12:00:00Z")

        # 2. Valid UTC ISO timestamp with '+00:00' suffix is accepted
        base["timestamp"] = "2026-11-15T12:00:00+00:00"
        msg = validate_raw_message(json.dumps(base))
        self.assertEqual(msg.timestamp, "2026-11-15T12:00:00+00:00")

        # 3. Naive timestamp without timezone offset is rejected
        base["timestamp"] = "2026-11-15T12:00:00"
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(base))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_TIMESTAMP)

        # 4. Non-zero UTC offset (+05:30) is rejected
        base["timestamp"] = "2026-11-15T12:00:00+05:30"
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(base))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_TIMESTAMP)

        # 5. Non-zero UTC offset (-04:00) is rejected
        base["timestamp"] = "2026-11-15T12:00:00-04:00"
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(base))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_TIMESTAMP)

        # 6. Malformed timestamp string is rejected
        base["timestamp"] = "not-a-valid-timestamp"
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(json.dumps(base))
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_TIMESTAMP)


class TestConnectionManager(unittest.TestCase):
    """Unit tests for connection tracking abstraction."""

    def test_register_and_unregister(self):
        """Verify client registration and unregistration lifecycle."""
        manager = ConnectionManager()
        self.assertEqual(manager.connection_count, 0)

        class MockSocket:
            remote_address = ("127.0.0.1", 54321)

        client = manager.register(MockSocket())
        self.assertEqual(manager.connection_count, 1)
        self.assertTrue(client.is_active)
        self.assertEqual(manager.get(client.connection_id), client)

        unreg = manager.unregister(client.connection_id)
        self.assertEqual(unreg, client)
        self.assertFalse(client.is_active)
        self.assertEqual(manager.connection_count, 0)

    def test_heartbeat_tracking_and_stale_detection(self):
        """Verify heartbeat timestamps and stale connection identification."""
        manager = ConnectionManager()

        class MockSocket:
            remote_address = ("127.0.0.1", 54322)

        client = manager.register(MockSocket())
        client.last_heartbeat_at -= 10.0  # simulate 10 seconds of silence

        # Timeout 5s -> should be stale
        stale = manager.get_stale_connections(timeout_seconds=5.0)
        self.assertIn(client, stale)

        # Record heartbeat -> should no longer be stale
        manager.record_heartbeat(client.connection_id)
        self.assertEqual(len(manager.get_stale_connections(timeout_seconds=5.0)), 0)


class TestWebSocketServerIntegration(unittest.IsolatedAsyncioTestCase):
    """Live integration tests for WebSocket server on dynamic loopback ports."""

    async def asyncSetUp(self):
        """Start a SnowWebSocketServer instance on 127.0.0.1 on an available test port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            test_port = s.getsockname()[1]

        self.config = CoreConfig(
            bind_host="127.0.0.1",
            port=test_port,
            heartbeat_timeout=1.5,
            max_message_size=4096,
            tls_enabled=False,
            auth_required=False,
        )
        self.server = SnowWebSocketServer(self.config)
        await self.server.start()
        self.port = self.server.bound_port or test_port
        self.ws_url = f"ws://127.0.0.1:{self.port}"

    async def asyncTearDown(self):
        """Stop the WebSocket server cleanly."""
        await self.server.stop()

    async def test_ping_pong_request_response(self):
        """Verify client can connect, send 'ping', and receive matched 'pong' response."""
        async with connect(self.ws_url) as ws:
            req = SnowMessage.create_request("ping")
            await ws.send(req.to_json())

            raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            resp = validate_raw_message(raw_resp)

            self.assertEqual(resp.type, MessageType.RESPONSE)
            self.assertEqual(resp.correlation_id, req.id)
            self.assertEqual(resp.payload["status"], "success")
            self.assertEqual(resp.payload["action"], "pong")

    async def test_heartbeat_and_ack(self):
        """Verify client can send heartbeat and receive heartbeat_ack with correlation ID."""
        async with connect(self.ws_url) as ws:
            hb = SnowMessage.create_heartbeat()
            await ws.send(hb.to_json())

            raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            ack = validate_raw_message(raw_resp)

            self.assertEqual(ack.type, MessageType.HEARTBEAT_ACK)
            self.assertEqual(ack.correlation_id, hb.id)

    async def test_unsupported_action_returns_error(self):
        """Verify requesting an unauthorized action returns UNSUPPORTED_ACTION error."""
        async with connect(self.ws_url) as ws:
            req = SnowMessage.create_request("unauthorized_exec")
            await ws.send(req.to_json())

            raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            err_msg = validate_raw_message(raw_resp)

            self.assertEqual(err_msg.type, MessageType.ERROR)
            self.assertEqual(err_msg.correlation_id, req.id)
            self.assertEqual(err_msg.error["code"], ErrorCode.UNSUPPORTED_ACTION)

    async def test_malformed_json_returns_error_without_crash(self):
        """Verify sending invalid JSON returns an error response and keeps socket open."""
        async with connect(self.ws_url) as ws:
            await ws.send("{malformed json string!!")

            raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            err_msg = validate_raw_message(raw_resp)

            self.assertEqual(err_msg.type, MessageType.ERROR)
            self.assertEqual(err_msg.error["code"], ErrorCode.INVALID_JSON)

            # Subsequent valid ping still succeeds on the same connection
            req = SnowMessage.create_request("ping")
            await ws.send(req.to_json())
            raw_pong = await asyncio.wait_for(ws.recv(), timeout=2.0)
            pong = validate_raw_message(raw_pong)
            self.assertEqual(pong.payload["action"], "pong")

    async def test_oversized_message_closes_with_1009(self):
        """Verify sending a message exceeding max_size triggers RFC 6455 close code 1009 (Message Too Big)."""
        async with connect(self.ws_url) as ws:
            blob = "a" * 5000  # max_size configured to 4096
            req = SnowMessage.create_request("ping", {"blob": blob})
            await ws.send(req.to_json())

            with self.assertRaises(ConnectionClosed) as ctx:
                await ws.recv()
            self.assertEqual(ctx.exception.rcvd.code, 1009)

    async def test_multiple_simultaneous_clients(self):
        """Verify multiple simultaneous client connections operate independently."""
        client_count = 3
        connections = [await connect(self.ws_url) for _ in range(client_count)]

        try:
            self.assertEqual(self.server.connection_manager.connection_count, client_count)

            # Send ping from each client
            requests = [SnowMessage.create_request("ping", {"client_idx": i}) for i in range(client_count)]
            for ws, req in zip(connections, requests):
                await ws.send(req.to_json())

            # Read and verify responses
            for ws, req in zip(connections, requests):
                raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
                resp = validate_raw_message(raw_resp)
                self.assertEqual(resp.type, MessageType.RESPONSE)
                self.assertEqual(resp.correlation_id, req.id)
                self.assertEqual(resp.payload["action"], "pong")
        finally:
            for ws in connections:
                await ws.close()

    async def test_unexpected_client_disconnect_cleanup(self):
        """Verify server unregisters client immediately when connection is severed."""
        ws = await connect(self.ws_url)
        self.assertEqual(self.server.connection_manager.connection_count, 1)

        await ws.close(code=1000)
        # Yield briefly so server handles disconnect event
        await asyncio.sleep(0.1)

        self.assertEqual(self.server.connection_manager.connection_count, 0)

    async def test_heartbeat_timeout_reaper(self):
        """Verify inactive clients exceeding heartbeat_timeout are terminated by reaper."""
        ws = await connect(self.ws_url)
        self.assertEqual(self.server.connection_manager.connection_count, 1)

        # Do not send heartbeats; wait for reaper (configured heartbeat_timeout=2.0s)
        # Sleep long enough for reaper to identify and terminate stale connection
        await asyncio.sleep(2.5)

        # Client socket should now be closed by server
        with self.assertRaises(ConnectionClosed):
            await ws.recv()

        self.assertEqual(self.server.connection_manager.connection_count, 0)

    async def test_server_to_client_request_correlation(self):
        """Verify server can send a request to a client and correlate the response."""
        async with connect(self.ws_url) as ws:
            active_clients = self.server.connection_manager.get_active_connections()
            self.assertEqual(len(active_clients), 1)
            client_id = active_clients[0].connection_id

            async def client_responder():
                raw = await ws.recv()
                msg = validate_raw_message(raw)
                if msg.type == MessageType.REQUEST and msg.payload.get("action") == "echo":
                    resp = SnowMessage.create_response(
                        correlation_id=msg.id,
                        payload={"status": "success", "echo": msg.payload.get("data")},
                    )
                    await ws.send(resp.to_json())

            responder_task = asyncio.create_task(client_responder())

            # Server initiates generic command to client
            response = await self.server.send_request(
                connection_id=client_id,
                action="echo",
                payload={"text": "snow_protocol_v1"},
                timeout=5.0,
            )
            await responder_task

            self.assertEqual(response.type, MessageType.RESPONSE)
            self.assertEqual(response.payload["status"], "success")
            self.assertEqual(response.payload["echo"], {"text": "snow_protocol_v1"})

    async def test_server_send_request_timeout(self):
        """Verify send_request raises TimeoutError if client does not respond within timeout."""
        async with connect(self.ws_url):
            active_clients = self.server.connection_manager.get_active_connections()
            self.assertEqual(len(active_clients), 1)
            client_id = active_clients[0].connection_id

            with self.assertRaises(TimeoutError):
                # Client does not respond; timeout set to 0.2s
                await self.server.send_request(
                    connection_id=client_id,
                    action="echo",
                    timeout=0.2,
                )

    async def test_mock_device_handles_error_message_without_attribute_error(self):
        """Verify MockDeviceClient._receiver_loop safely extracts error info without AttributeError."""
        from tests.mock_device import MockDeviceClient
        client = MockDeviceClient("127.0.0.1", self.port)

        class MockIncomingWS:
            def __init__(self, messages):
                self._messages = list(messages)

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self._messages:
                    return self._messages.pop(0)
                raise StopAsyncIteration

        err_msg = SnowMessage.create_error(
            code=ErrorCode.UNSUPPORTED_ACTION,
            message="Simulated action unsupported",
            correlation_id=str(uuid.uuid4()),
        )
        fake_ws = MockIncomingWS([err_msg.to_json()])

        # Must execute without raising AttributeError on msg.error
        await client._receiver_loop(fake_ws)


if __name__ == "__main__":
    unittest.main()
