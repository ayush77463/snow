"""Unit tests for Phase 2 Sub-Milestone 2.1: Device Identity and Pairing."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
import websockets

from snow.core.config import CoreConfig
from snow.network.connection_manager import ConnectionManager
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import ErrorCode, MessageType, PROTOCOL_VERSION
from snow.protocol.models import SnowMessage
from snow.security.identity import (
    DeviceIdentity,
    is_valid_uuidv4,
    load_or_create_device_identity,
)
from snow.security.pairing import (
    DEFAULT_PIN_LIFETIME_SECONDS,
    MAX_FAILED_PAIRING_ATTEMPTS,
    PairingManager,
    PairingOutcome,
    VerificationResult,
)


class TestDeviceIdentity(unittest.TestCase):
    """Test suite for desktop device identity generation, validation, and persistence."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_first_run_generation(self) -> None:
        """Verify device identity is created on first run with a valid UUIDv4."""
        identity = load_or_create_device_identity(data_dir=self.data_dir)

        self.assertTrue(is_valid_uuidv4(identity.device_id))
        self.assertTrue(len(identity.device_name) > 0)
        self.assertTrue(len(identity.created_at) > 0)

        # Check persisted file on disk
        persisted_file = self.data_dir / "device_identity.json"
        self.assertTrue(persisted_file.is_file())

        with open(persisted_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["device_id"], identity.device_id)
        self.assertEqual(data["device_name"], identity.device_name)
        self.assertEqual(data["created_at"], identity.created_at)

    def test_uuidv4_format_and_version(self) -> None:
        """Verify UUIDv4 validator accepts valid RFC 4122 v4 UUIDs and rejects invalid ones."""
        valid_v4 = str(uuid.uuid4())
        self.assertTrue(is_valid_uuidv4(valid_v4))

        # UUIDv1 (non-v4)
        valid_v1 = str(uuid.uuid1())
        self.assertFalse(is_valid_uuidv4(valid_v1))

        # Malformed strings
        self.assertFalse(is_valid_uuidv4("not-a-uuid"))
        self.assertFalse(is_valid_uuidv4(""))
        self.assertFalse(is_valid_uuidv4(None))
        self.assertFalse(is_valid_uuidv4(12345))

    def test_persistence_and_restart_stability(self) -> None:
        """Verify identity remains stable across simulated server restarts."""
        id1 = load_or_create_device_identity(data_dir=self.data_dir, device_name="Test Core")
        id2 = load_or_create_device_identity(data_dir=self.data_dir)

        self.assertEqual(id1.device_id, id2.device_id)
        self.assertEqual(id1.device_name, id2.device_name)
        self.assertEqual(id1.created_at, id2.created_at)

    def test_corrupted_identity_handling(self) -> None:
        """Verify corrupted or invalid identity files are cleanly replaced with a valid UUIDv4."""
        persisted_file = self.data_dir / "device_identity.json"
        with open(persisted_file, "w", encoding="utf-8") as f:
            f.write("{malformed_json: true, invalid}")

        id_recovered = load_or_create_device_identity(data_dir=self.data_dir)
        self.assertTrue(is_valid_uuidv4(id_recovered.device_id))

        # Non-v4 UUID in valid JSON
        with open(persisted_file, "w", encoding="utf-8") as f:
            json.dump({"device_id": str(uuid.uuid1()), "device_name": "Bad", "created_at": "now"}, f)

        id_recovered2 = load_or_create_device_identity(data_dir=self.data_dir)
        self.assertTrue(is_valid_uuidv4(id_recovered2.device_id))
        self.assertNotEqual(id_recovered2.device_id, str(uuid.uuid1()))

    def test_no_stdout_pollution_during_identity_load(self) -> None:
        """Verify identity loading never writes to stdout."""
        stdout_capture = io.StringIO()
        original_stdout = sys.stdout
        sys.stdout = stdout_capture
        try:
            load_or_create_device_identity(data_dir=self.data_dir)
        finally:
            sys.stdout = original_stdout

        self.assertEqual(stdout_capture.getvalue(), "", "Identity loading emitted forbidden stdout!")


class TestPairingManager(unittest.TestCase):
    """Test suite for in-memory 6-digit PIN pairing manager and lockout behavior."""

    def setUp(self) -> None:
        self.current_time = 1000.0
        self.manager = PairingManager(
            pin_lifetime=60.0,
            max_attempts=3,
            time_provider=lambda: self.current_time,
        )

    def test_pin_generation_and_format(self) -> None:
        """Verify generated PIN is exactly 6 decimal digits with leading zeros preserved."""
        for _ in range(50):
            pin = self.manager.generate_pin(display_to_stderr=False)
            self.assertEqual(len(pin), 6)
            self.assertTrue(pin.isdigit(), f"PIN '{pin}' is not numeric")

    def test_pin_output_to_stderr_only(self) -> None:
        """Verify PIN generation outputs exclusively to sys.stderr, never sys.stdout."""
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture
        try:
            pin = self.manager.generate_pin(display_to_stderr=True)
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr

        self.assertEqual(stdout_capture.getvalue(), "", "PIN output was printed to stdout!")
        self.assertIn(pin, stderr_capture.getvalue(), "PIN output was not present in stderr!")

    def test_valid_pin_accepted(self) -> None:
        """Verify correct PIN within lifetime succeeds and returns session ID."""
        pin = self.manager.generate_pin(display_to_stderr=False)
        self.current_time += 15.0  # 15s elapsed (< 60s)

        res = self.manager.verify_pin(pin, client_device_id="client-uuid-1")
        self.assertEqual(res.outcome, PairingOutcome.SUCCESS)
        self.assertTrue(res.is_success)
        self.assertIsNotNone(res.session_id)
        self.assertEqual(res.paired_device_id, "client-uuid-1")
        self.assertTrue(self.manager.is_paired)

    def test_invalid_pin_rejected_and_attempts_decremented(self) -> None:
        """Verify incorrect PIN is rejected and remaining attempts are decremented."""
        pin = self.manager.generate_pin(display_to_stderr=False)
        wrong_pin = "999999" if pin != "999999" else "111111"

        res1 = self.manager.verify_pin(wrong_pin)
        self.assertEqual(res1.outcome, PairingOutcome.INVALID_PIN)
        self.assertEqual(res1.remaining_attempts, 2)
        self.assertEqual(res1.error_code, ErrorCode.INVALID_PIN)

        res2 = self.manager.verify_pin(wrong_pin)
        self.assertEqual(res2.outcome, PairingOutcome.INVALID_PIN)
        self.assertEqual(res2.remaining_attempts, 1)

    def test_third_failed_attempt_causes_lockout(self) -> None:
        """Verify three consecutive incorrect submissions lock pairing."""
        pin = self.manager.generate_pin(display_to_stderr=False)
        wrong_pin = "999999" if pin != "999999" else "111111"

        self.manager.verify_pin(wrong_pin)
        self.manager.verify_pin(wrong_pin)
        res3 = self.manager.verify_pin(wrong_pin)

        self.assertEqual(res3.outcome, PairingOutcome.LOCKED)
        self.assertEqual(res3.remaining_attempts, 0)
        self.assertEqual(res3.error_code, ErrorCode.PAIRING_LOCKED)
        self.assertTrue(self.manager.is_locked)

    def test_locked_session_rejects_further_attempts_even_with_valid_pin(self) -> None:
        """Verify a locked session rejects further submissions even if the submitted PIN is valid."""
        pin = self.manager.generate_pin(display_to_stderr=False)
        wrong = "000000" if pin != "000000" else "111111"

        for _ in range(3):
            self.manager.verify_pin(wrong)

        res = self.manager.verify_pin(pin)
        self.assertEqual(res.outcome, PairingOutcome.LOCKED)
        self.assertEqual(res.remaining_attempts, 0)
        self.assertFalse(self.manager.is_paired)

    def test_pin_expires_at_60_second_boundary(self) -> None:
        """Verify PIN is accepted at 59.9s but rejected as EXPIRED at 60.0s."""
        pin = self.manager.generate_pin(display_to_stderr=False)

        # 59.9s -> Still active
        self.current_time += 59.9
        self.assertTrue(self.manager.has_active_pin)

        # 60.0s -> Expired
        self.current_time += 0.1
        self.assertFalse(self.manager.has_active_pin)

        res = self.manager.verify_pin(pin)
        self.assertEqual(res.outcome, PairingOutcome.EXPIRED)
        self.assertEqual(res.error_code, ErrorCode.PIN_EXPIRED)

    def test_expired_pin_cannot_be_reused(self) -> None:
        """Verify an expired PIN cannot become valid again."""
        pin = self.manager.generate_pin(display_to_stderr=False)
        self.current_time += 65.0

        res1 = self.manager.verify_pin(pin)
        self.assertEqual(res1.outcome, PairingOutcome.EXPIRED)

        # Second try with same PIN
        res2 = self.manager.verify_pin(pin)
        self.assertEqual(res2.outcome, PairingOutcome.NO_ACTIVE_PIN)

    def test_successful_pin_cannot_be_replayed(self) -> None:
        """Verify a successfully consumed PIN cannot be replayed."""
        pin = self.manager.generate_pin(display_to_stderr=False)
        res1 = self.manager.verify_pin(pin, client_device_id="device-A")
        self.assertEqual(res1.outcome, PairingOutcome.SUCCESS)

        # Replay attempt
        res2 = self.manager.verify_pin(pin, client_device_id="device-A")
        self.assertEqual(res2.outcome, PairingOutcome.ALREADY_PAIRED)
        self.assertEqual(res2.error_code, ErrorCode.ALREADY_PAIRED)

    def test_concurrent_submissions_cannot_both_succeed(self) -> None:
        """Verify concurrent requests cannot both consume the same valid PIN."""
        pin = self.manager.generate_pin(display_to_stderr=False)

        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(self.manager.verify_pin, pin, f"client-{i}")
                for i in range(10)
            ]
            for f in futures:
                results.append(f.result())

        success_count = sum(1 for r in results if r.outcome == PairingOutcome.SUCCESS)
        already_paired_count = sum(1 for r in results if r.outcome == PairingOutcome.ALREADY_PAIRED)

        self.assertEqual(success_count, 1, "Exactly one concurrent attempt must succeed!")
        self.assertEqual(already_paired_count, 9, "All other attempts must return ALREADY_PAIRED!")


class TestPairingOverWebSocket(unittest.IsolatedAsyncioTestCase):
    """Integration test verifying pairing protocol handshake over WebSocket."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.device_identity = load_or_create_device_identity(
            data_dir=self.data_dir, device_name="Test Core Host"
        )
        self.pairing_manager = PairingManager(pin_lifetime=60.0, max_attempts=3)

        # Allocate ephemeral port
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            test_port = s.getsockname()[1]

        self.config = CoreConfig(bind_host="127.0.0.1", port=test_port)
        self.conn_mgr = ConnectionManager()

        self.server = SnowWebSocketServer(
            config=self.config,
            connection_manager=self.conn_mgr,
            pairing_manager=self.pairing_manager,
            device_identity=self.device_identity,
        )
        await self.server.start()
        self.port = self.server.bound_port

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        self.temp_dir.cleanup()

    async def test_request_fresh_pin_display(self) -> None:
        """Verify client can request a fresh PIN display without submitting a PIN."""
        uri = f"ws://127.0.0.1:{self.port}"
        async with websockets.connect(uri) as ws:
            req = SnowMessage.create_request(action="pair_request", data={"device_id": str(uuid.uuid4())})
            await ws.send(req.to_json())

            raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            resp = json.loads(raw_resp)

            self.assertEqual(resp["type"], MessageType.RESPONSE)
            self.assertEqual(resp["correlation_id"], req.id)
            self.assertEqual(resp["payload"]["status"], "pin_displayed")
            self.assertEqual(resp["payload"]["data"]["device_id"], self.device_identity.device_id)
            self.assertEqual(resp["payload"]["data"]["expires_in"], 60)

    async def test_successful_pin_pairing_over_ws(self) -> None:
        """Verify client submitting valid PIN pairs successfully over WebSocket with canonical envelope."""
        pin = self.pairing_manager.generate_pin(display_to_stderr=False)
        client_id = str(uuid.uuid4())

        uri = f"ws://127.0.0.1:{self.port}"
        async with websockets.connect(uri) as ws:
            req = SnowMessage.create_request(
                action="pair_request",
                data={"device_id": client_id, "device_name": "Test Phone", "pin": pin},
            )
            await ws.send(req.to_json())

            raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            resp = json.loads(raw_resp)

            # Canonical protocol envelope verification
            self.assertEqual(resp["version"], PROTOCOL_VERSION)
            self.assertEqual(resp["type"], MessageType.RESPONSE)
            self.assertTrue(is_valid_uuidv4(resp["id"]))
            self.assertNotEqual(resp["id"], req.id, "Response ID must be distinct from request ID!")
            self.assertEqual(resp["correlation_id"], req.id, "Correlation ID must equal request ID!")
            self.assertTrue(resp["timestamp"].endswith("Z") or "+00:00" in resp["timestamp"])

            # Payload verification
            self.assertEqual(resp["payload"]["status"], "success")
            self.assertEqual(resp["payload"]["action"], "pair_request")
            self.assertEqual(resp["payload"]["data"]["device_id"], self.device_identity.device_id)
            self.assertEqual(resp["payload"]["data"]["device_name"], self.device_identity.device_name)
            self.assertTrue(is_valid_uuidv4(resp["payload"]["data"]["session_id"]))
            self.assertTrue(self.pairing_manager.is_paired)

    async def test_wrong_pin_error_over_ws(self) -> None:
        """Verify client submitting invalid PIN receives structured INVALID_PIN error with canonical envelope."""
        pin = self.pairing_manager.generate_pin(display_to_stderr=False)
        wrong_pin = "000000" if pin != "000000" else "111111"

        uri = f"ws://127.0.0.1:{self.port}"
        async with websockets.connect(uri) as ws:
            req = SnowMessage.create_request(
                action="pair_request",
                data={"device_id": str(uuid.uuid4()), "pin": wrong_pin},
            )
            await ws.send(req.to_json())

            raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            resp = json.loads(raw_resp)

            self.assertEqual(resp["version"], PROTOCOL_VERSION)
            self.assertEqual(resp["type"], MessageType.ERROR)
            self.assertTrue(is_valid_uuidv4(resp["id"]))
            self.assertNotEqual(resp["id"], req.id)
            self.assertEqual(resp["correlation_id"], req.id)
            self.assertEqual(resp["error"]["code"], ErrorCode.INVALID_PIN)
            self.assertIn("2 attempt(s) remaining", resp["error"]["message"])

    async def test_expired_pin_error_over_ws(self) -> None:
        """Verify client submitting expired PIN receives structured PIN_EXPIRED error over WebSocket."""
        # Create a manager with 0.05s lifetime for test
        self.pairing_manager.pin_lifetime = 0.05
        pin = self.pairing_manager.generate_pin(display_to_stderr=False)
        await asyncio.sleep(0.08)

        uri = f"ws://127.0.0.1:{self.port}"
        async with websockets.connect(uri) as ws:
            req = SnowMessage.create_request(
                action="pair_request",
                data={"device_id": str(uuid.uuid4()), "pin": pin},
            )
            await ws.send(req.to_json())

            raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            resp = json.loads(raw_resp)

            self.assertEqual(resp["version"], PROTOCOL_VERSION)
            self.assertEqual(resp["type"], MessageType.ERROR)
            self.assertEqual(resp["correlation_id"], req.id)
            self.assertNotEqual(resp["id"], req.id)
            self.assertEqual(resp["error"]["code"], ErrorCode.PIN_EXPIRED)

    async def test_pairing_locked_error_over_ws(self) -> None:
        """Verify 3 consecutive invalid attempts over WebSocket trigger PAIRING_LOCKED."""
        pin = self.pairing_manager.generate_pin(display_to_stderr=False)
        wrong_pin = "000000" if pin != "000000" else "111111"
        uri = f"ws://127.0.0.1:{self.port}"

        async with websockets.connect(uri) as ws:
            # Attempts 1 and 2
            for remaining in (2, 1):
                req = SnowMessage.create_request(
                    action="pair_request",
                    data={"device_id": str(uuid.uuid4()), "pin": wrong_pin},
                )
                await ws.send(req.to_json())
                resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=2.0))
                self.assertEqual(resp["error"]["code"], ErrorCode.INVALID_PIN)

            # Attempt 3: Triggers lockout
            req3 = SnowMessage.create_request(
                action="pair_request",
                data={"device_id": str(uuid.uuid4()), "pin": wrong_pin},
            )
            await ws.send(req3.to_json())
            resp3 = json.loads(await asyncio.wait_for(ws.recv(), timeout=2.0))
            self.assertEqual(resp3["error"]["code"], ErrorCode.PAIRING_LOCKED)
            self.assertEqual(resp3["correlation_id"], req3.id)


if __name__ == "__main__":
    unittest.main()
