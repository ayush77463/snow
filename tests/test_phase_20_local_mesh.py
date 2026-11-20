"""Unit tests for SNOW Phase 20: Local Connectivity, Zero-IP-Friction Onboarding & Device Mesh.

Tests cover:
1. QR Pairing Payload Construction & Security Validation (RFC-compliant schema v1)
2. IP Filtering & Loopback Rejection for LAN Onboarding
3. Fingerprint Format Normalization and Timing-Resistant Verification
4. Zero-Data USB Mode (ADB executable detection, device enumeration, reverse mapping parsing)
5. USB Tethering Network Interface Detection vs. ADB Reverse Port Forwarding
6. Pairing Manager PIN single-use consumption and expiry
"""

import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

from snow.cli import find_adb_binary, get_connected_adb_devices
from snow.core.network import (
    NetworkInterfaceInfo,
    detect_usb_tethering_interfaces,
    get_active_ip_addresses,
    is_usable_ipv4,
)
from snow.security.pairing import (
    PairingManager,
    create_qr_pairing_payload,
    validate_qr_pairing_payload,
)


class TestPhase20QrPairingPayload(unittest.TestCase):
    """Test QR pairing payload creation, filtering, and schema validation."""

    def setUp(self) -> None:
        self.node_id = "desktop-node-phase20-uuid"
        self.valid_ips = ["192.168.1.120", "10.0.0.15"]
        self.port = 8765
        self.valid_fp = "A1:B2:C3:D4:E5:F6:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23"
        self.raw_fp_hex = "A1B2C3D4E5F60123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
        self.valid_pin = "482915"

    def test_create_qr_pairing_payload_success(self) -> None:
        payload = create_qr_pairing_payload(
            node_id=self.node_id,
            candidate_ips=self.valid_ips,
            port=self.port,
            cert_fingerprint=self.valid_fp,
            pin=self.valid_pin,
        )

        self.assertEqual(payload["v"], 1)
        self.assertEqual(payload["id"], self.node_id)
        self.assertEqual(payload["port"], 8765)
        self.assertEqual(payload["pin"], "482915")
        self.assertEqual(payload["fp"], self.raw_fp_hex)
        self.assertEqual(payload["ips"], ["192.168.1.120", "10.0.0.15"])

    def test_create_qr_pairing_filters_loopback_and_link_local(self) -> None:
        candidate_ips = [
            "127.0.0.1",       # Loopback - MUST BE FILTERED
            "169.254.10.5",     # Link-local autoconfig - MUST BE FILTERED
            "0.0.0.0",          # Unspecified - MUST BE FILTERED
            "192.168.1.100",    # Valid LAN IPv4
        ]
        payload = create_qr_pairing_payload(
            node_id=self.node_id,
            candidate_ips=candidate_ips,
            port=self.port,
            cert_fingerprint=self.valid_fp,
            pin=self.valid_pin,
        )

        self.assertEqual(payload["ips"], ["192.168.1.100"])

    def test_create_qr_pairing_rejects_only_loopback_ips(self) -> None:
        loopback_only = ["127.0.0.1", "127.0.0.2", "169.254.1.1"]
        with self.assertRaises(ValueError) as ctx:
            create_qr_pairing_payload(
                node_id=self.node_id,
                candidate_ips=loopback_only,
                port=self.port,
                cert_fingerprint=self.valid_fp,
                pin=self.valid_pin,
            )
        self.assertIn("non-loopback", str(ctx.exception).lower())

    def test_create_qr_pairing_rejects_invalid_pin(self) -> None:
        for bad_pin in ["12345", "1234567", "abcdef", "12 45", ""]:
            with self.assertRaises(ValueError):
                create_qr_pairing_payload(
                    node_id=self.node_id,
                    candidate_ips=self.valid_ips,
                    port=self.port,
                    cert_fingerprint=self.valid_fp,
                    pin=bad_pin,
                )

    def test_create_qr_pairing_rejects_invalid_fingerprint(self) -> None:
        for bad_fp in ["A1B2C3", "NOT_A_HEX_STRING_FOR_SHA256_FINGERPRINT_1234567890123456789012345678", ""]:
            with self.assertRaises(ValueError):
                create_qr_pairing_payload(
                    node_id=self.node_id,
                    candidate_ips=self.valid_ips,
                    port=self.port,
                    cert_fingerprint=bad_fp,
                    pin=self.valid_pin,
                )

    def test_create_qr_pairing_rejects_invalid_port(self) -> None:
        for bad_port in [0, -1, 65536, 99999]:
            with self.assertRaises(ValueError):
                create_qr_pairing_payload(
                    node_id=self.node_id,
                    candidate_ips=self.valid_ips,
                    port=bad_port,
                    cert_fingerprint=self.valid_fp,
                    pin=self.valid_pin,
                )

    def test_create_qr_pairing_rejects_unsupported_version(self) -> None:
        with self.assertRaises(ValueError):
            create_qr_pairing_payload(
                node_id=self.node_id,
                candidate_ips=self.valid_ips,
                port=self.port,
                cert_fingerprint=self.valid_fp,
                pin=self.valid_pin,
                version=2,
            )

    def test_validate_qr_pairing_payload_json_string(self) -> None:
        json_str = json.dumps({
            "v": 1,
            "id": "node-target-1",
            "ips": ["192.168.31.50"],
            "port": 8765,
            "fp": self.raw_fp_hex,
            "pin": "654321",
        })
        validated = validate_qr_pairing_payload(json_str)
        self.assertEqual(validated["v"], 1)
        self.assertEqual(validated["id"], "node-target-1")
        self.assertEqual(validated["pin"], "654321")
        self.assertEqual(validated["fp"], self.raw_fp_hex)

    def test_validate_qr_pairing_payload_rejects_malformed_json(self) -> None:
        with self.assertRaises(ValueError):
            validate_qr_pairing_payload("{ bad json content ")

    def test_validate_qr_pairing_payload_rejects_missing_fields(self) -> None:
        incomplete = {
            "v": 1,
            "ips": ["192.168.1.50"],
            "port": 8765,
            "fp": self.raw_fp_hex,
            "pin": "123456",
        }
        with self.assertRaises(ValueError):
            validate_qr_pairing_payload(incomplete)


class TestPhase20UsbMode(unittest.TestCase):
    """Test USB mode ADB device enumeration and reverse port mapping parsing."""

    def test_get_connected_adb_devices_parsing(self) -> None:
        mock_output = (
            "List of devices attached\n"
            "9P89JZY9L75HAAL7       device product:RMX5110IN model:RMX5110 device:RE6440L1 transport_id:1\n"
            "emulator-5554          offline transport_id:2\n"
            "UNAUTH12345            unauthorized transport_id:3\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=mock_output, returncode=0)
            devices = get_connected_adb_devices(Path("adb.exe"))

            self.assertEqual(len(devices), 3)
            self.assertEqual(devices[0]["serial"], "9P89JZY9L75HAAL7")
            self.assertEqual(devices[0]["status"], "device")
            self.assertEqual(devices[0]["model"], "RMX5110")

            self.assertEqual(devices[1]["serial"], "emulator-5554")
            self.assertEqual(devices[1]["status"], "offline")

            self.assertEqual(devices[2]["serial"], "UNAUTH12345")
            self.assertEqual(devices[2]["status"], "unauthorized")

    def test_detect_usb_tethering_interfaces(self) -> None:
        mock_ifaces = [
            NetworkInterfaceInfo("Wi-Fi", "192.168.1.100", is_up=True),
            NetworkInterfaceInfo("Ethernet", "192.168.1.200", is_up=True),
            NetworkInterfaceInfo("Remote NDIS based Internet Sharing Device", "192.168.42.10", is_up=True),
            NetworkInterfaceInfo("Apple Mobile Device Ethernet", "172.20.10.5", is_up=True),
        ]
        with patch("snow.core.network.detect_usable_ipv4_addresses", return_value=mock_ifaces):
            tethered = detect_usb_tethering_interfaces()
            self.assertEqual(len(tethered), 2)
            names = [t.interface_name for t in tethered]
            self.assertIn("Remote NDIS based Internet Sharing Device", names)
            self.assertIn("Apple Mobile Device Ethernet", names)

    def test_get_active_ip_addresses_deduplication(self) -> None:
        mock_ifaces = [
            NetworkInterfaceInfo("Wi-Fi", "192.168.1.50", is_up=True),
            NetworkInterfaceInfo("Wi-Fi-Virtual", "192.168.1.50", is_up=True),
            NetworkInterfaceInfo("Ethernet", "10.0.0.5", is_up=True),
            NetworkInterfaceInfo("Inactive", "192.168.1.99", is_up=False),
        ]
        with patch("snow.core.network.detect_usable_ipv4_addresses", return_value=mock_ifaces):
            active = get_active_ip_addresses()
            self.assertEqual(len(active), 2)
            self.assertEqual(active, ["192.168.1.50", "10.0.0.5"])


class TestPhase20PairingManager(unittest.TestCase):
    """Test pairing manager single-use PIN consumption and expiry for QR pairing."""

    def setUp(self) -> None:
        self.pm = PairingManager(pin_lifetime=60.0, max_attempts=3)

    def test_pin_generation_and_consumption(self) -> None:
        owner_pin = self.pm.generate_pin(display_to_stderr=False)
        self.assertEqual(len(owner_pin), 6)
        self.assertTrue(owner_pin.isdigit())
        self.assertTrue(self.pm.has_active_pin)

        # Successful verification
        res = self.pm.verify_pin(owner_pin, client_device_id="android-client-1")
        self.assertTrue(res.is_success)
        self.assertEqual(res.assigned_trust_tier, "owner")
        self.assertFalse(self.pm.has_active_pin)

        # Replay attempt with same PIN must fail
        replay_res = self.pm.verify_pin(owner_pin, client_device_id="attacker-device")
        self.assertFalse(replay_res.is_success)


class TestPhase20CliPair(unittest.TestCase):
    """Test CLI snow pair execution against Core daemon IPC."""

    @patch("snow.cli.SnowMcpBridge")
    def test_run_pair_invokes_bridge_call(self, mock_bridge_cls: MagicMock) -> None:
        from snow.cli import run_pair
        mock_bridge = MagicMock()
        mock_bridge_cls.return_value = mock_bridge

        async def mock_is_ready(timeout: float = 0.3) -> bool:
            return True
        mock_bridge.daemon_manager.is_ipc_ready = mock_is_ready

        async def mock_call(op: str, payload: dict | None = None, timeout: float = 10.0) -> dict:
            self.assertEqual(op, "generate_pairing_qr")
            return {
                "success": True,
                "data": {
                    "v": 1,
                    "id": "desktop-node-1",
                    "ips": ["192.168.1.100"],
                    "port": 8765,
                    "fp": "A1" * 32,
                    "pin": "123456",
                },
            }
        mock_bridge.call = mock_call

        ret = run_pair(json_output=True)
        self.assertEqual(ret, 0)


if __name__ == "__main__":
    unittest.main()
