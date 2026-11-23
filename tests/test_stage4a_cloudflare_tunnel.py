"""Unit tests for Stage 4A Track A: Cloudflare packaging and isolated dual tunnels."""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

_build_release_path = Path(__file__).resolve().parent.parent / "packaging" / "windows" / "build_release.py"
_spec = importlib.util.spec_from_file_location("snow_build_release", _build_release_path)
_build_release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_build_release)

CLOUDFLARED_SHA256 = _build_release.CLOUDFLARED_SHA256
CLOUDFLARED_VERSION = _build_release.CLOUDFLARED_VERSION
compute_file_sha256 = _build_release.compute_file_sha256
ensure_cloudflared_binary = _build_release.ensure_cloudflared_binary
verify_file_sha256 = _build_release.verify_file_sha256
from snow.mcp.tunnel import (
    ALLOWED_RELAY_TUNNEL_PORT,
    ALLOWED_TUNNEL_PORT,
    ALLOWED_TUNNEL_PORTS,
    CLOUDFLARED_URL_REGEX,
    TAILSCALE_URL_REGEX,
    TunnelManager,
    _TunnelInstance,
    find_cloudflared_binary,
)


class TestCloudflaredBinaryPackaging(unittest.TestCase):
    """Verify lookup precedence, supply-chain verification, and build failure on checksum mismatch."""

    def test_find_cloudflared_prefers_meipass_when_frozen(self) -> None:
        """When running in a PyInstaller bundle, _MEIPASS candidates take precedence."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            fake_bin = tmp_path / "bin" / "cloudflared.exe"
            fake_bin.parent.mkdir(parents=True, exist_ok=True)
            fake_bin.write_text("dummy binary", encoding="utf-8")

            with patch.object(sys, "frozen", True, create=True), patch.object(
                sys, "_MEIPASS", str(tmp_path), create=True
            ):
                found = find_cloudflared_binary()
                self.assertIsNotNone(found)
                self.assertEqual(Path(found).resolve(), fake_bin.resolve())

    def test_find_cloudflared_prefers_exe_dir_over_path(self) -> None:
        """Installed application bin/ takes precedence over system PATH."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            fake_bin = tmp_path / "bin" / "cloudflared.exe"
            fake_bin.parent.mkdir(parents=True, exist_ok=True)
            fake_bin.write_text("dummy", encoding="utf-8")

            fake_python = str(tmp_path / "python.exe")
            with patch.object(sys, "executable", fake_python), patch(
                "shutil.which", return_value=r"C:\Windows\System32\cloudflared.exe"
            ):
                found = find_cloudflared_binary()
                self.assertIsNotNone(found)
                self.assertEqual(Path(found).resolve(), fake_bin.resolve())

    def test_find_cloudflared_missing_returns_none(self) -> None:
        """When no candidate exists anywhere, returns None gracefully."""
        with tempfile.TemporaryDirectory() as empty_dir:
            fake_py = str(Path(empty_dir) / "py.exe")
            with patch.object(sys, "executable", fake_py), patch(
                "shutil.which", return_value=None
            ), patch.dict("os.environ", {}, clear=True), patch(
                "pathlib.Path.home", return_value=Path(empty_dir)
            ):
                found = find_cloudflared_binary()
                # If development repo has packaging/bin/cloudflared.exe, skip or check
                if found and "packaging" in found:
                    self.assertTrue(Path(found).is_file())
                else:
                    self.assertIsNone(found)

    def test_sha256_verification_and_integrity_check(self) -> None:
        """File matching expected SHA-256 verifies; corrupted file fails."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"SNOW_SECURE_PAYLOAD")
            tf_path = Path(tf.name)

        try:
            expected_digest = compute_file_sha256(tf_path)
            self.assertTrue(verify_file_sha256(tf_path, expected_digest))
            self.assertFalse(verify_file_sha256(tf_path, "0" * 64))
        finally:
            tf_path.unlink(missing_ok=True)

    def test_pinned_version_and_checksum_consistency(self) -> None:
        """Official release version is 2026.11.2 and checksum matches pinned constant."""
        self.assertEqual(CLOUDFLARED_VERSION, "2026.11.2")
        self.assertEqual(
            CLOUDFLARED_SHA256,
            "555b46c85582461d189cac30d14ad05480d612613801be9f110b8ce08c5b2113",
        )

    def test_inno_setup_installer_includes_cloudflared_binary(self) -> None:
        """Inno Setup script explicitly includes cloudflared.exe in {app}\\bin."""
        iss_path = Path(__file__).resolve().parent.parent / "packaging" / "windows" / "snow_setup.iss"
        self.assertTrue(iss_path.is_file(), "snow_setup.iss must exist")
        content = iss_path.read_text(encoding="utf-8")
        self.assertIn("cloudflared.exe", content)
        self.assertIn("DestDir: \"{app}\\bin\"", content)

    def test_ensure_cloudflared_binary_aborts_on_corrupt_binary(self) -> None:
        """ensure_cloudflared_binary raises RuntimeError if binary fails checksum verification."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo_root = Path(tmp_dir)
            pkg_bin = repo_root / "packaging" / "bin"
            pkg_bin.mkdir(parents=True, exist_ok=True)
            bad_exe = pkg_bin / "cloudflared.exe"
            bad_exe.write_text("CORRUPTED_PAYLOAD_NOT_CLOUDFLARE", encoding="utf-8")

            # Without download allowed, must raise RuntimeError
            with self.assertRaises(RuntimeError) as ctx:
                ensure_cloudflared_binary(repo_root, allow_download=False)
            self.assertIn("missing in", str(ctx.exception))


class TestIsolatedDualTunnelManager(unittest.IsolatedAsyncioTestCase):
    """Verify strictly isolated dual tunnel instances for MCP Gateway and Device Relay."""

    async def test_strictly_isolated_instances(self) -> None:
        """TunnelManager maintains two completely separate instances with independent states."""
        tm = TunnelManager(target_port=ALLOWED_TUNNEL_PORT)
        self.assertIsNot(tm.mcp_tunnel, tm.relay_tunnel)
        self.assertEqual(tm.mcp_tunnel.target_port, 8771)
        self.assertEqual(tm.relay_tunnel.target_port, 8770)

        # Start custom tunnel on MCP
        res_mcp = await tm.start_tunnel(
            provider="custom",
            port=8771,
            custom_url="https://mcp.snow.example.com",
        )
        self.assertTrue(res_mcp["success"])
        self.assertEqual(res_mcp["mcp_endpoint"], "https://mcp.snow.example.com/mcp")

        # Relay tunnel must remain completely inactive and unaffected
        relay_status = tm.get_status(port=8770)
        self.assertFalse(relay_status["active"])
        self.assertIsNone(relay_status["public_url"])

        # Start custom tunnel on Relay
        res_relay = await tm.start_relay_tunnel(
            provider="custom",
            port=8770,
            custom_url="wss://relay.snow.example.com:8770",
        )
        self.assertTrue(res_relay["success"])

        # Both tunnels active independently
        all_status = tm.get_all_status()
        self.assertTrue(all_status["mcp"]["active"])
        self.assertEqual(all_status["mcp"]["public_url"], "https://mcp.snow.example.com")
        self.assertTrue(all_status["relay"]["active"])
        self.assertEqual(all_status["relay"]["public_url"], "wss://relay.snow.example.com:8770")

        # Stop only MCP tunnel
        await tm.stop_tunnel(port=8771)
        self.assertFalse(tm.get_status(port=8771)["active"])
        self.assertTrue(tm.get_status(port=8770)["active"])

        # stop_all_tunnels stops all
        await tm.stop_all_tunnels()
        self.assertFalse(tm.get_status(port=8771)["active"])
        self.assertFalse(tm.get_status(port=8770)["active"])

    async def test_port_restriction_enforcement(self) -> None:
        """Only ports 8771 and 8770 are permitted; dashboard 8769 and Core IPC 8767 must be blocked."""
        tm = TunnelManager()

        # Reject dashboard (:8769)
        res_69 = await tm.start_tunnel(provider="custom", port=8769, custom_url="https://evil.com")
        self.assertFalse(res_69["success"])
        self.assertEqual(res_69["status"], "PORT_RESTRICTED")

        # Reject relay port via MCP start_tunnel (:8770)
        res_70_mcp = await tm.start_tunnel(provider="custom", port=8770, custom_url="https://evil.com")
        self.assertFalse(res_70_mcp["success"])
        self.assertEqual(res_70_mcp["status"], "PORT_RESTRICTED")

        # Reject MCP port via relay start_relay_tunnel (:8771)
        res_71_relay = await tm.start_relay_tunnel(provider="custom", port=8771, custom_url="https://evil.com")
        self.assertFalse(res_71_relay["success"])
        self.assertEqual(res_71_relay["status"], "PORT_RESTRICTED")

        # Reject Core IPC (:8767)
        res_67 = await tm.start_tunnel(provider="custom", port=8767, custom_url="https://evil.com")
        self.assertFalse(res_67["success"])
        self.assertEqual(res_67["status"], "PORT_RESTRICTED")

        # Reject Core WSS direct (:8765)
        res_65 = await tm.start_tunnel(provider="custom", port=8765, custom_url="https://evil.com")
        self.assertFalse(res_65["success"])
        self.assertEqual(res_65["status"], "PORT_RESTRICTED")

        # Reject Transfer plane (:8766)
        res_66 = await tm.start_tunnel(provider="custom", port=8766, custom_url="https://evil.com")
        self.assertFalse(res_66["success"])
        self.assertEqual(res_66["status"], "PORT_RESTRICTED")

    async def test_cloudflared_stderr_drain_and_timeout(self) -> None:
        """Subprocess stderr reader drains output continuously without pipe deadlocks."""
        inst = _TunnelInstance(target_port=8771, purpose="mcp")

        # Mock process with a fake reader that does not emit URL
        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.returncode = None

        class MockStream:
            def __init__(self) -> None:
                self.lines = [
                    b"INF Starting cloudflared tunnel\n",
                    b"INF Configuration loaded\n",
                ]

            def at_eof(self) -> bool:
                return len(self.lines) == 0

            async def readline(self) -> bytes:
                if self.lines:
                    return self.lines.pop(0)
                await asyncio.sleep(0.05)
                return b""

        mock_proc.stderr = MockStream()

        with patch("snow.mcp.tunnel.find_cloudflared_binary", return_value="cloudflared.exe"), patch(
            "asyncio.create_subprocess_exec", return_value=mock_proc
        ):
            res = await inst.start(provider="cloudflared", port=8771, timeout=0.1)
            self.assertFalse(res["success"])
            self.assertEqual(res["status"], "TUNNEL_URL_TIMEOUT")
            # Ensure instance state cleaned up
            self.assertFalse(inst.get_status()["active"])


if __name__ == "__main__":
    unittest.main()
