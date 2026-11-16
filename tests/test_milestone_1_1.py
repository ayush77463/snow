"""Automated verification suite for Phase 1, Sub-Milestone 1.1: Python 3.13 Headless Core.

Test Coverage:
- Test A: Application startup and stderr diagnostics.
- Test B: Stdout isolation (zero bytes emitted to stdout).
- Test C: Usable IPv4 detection and exclusion of loopback/link-local/invalid addresses.
- Test D: Graceful shutdown and signal handling on Windows.
- Core configuration: Defaults, environment overrides, boundary checks, and strict validation.
- Server lifecycle: Start, run, stop, idempotent transitions, and clean restarts.
- Error resilience: Empty interface handling and socket fallback on psutil failure.
"""

import asyncio
import os
import signal
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

from snow.core.config import CoreConfig
from snow.core.network import (
    NetworkInterfaceInfo,
    _detect_via_socket_fallback,
    detect_usable_ipv4_addresses,
    is_usable_ipv4,
)
from snow.core.server import SnowCoreServer


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]



class TestNetworkDetection(unittest.TestCase):
    """Test C: Validate IPv4 detection, filtering rules, and resilience."""

    def test_usable_ipv4_valid_addresses(self):
        """Verify that standard private and public IPv4 addresses are accepted."""
        valid_ips = [
            "192.168.1.1",
            "192.168.43.1",   # Common mobile hotspot gateway
            "10.0.0.100",
            "172.16.0.50",
            "8.8.8.8",
        ]
        for ip in valid_ips:
            with self.subTest(ip=ip):
                self.assertTrue(is_usable_ipv4(ip), f"Expected {ip} to be usable.")

    def test_usable_ipv4_excludes_loopback(self):
        """Verify that loopback addresses (127.0.0.0/8) are strictly rejected."""
        loopback_ips = [
            "127.0.0.1",
            "127.0.0.2",
            "127.1.2.3",
            "127.255.255.254",
        ]
        for ip in loopback_ips:
            with self.subTest(ip=ip):
                self.assertFalse(is_usable_ipv4(ip), f"Loopback address {ip} must be excluded.")

    def test_usable_ipv4_excludes_link_local(self):
        """Verify that link-local addresses (169.254.0.0/16) are strictly rejected."""
        link_local_ips = [
            "169.254.0.1",
            "169.254.19.244",
            "169.254.203.60",
            "169.254.255.254",
        ]
        for ip in link_local_ips:
            with self.subTest(ip=ip):
                self.assertFalse(is_usable_ipv4(ip), f"Link-local address {ip} must be excluded.")

    def test_usable_ipv4_excludes_unusable_and_invalid(self):
        """Verify that multicast, unspecified (0.0.0.0), and invalid inputs are rejected."""
        invalid_inputs = [
            "0.0.0.0",
            "224.0.0.1",       # Multicast
            "255.255.255.255", # Broadcast
            "::1",             # IPv6 loopback
            "fe80::1",         # IPv6 link-local
            "invalid_ip",
            "999.999.999.999",
            "",
        ]
        for item in invalid_inputs:
            with self.subTest(item=item):
                self.assertFalse(is_usable_ipv4(item), f"Expected {item} to be rejected.")

    def test_detect_usable_ipv4_addresses_contract(self):
        """Verify that detect_usable_ipv4_addresses returns structured, valid interfaces."""
        interfaces = detect_usable_ipv4_addresses()
        self.assertIsInstance(interfaces, list)

        # On any machine (even offline), returned list must strictly contain valid addresses
        for iface in interfaces:
            self.assertIsInstance(iface, NetworkInterfaceInfo)
            self.assertIsInstance(iface.interface_name, str)
            self.assertTrue(len(iface.interface_name) > 0)
            self.assertTrue(
                is_usable_ipv4(iface.ip_address),
                f"Detected IP {iface.ip_address} failed usability check.",
            )
            self.assertFalse(iface.ip_address.startswith("127."))
            self.assertFalse(iface.ip_address.startswith("169.254."))
            self.assertIsInstance(iface.is_up, bool)

    def test_socket_fallback_contract(self):
        """Verify that the socket fallback function also returns valid interfaces."""
        interfaces = _detect_via_socket_fallback()
        self.assertIsInstance(interfaces, list)
        for iface in interfaces:
            self.assertTrue(is_usable_ipv4(iface.ip_address))
            self.assertFalse(iface.ip_address.startswith("127."))
            self.assertFalse(iface.ip_address.startswith("169.254."))

    def test_psutil_exception_triggers_socket_fallback(self):
        """Verify that an exception in psutil enumeration safely falls back to socket detection."""
        with patch("psutil.net_if_addrs", side_effect=OSError("Mock OS permission failure")):
            interfaces = detect_usable_ipv4_addresses()
            self.assertIsInstance(interfaces, list)
            for iface in interfaces:
                self.assertTrue(is_usable_ipv4(iface.ip_address))

    def test_empty_network_interfaces_handled_gracefully(self):
        """Verify that empty interface dictionaries return an empty list without error."""
        with patch("psutil.net_if_addrs", return_value={}), patch("psutil.net_if_stats", return_value={}):
            interfaces = detect_usable_ipv4_addresses()
            self.assertEqual(interfaces, [])


class TestCoreConfig(unittest.TestCase):
    """Validate centralized configuration defaults, environment overrides, and strict validation."""

    def test_default_config_values(self):
        """Verify frozen architectural defaults."""
        config = CoreConfig()
        self.assertEqual(config.bind_host, "0.0.0.0")
        self.assertEqual(config.port, 8765)
        self.assertEqual(config.log_level, "INFO")
        self.assertEqual(config.shutdown_timeout, 5.0)

    def test_from_env_overrides(self):
        """Verify that valid environment variables safely override defaults."""
        test_env = {
            "SNOW_BIND_HOST": "127.0.0.1",
            "SNOW_PORT": "9000",
            "SNOW_LOG_LEVEL": "DEBUG",
            "SNOW_SHUTDOWN_TIMEOUT": "10.0",
        }
        with patch.dict(os.environ, test_env, clear=False):
            config = CoreConfig.from_env()
            self.assertEqual(config.bind_host, "127.0.0.1")
            self.assertEqual(config.port, 9000)
            self.assertEqual(config.log_level, "DEBUG")
            self.assertEqual(config.shutdown_timeout, 10.0)

    def test_invalid_port_non_integer(self):
        """Verify that non-numeric port strings raise a clear ValueError."""
        with patch.dict(os.environ, {"SNOW_PORT": "not_a_port"}):
            with self.assertRaises(ValueError) as ctx:
                CoreConfig.from_env()
            self.assertIn("SNOW_PORT", str(ctx.exception))

    def test_invalid_port_out_of_bounds(self):
        """Verify that out-of-bounds ports (0, negative, > 65535) raise ValueError."""
        out_of_bounds = ["0", "-1", "65536", "70000"]
        for p in out_of_bounds:
            with self.subTest(port=p):
                with patch.dict(os.environ, {"SNOW_PORT": p}):
                    with self.assertRaises(ValueError) as ctx:
                        CoreConfig.from_env()
                    self.assertIn("SNOW_PORT", str(ctx.exception))

    def test_direct_constructor_port_validation(self):
        """Verify that direct constructor calls also enforce port boundaries."""
        with self.assertRaises(ValueError):
            CoreConfig(port=0)
        with self.assertRaises(ValueError):
            CoreConfig(port=65536)

    def test_invalid_shutdown_timeout(self):
        """Verify that non-numeric, zero, negative, or non-finite timeouts raise ValueError."""
        invalid_timeouts = ["0", "-5.0", "not_a_number", "nan", "inf", "-inf"]
        for t in invalid_timeouts:
            with self.subTest(timeout=t):
                with patch.dict(os.environ, {"SNOW_SHUTDOWN_TIMEOUT": t}):
                    with self.assertRaises(ValueError) as ctx:
                        CoreConfig.from_env()
                    self.assertIn("SNOW_SHUTDOWN_TIMEOUT", str(ctx.exception))

    def test_direct_constructor_timeout_validation(self):
        """Verify that direct constructor calls enforce positive finite timeout."""
        with self.assertRaises(ValueError):
            CoreConfig(shutdown_timeout=0.0)
        with self.assertRaises(ValueError):
            CoreConfig(shutdown_timeout=-2.5)

    def test_invalid_bind_host_empty_or_whitespace(self):
        """Verify that empty or whitespace-only bind hosts raise ValueError."""
        with patch.dict(os.environ, {"SNOW_BIND_HOST": "   "}):
            with self.assertRaises(ValueError) as ctx:
                CoreConfig.from_env()
            self.assertIn("SNOW_BIND_HOST", str(ctx.exception))

        with self.assertRaises(ValueError):
            CoreConfig(bind_host="")

    def test_invalid_log_level(self):
        """Verify that unrecognized log levels raise ValueError."""
        with patch.dict(os.environ, {"SNOW_LOG_LEVEL": "VERBOSE"}):
            with self.assertRaises(ValueError) as ctx:
                CoreConfig.from_env()
            self.assertIn("SNOW_LOG_LEVEL", str(ctx.exception))

        with self.assertRaises(ValueError):
            CoreConfig(log_level="NOT_A_LEVEL")


class TestSnowCoreServerLifecycle(unittest.TestCase):
    """Validate async server lifecycle, idempotence, and clean state transitions."""

    def _create_test_server(self) -> SnowCoreServer:
        config = CoreConfig(bind_host="127.0.0.1", port=_get_free_port(), tls_enabled=False)
        return SnowCoreServer(config=config)

    def test_server_startup_and_shutdown(self):
        """Verify start(), is_running, and stop() in an asyncio loop."""
        async def _test():
            server = self._create_test_server()
            self.assertFalse(server.is_running)

            await server.start()
            self.assertTrue(server.is_running)
            self.assertIsInstance(server.detected_interfaces, list)

            await server.stop()
            self.assertFalse(server.is_running)

        asyncio.run(_test())

    def test_repeated_start_is_idempotent(self):
        """Verify that repeated start() calls do not re-initialize an already running server."""
        async def _test():
            server = self._create_test_server()
            await server.start()
            self.assertTrue(server.is_running)

            # Second start() call should be a safe no-op
            await server.start()
            self.assertTrue(server.is_running)

            await server.stop()
            self.assertFalse(server.is_running)

        asyncio.run(_test())

    def test_repeated_stop_is_idempotent(self):
        """Verify that repeated stop() calls are safe no-ops."""
        async def _test():
            server = self._create_test_server()
            await server.start()
            await server.stop()
            self.assertFalse(server.is_running)

            # Second stop() call should exit cleanly
            await server.stop()
            self.assertFalse(server.is_running)

        asyncio.run(_test())

    def test_shutdown_request_after_stop(self):
        """Verify request_shutdown() is safe when called after server has already stopped."""
        async def _test():
            server = self._create_test_server()
            await server.start()
            await server.stop()
            self.assertFalse(server.is_running)

            # Requesting shutdown on an already stopped server is safe
            server.request_shutdown()
            self.assertFalse(server.is_running)

        asyncio.run(_test())

    def test_server_restart_after_stop(self):
        """Verify that a server can be cleanly restarted after being stopped."""
        async def _test():
            server = self._create_test_server()
            await server.start()
            self.assertTrue(server.is_running)
            await server.stop()
            self.assertFalse(server.is_running)

            # Restarting should clear previous shutdown event and transition to running
            await server.start()
            self.assertTrue(server.is_running)
            await server.stop()
            self.assertFalse(server.is_running)

        asyncio.run(_test())

    def test_server_run_and_request_shutdown(self):
        """Verify run() wait loop terminates cleanly when request_shutdown() is called."""
        async def _test():
            server = self._create_test_server()
            run_task = asyncio.create_task(server.run())

            # Yield control so server starts running
            while not server.is_running:
                await asyncio.sleep(0.05)

            self.assertTrue(server.is_running)

            # Signal shutdown
            server.request_shutdown()
            await asyncio.wait_for(run_task, timeout=5.0)

            self.assertFalse(server.is_running)

        asyncio.run(_test())


class TestSubprocessLifecycleAndStdoutIsolation(unittest.TestCase):
    """Validate Test A (Startup), Test B (Stdout Isolation), and Test D (Graceful Shutdown)."""

    def test_subprocess_startup_stdout_isolation_and_graceful_shutdown(self):
        """Launch snow.main as a subprocess, verify stderr startup logs, verify zero stdout, and cleanly shut down."""
        # Use the virtual environment's Python interpreter
        python_exe = sys.executable

        # Start subprocess in a new process group for clean signal dispatch on Windows
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        sub_env = {
            **os.environ,
            "SNOW_PORT": str(_get_free_port()),
            "SNOW_TRANSFER_PORT": str(_get_free_port()),
            "SNOW_TLS_ENABLED": "false",
        }
        proc = subprocess.Popen(
            [python_exe, "-m", "snow.main"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creationflags,
            env=sub_env,
        )

        captured_stderr_lines = []
        started_event_found = False

        try:
            # Synchronize on stderr output: read line-by-line until startup completes
            # Avoids arbitrary time-based sleep flakiness
            for _ in range(50):  # read up to 50 lines or until found
                line = proc.stderr.readline()
                if not line:
                    break
                captured_stderr_lines.append(line)
                if "started successfully" in line or "async core loop active" in line:
                    started_event_found = True
                    break

            # Test A: Verify successful startup diagnostics on stderr
            self.assertTrue(
                started_event_found,
                f"Server failed to log startup confirmation. Stderr captured:\n{''.join(captured_stderr_lines)}",
            )

            # Test D: Terminate using Windows-compatible signal
            if sys.platform == "win32":
                proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                proc.send_signal(signal.SIGINT)

            # Read remaining output and wait for clean termination
            stdout_data, remaining_stderr = proc.communicate(timeout=10)
            all_stderr = "".join(captured_stderr_lines) + remaining_stderr

            # Verify clean exit code (0)
            self.assertEqual(
                proc.returncode,
                0,
                f"Process exited with non-zero code {proc.returncode}. Stderr:\n{all_stderr}",
            )

            # Test B: Verify stdout isolation (STRICT RULE: zero bytes on stdout)
            self.assertEqual(
                stdout_data,
                "",
                f"CRITICAL VIOLATION: stdout received data! Captured:\n{stdout_data}",
            )

            # Test D: Verify clean shutdown message in stderr
            self.assertTrue(
                ("stopped cleanly" in all_stderr) or ("Shutdown complete" in all_stderr),
                f"Expected clean shutdown message in stderr. Stderr captured:\n{all_stderr}",
            )

        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()


if __name__ == "__main__":
    unittest.main()
