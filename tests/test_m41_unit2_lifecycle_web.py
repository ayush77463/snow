"""Unit 4.1.2 behavioral regression tests:
Core/Web single-instance lifecycle, IPC identity probing, dashboard reuse,
parallel deadline-bounded telemetry + caching, tray persistent loop reuse,
and headless Chromium CDP behavioral tests for Web UI polling & capture.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from contextlib import ExitStack
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import urllib.request

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
import psutil

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from snow import cli
from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer
from snow.daemon import (
    CREATE_NEW_PROCESS_GROUP,
    CoreDaemonManager,
    get_pid_file_path,
)
from snow.tray.app import SnowTrayApp
from snow.web.server import (
    DASHBOARD_SERVICE_ID,
    SnowWebServer,
    TELEMETRY_CACHE_MAX_ENTRIES,
    is_port_bound,
    probe_existing_dashboard,
    reuse_or_reject_existing_dashboard,
    run_dashboard,
)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _find_chromium_binary() -> str | None:
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        shutil.which("msedge"),
        shutil.which("chrome"),
        shutil.which("chromium"),
    ]
    for path in candidates:
        if path and Path(path).is_file():
            return str(path)
    return None


def _auth_client_session(client: TestClient, server: SnowWebServer):
    """Consume bootstrap token on a TestClient so protected routes work realistically."""
    return client.post("/api/auth/session", json={"token": server.bootstrap_token})


class TestUnit2DaemonLifecycle(unittest.IsolatedAsyncioTestCase):
    """Real cross-process lock, IPC identity, PID reuse, and fail-closed tests."""

    async def asyncSetUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmpdir.name) / "snow_data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.secret = "test-m41-unit2-secret-value-0123456789abcdef"
        self.secret_file = self.data_dir / ".ipc_secret"
        self.secret_file.write_text(self.secret, encoding="utf-8")
        self._env_patch = patch.dict(
            os.environ,
            {
                "SNOW_DATA_DIR": str(self.data_dir),
                "SNOW_IPC_SECRET": self.secret,
                "LOCALAPPDATA": str(Path(self._tmpdir.name) / "localappdata"),
            },
            clear=False,
        )
        self._env_patch.start()
        self._spawned_procs: list[subprocess.Popen[str]] = []
        self._managers_to_stop: list[CoreDaemonManager] = []

    async def asyncTearDown(self) -> None:
        for mgr in self._managers_to_stop:
            try:
                await mgr.stop_core(timeout=2.0)
            except Exception:
                pass
        for proc in self._spawned_procs:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3.0)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
        self._env_patch.stop()
        self._tmpdir.cleanup()

    async def test_concurrent_multiprocess_ensure_core_spawns_only_one_core(self) -> None:
        port = _find_free_port()
        spawn_log = self.data_dir / "spawns.log"
        core_stub = self.data_dir / "fake_core_runner.py"
        racer_script = self.data_dir / "racer_child.py"

        core_stub.write_text(
            f"""
import asyncio, os, signal, sys, time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, {repr(str(SRC_ROOT))})
from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer

SPAWN_LOG = {repr(str(spawn_log))}
PORT = {port}
SECRET_PATH = Path({repr(str(self.secret_file))})

async def _run():
    with open(SPAWN_LOG, "a", encoding="utf-8") as fh:
        fh.write(f"{{os.getpid()}}\\n")
        fh.flush()
    stop_event = asyncio.Event()
    cfg = CoreConfig(ipc_host="127.0.0.1", ipc_port=PORT, ipc_secret_path=str(SECRET_PATH))
    srv = SnowIpcServer(SimpleNamespace(), cfg)
    await srv.start()
    try:
        while not stop_event.is_set():
            await asyncio.sleep(0.1)
    finally:
        await srv.stop()

def _handle_term(signum, frame):
    raise SystemExit(0)

signal.signal(signal.SIGTERM, _handle_term)
if hasattr(signal, "SIGINT"):
    signal.signal(signal.SIGINT, _handle_term)

try:
    asyncio.run(_run())
except (KeyboardInterrupt, SystemExit):
    pass
""".strip(),
            encoding="utf-8",
        )

        # Configure snow_core command tag so CoreDaemonManager.is_process_snow_core recognizes this test stub.
        racer_script.write_text(
            f"""
import asyncio, json, os, sys
sys.path.insert(0, {repr(str(SRC_ROOT))})
from snow.daemon import CoreDaemonManager

async def _main():
    mgr = CoreDaemonManager(host="127.0.0.1", port={port}, spawn_timeout=12.0)
    mgr._get_core_command = lambda: [sys.executable, {repr(str(core_stub))}, "--m", "snow.main"]
    res = await mgr.ensure_core_running()
    print(json.dumps(res))

asyncio.run(_main())
""".strip(),
            encoding="utf-8",
        )

        # Ensure snow_core recognizer accepts python running fake_core_runner with snow.main arg:
        # is_process_snow_core checks for "snow.main" or "-m snow" in cmdline, which "--m snow.main" contains.
        child1 = subprocess.Popen(
            [sys.executable, str(racer_script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ.copy(),
        )
        child2 = subprocess.Popen(
            [sys.executable, str(racer_script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ.copy(),
        )
        mgr = CoreDaemonManager(host="127.0.0.1", port=port)
        self._managers_to_stop.append(mgr)
        try:
            out1, err1 = child1.communicate(timeout=25)
            out2, err2 = child2.communicate(timeout=25)

            self.assertEqual(child1.returncode, 0, f"child1 failed: {err1}")
            self.assertEqual(child2.returncode, 0, f"child2 failed: {err2}")

            res1 = json.loads(out1.strip().splitlines()[-1])
            res2 = json.loads(out2.strip().splitlines()[-1])
            self.assertTrue(res1.get("success"), res1)
            self.assertTrue(res2.get("success"), res2)

            spawn_lines = [line.strip() for line in spawn_log.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(spawn_lines), 1, f"Expected exactly 1 spawned Core, got {spawn_lines}")

            statuses = sorted([res1.get("status"), res2.get("status")])
            self.assertEqual(statuses, ["ALREADY_RUNNING", "STARTED"])
            self.assertEqual(res1.get("pid"), int(spawn_lines[0]))
            self.assertEqual(res2.get("pid"), int(spawn_lines[0]))

            pid_payload = json.loads(get_pid_file_path().read_text(encoding="utf-8"))
            self.assertEqual(pid_payload["pid"], int(spawn_lines[0]))
            self.assertEqual(pid_payload["port"], port)
            self.assertIsInstance(pid_payload["create_time"], float)
            self.assertTrue(pid_payload["exe"])
        finally:
            stop_res = await mgr.stop_core(timeout=3.0)
        self.assertTrue(stop_res.get("success"), stop_res)
        self.assertEqual(stop_res.get("status"), "STOPPED")
        self.assertFalse(get_pid_file_path().exists())

    async def test_pid_reuse_detected_refuses_termination_and_refuses_adoption(self) -> None:
        port = _find_free_port()
        unrelated = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self._spawned_procs.append(unrelated)
        actual_ct = float(psutil.Process(unrelated.pid).create_time())

        get_pid_file_path().write_text(
            json.dumps(
                {
                    "pid": unrelated.pid,
                    "create_time": actual_ct - 3600.0,
                    "exe": sys.executable,
                    "port": port,
                }
            ),
            encoding="utf-8",
        )

        mgr = CoreDaemonManager(host="127.0.0.1", port=port)
        self.assertFalse(mgr.is_process_snow_core(unrelated.pid, expected_create_time=actual_ct - 3600.0))

        # When IPC appears ready, stop_core must fail closed with UNVERIFIABLE_PROCESS and never kill unrelated proc.
        with patch.object(mgr, "is_ipc_ready", new=AsyncMock(return_value=True)):
            stop_res = await mgr.stop_core(timeout=1.0)
        self.assertFalse(stop_res.get("success"))
        self.assertEqual(stop_res.get("status"), "UNVERIFIABLE_PROCESS")
        self.assertIsNone(unrelated.poll(), "Unrelated reused-PID process must never be killed")

        # When IPC is offline, stop_core clears stale PID without killing unrelated process.
        stop_offline = await mgr.stop_core(timeout=1.0)
        self.assertTrue(stop_offline.get("success"))
        self.assertEqual(stop_offline.get("status"), "ALREADY_STOPPED")
        self.assertIsNone(unrelated.poll())

    async def test_foreign_listener_on_ipc_port_triggers_port_conflict(self) -> None:
        port = _find_free_port()
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.bind(("127.0.0.1", port))
        srv_sock.listen(5)
        stop_evt = threading.Event()

        def _accept_loop() -> None:
            srv_sock.settimeout(0.1)
            while not stop_evt.is_set():
                try:
                    conn, _ = srv_sock.accept()
                    try:
                        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                    finally:
                        conn.close()
                except socket.timeout:
                    continue
                except OSError:
                    break

        t = threading.Thread(target=_accept_loop, daemon=True)
        t.start()
        try:
            mgr = CoreDaemonManager(host="127.0.0.1", port=port)
            self.assertFalse(await mgr.is_ipc_ready(timeout=0.3))
            res = await mgr.ensure_core_running()
            self.assertFalse(res.get("success"))
            self.assertEqual(res.get("status"), "PORT_CONFLICT")
        finally:
            stop_evt.set()
            srv_sock.close()
            t.join(timeout=1.0)

    async def test_malformed_pid_metadata_and_legacy_pid_upgrade(self) -> None:
        port = _find_free_port()
        mgr = CoreDaemonManager(host="127.0.0.1", port=port)

        for corrupt in ["", "{not-json", '{"pid": "abc"}', '{"pid": -4}']:
            get_pid_file_path().write_text(corrupt, encoding="utf-8")
            self.assertIsNone(mgr.get_pid_metadata(), f"Accepted corrupt PID payload {corrupt!r}")
            self.assertEqual(mgr._last_pid_error, "MALFORMED_PID_METADATA")
            stop_res = await mgr.stop_core(timeout=0.5)
            self.assertFalse(stop_res.get("success"))
            self.assertEqual(stop_res.get("status"), "INVALID_PID_METADATA")

        # Legacy int PID alone pointing to unrelated live process cannot be stopped or killed.
        unrelated = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(20)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self._spawned_procs.append(unrelated)
        get_pid_file_path().write_text(str(unrelated.pid), encoding="utf-8")
        legacy_meta = mgr.get_pid_metadata()
        self.assertIsNotNone(legacy_meta)
        self.assertTrue(legacy_meta.get("legacy"))
        with patch.object(mgr, "is_ipc_ready", new=AsyncMock(return_value=True)):
            refused = await mgr.stop_core(timeout=0.5)
        self.assertFalse(refused.get("success"))
        self.assertEqual(refused.get("status"), "UNVERIFIABLE_PROCESS")
        self.assertIsNone(unrelated.poll())

        # Legacy int PID upgraded atomically when authenticated IPC ping succeeds + is_process_snow_core passes.
        cfg = CoreConfig(ipc_host="127.0.0.1", ipc_port=port, ipc_secret_path=str(self.secret_file))
        ipc = SnowIpcServer(SimpleNamespace(), cfg)
        await ipc.start()
        try:
            current_pid = os.getpid()
            get_pid_file_path().write_text(str(current_pid), encoding="utf-8")
            with patch.object(mgr, "is_process_snow_core", return_value=True):
                res = await mgr.ensure_core_running()
            self.assertTrue(res.get("success"), res)
            self.assertEqual(res.get("status"), "ALREADY_RUNNING")
            upgraded = json.loads(get_pid_file_path().read_text(encoding="utf-8"))
            self.assertEqual(upgraded["pid"], current_pid)
            self.assertEqual(upgraded["port"], port)
            self.assertIsInstance(upgraded["create_time"], float)
        finally:
            await ipc.stop()

    async def test_clear_pid_ownership_and_windows_creation_flags(self) -> None:
        port = _find_free_port()
        mgr = CoreDaemonManager(host="127.0.0.1", port=port, spawn_timeout=1.5)
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(20)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self._spawned_procs.append(proc)
        ct = float(psutil.Process(proc.pid).create_time())
        mgr._write_pid(proc.pid, port=port)

        # Losing / mismatched caller must never wipe an active healthy PID file.
        mgr._clear_pid(expected_pid=proc.pid + 12345, expected_create_time=ct)
        self.assertTrue(get_pid_file_path().exists())
        mgr._clear_pid(expected_pid=proc.pid, expected_create_time=ct - 500.0)
        self.assertTrue(get_pid_file_path().exists())
        mgr._clear_pid(expected_pid=proc.pid, expected_create_time=ct)
        self.assertFalse(get_pid_file_path().exists())

        if sys.platform == "win32":
            captured_kwargs: dict[str, object] = {}

            def _fake_popen(cmd, **kwargs):
                captured_kwargs.update(kwargs)
                mock_proc = MagicMock()
                mock_proc.pid = proc.pid
                mock_proc.poll.return_value = None
                return mock_proc

            with (
                patch.object(mgr, "is_ipc_ready", new=AsyncMock(side_effect=[False, False, True])),
                patch.object(mgr, "_is_port_occupied", new=AsyncMock(return_value=False)),
                patch("snow.daemon.subprocess.Popen", side_effect=_fake_popen),
                patch.object(mgr, "_write_pid"),
            ):
                spawn_res = await mgr.ensure_core_running()
            self.assertTrue(spawn_res.get("success"), spawn_res)
            flags = int(captured_kwargs.get("creationflags", 0))
            self.assertTrue(flags & CREATE_NEW_PROCESS_GROUP, f"Missing CREATE_NEW_PROCESS_GROUP in {flags:#x}")


class TestUnit2WebHealthAndReuse(unittest.IsolatedAsyncioTestCase):
    """Health endpoint security, foreign port fail-closed, and healthy dashboard reuse."""

    async def _raw_http_request(
        self,
        port: int,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, str]:
        def _do() -> tuple[int, str]:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3.0)
            try:
                conn.request(method, path, body=body, headers=headers or {})
                resp = conn.getresponse()
                raw = resp.read().decode("utf-8", errors="replace")
                return resp.status, raw
            finally:
                conn.close()

        return await asyncio.to_thread(_do)

    async def test_health_endpoint_host_validation_and_csrf_unaffected(self) -> None:
        port = _find_free_port()
        with patch("snow.mcp.tunnel.is_remote_ai_link_enabled", return_value=False):
            server = SnowWebServer(host="127.0.0.1", port=port, auto_open_browser=False)
            await server.start()
            try:
                for valid_host in [f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"]:
                    status, raw = await self._raw_http_request(port, "GET", "/api/health", headers={"Host": valid_host})
                    self.assertEqual(status, 200, f"Rejected valid Host {valid_host}: {raw}")
                    data = json.loads(raw)
                    self.assertEqual(data["service"], DASHBOARD_SERVICE_ID)
                    self.assertEqual(data["status"], "ok")
                    self.assertEqual(data["version"], CoreConfig.version)
                    self.assertEqual(data["pid"], os.getpid())
                    serialized = json.dumps(data).lower()
                    self.assertNotIn("token", serialized)
                    self.assertNotIn("secret", serialized)
                    self.assertNotIn("csrf", serialized)

                status, _ = await self._raw_http_request(port, "HEAD", "/api/health", headers={"Host": f"127.0.0.1:{port}"})
                self.assertEqual(status, 200)

                status, _ = await self._raw_http_request(
                    port, "POST", "/api/health", body=b"{}", headers={"Host": f"127.0.0.1:{port}"}
                )
                self.assertIn(status, (401, 403, 405))

                for evil_host in [
                    f"attacker.com:{port}",
                    f"evil.localhost:{port}",
                    f"localhost.evil.com:{port}",
                    f"127.0.0.1@evil.com:{port}",
                    "127.0.0.1:notaport",
                ]:
                    status, _ = await self._raw_http_request(port, "GET", "/api/health", headers={"Host": evil_host})
                    self.assertIn(status, (400, 403), f"Host {evil_host} must be rejected")

                # Unauthenticated health probes must not consume bootstrap token or create sessions.
                self.assertFalse(server.bootstrap_consumed)
                self.assertEqual(len(server._sessions), 0)

                # Protected routes still reject unauthenticated / cross-origin / missing-CSRF access.
                status, _ = await self._raw_http_request(port, "GET", "/api/devices", headers={"Host": f"127.0.0.1:{port}"})
                self.assertEqual(status, 401)

                status, _ = await self._raw_http_request(
                    port, "POST", "/api/media", body=b"{}", headers={"Host": f"127.0.0.1:{port}"}
                )
                self.assertEqual(status, 401)

                status, _ = await self._raw_http_request(
                    port,
                    "POST",
                    "/api/media",
                    body=b"{}",
                    headers={"Host": f"127.0.0.1:{port}", "Origin": "https://evil.example"},
                )
                self.assertEqual(status, 403)
            finally:
                await server.stop()

    async def test_foreign_http_server_fails_closed_without_spawning_core_or_web(self) -> None:
        port = _find_free_port()
        foreign_app = web.Application()
        response_payload = {"mode": "html"}

        async def _foreign_handler(req: web.Request) -> web.Response:
            if response_payload["mode"] == "html":
                return web.Response(text="<html>foreign service</html>", content_type="text/html")
            if response_payload["mode"] == "bogus_json":
                return web.json_response({"service": "other-service", "status": "ok"})
            return web.json_response(
                {
                    "service": DASHBOARD_SERVICE_ID,
                    "status": "ok",
                    "version": CoreConfig.version,
                    "pid": 999999,
                }
            )

        foreign_app.router.add_get("/api/health", _foreign_handler)
        foreign_app.router.add_get("/", _foreign_handler)
        runner = web.AppRunner(foreign_app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", port)
        await site.start()
        try:
            for mode in ("html", "bogus_json", "spoofed_pid"):
                response_payload["mode"] = mode
                with (
                    patch("snow.daemon.CoreDaemonManager.ensure_core_running", new=AsyncMock()) as ensure_mock,
                    patch.object(SnowWebServer, "start", new=AsyncMock()) as web_start_mock,
                ):
                    rc_dash = await asyncio.to_thread(run_dashboard, port, True)
                    rc_cli = await asyncio.to_thread(cli.run_web, port, True)

                self.assertEqual(rc_dash, 1, f"run_dashboard must fail closed on {mode}")
                self.assertEqual(rc_cli, 1, f"cli.run_web must fail closed on {mode}")
                ensure_mock.assert_not_called()
                web_start_mock.assert_not_called()

            # Foreign server itself remained undisturbed and still serving.
            status, _ = await self._raw_http_request(port, "GET", "/")
            self.assertEqual(status, 200)
        finally:
            await runner.cleanup()

    async def test_healthy_dashboard_reused_across_run_dashboard_and_run_web(self) -> None:
        port = _find_free_port()
        with patch("snow.mcp.tunnel.is_remote_ai_link_enabled", return_value=False):
            server = SnowWebServer(host="127.0.0.1", port=port, auto_open_browser=False)
            await server.start()
            try:
                with (
                    patch("snow.daemon.CoreDaemonManager.ensure_core_running", new=AsyncMock()) as ensure_mock,
                    patch.object(SnowWebServer, "start", new=AsyncMock()) as web_start_mock,
                ):
                    rc_dash = await asyncio.to_thread(run_dashboard, port, True)
                    rc_cli = await asyncio.to_thread(cli.run_web, port, True)

                self.assertEqual(rc_dash, 0)
                self.assertEqual(rc_cli, 0)
                ensure_mock.assert_not_called()
                web_start_mock.assert_not_called()
                self.assertFalse(server.bootstrap_consumed)

                with patch("snow.web.server.webbrowser.open", return_value=True) as wb_ok:
                    rc_open = await asyncio.to_thread(reuse_or_reject_existing_dashboard, "127.0.0.1", port, False)
                self.assertEqual(rc_open, 0)
                wb_ok.assert_called_once_with(f"http://127.0.0.1:{port}")

                with patch("snow.web.server.webbrowser.open", return_value=False):
                    rc_fail = await asyncio.to_thread(reuse_or_reject_existing_dashboard, "127.0.0.1", port, False)
                self.assertEqual(rc_fail, 1)
            finally:
                await server.stop()


class TestUnit2TelemetryAndCache(unittest.IsolatedAsyncioTestCase):
    """Telemetry parallelism, overall deadline enforcement, and bounded TTL cache."""

    async def test_devices_parallel_deadline_and_stalled_device_isolation(self) -> None:
        bridge = MagicMock()
        bridge.daemon_manager = MagicMock()
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=True)
        bridge.list_devices = AsyncMock(
            return_value={
                "success": True,
                "status": "SUCCESS",
                "data": {
                    "devices": [
                        {"device_id": "phone-fast-1", "platform": "android", "is_connected": True},
                        {"device_id": "phone-fast-2", "platform": "android", "is_connected": True},
                        {"device_id": "phone-stalled", "platform": "android", "is_connected": True},
                    ]
                },
            }
        )
        bridge.list_discovered_peers = AsyncMock(return_value={"success": True, "data": {"peers": []}})

        stalled_cancelled = asyncio.Event()

        async def _fake_battery(device_id: str):
            if device_id == "phone-stalled":
                try:
                    await asyncio.sleep(5.0)
                except asyncio.CancelledError:
                    stalled_cancelled.set()
                    raise
            await asyncio.sleep(0.05)
            level = 81 if device_id == "phone-fast-1" else 64
            return {"success": True, "data": {"battery": level, "charging": True}}

        bridge.android_battery = AsyncMock(side_effect=_fake_battery)
        server = SnowWebServer(host="127.0.0.1", port=_find_free_port(), bridge=bridge, auto_open_browser=False)

        async with TestClient(TestServer(server._build_app())) as client:
            auth_resp = await _auth_client_session(client, server)
            self.assertEqual(auth_resp.status, 200)

            started = time.monotonic()
            resp = await client.get("/api/devices")
            elapsed = time.monotonic() - started
            payload = await resp.json()

        self.assertEqual(resp.status, 200)
        self.assertLess(elapsed, 2.2, f"/api/devices exceeded deadline bound: {elapsed:.2f}s")
        self.assertTrue(stalled_cancelled.is_set(), "Stalled telemetry task was not cancelled on timeout")

        by_id = {d["device_id"]: d for d in payload["devices"]}
        self.assertEqual(by_id["phone-fast-1"]["telemetry_status"], "live")
        self.assertEqual(by_id["phone-fast-1"]["telemetry"]["battery"], 81)
        self.assertEqual(by_id["phone-fast-2"]["telemetry_status"], "live")
        self.assertEqual(by_id["phone-fast-2"]["telemetry"]["battery"], 64)
        self.assertEqual(by_id["phone-stalled"]["telemetry_status"], "unavailable")
        self.assertFalse(by_id["phone-stalled"].get("telemetry"))

    async def test_status_runs_telemetry_and_ipc_checks_concurrently_under_deadline(self) -> None:
        bridge = MagicMock()
        bridge.daemon_manager = MagicMock()

        async def _slow_ipc(*, timeout: float = 0.2):
            await asyncio.sleep(0.55)
            return True

        async def _slow_sys_info():
            await asyncio.sleep(0.55)
            return {"success": True, "data": {"os": "Windows", "ram_gb": 16}}

        async def _slow_battery():
            await asyncio.sleep(0.55)
            return {"success": True, "data": {"percent": 90, "plugged": True}}

        async def _slow_usb():
            await asyncio.sleep(0.55)
            return {"adb_available": True, "device_count": 0}

        bridge.daemon_manager.is_ipc_ready = AsyncMock(side_effect=_slow_ipc)
        bridge.windows_system_info = AsyncMock(side_effect=_slow_sys_info)
        bridge.windows_battery = AsyncMock(side_effect=_slow_battery)

        server = SnowWebServer(host="127.0.0.1", port=_find_free_port(), bridge=bridge, auto_open_browser=False)

        def _slow_ips():
            time.sleep(0.55)
            return ["192.168.1.10"]

        with (
            patch.object(server, "_get_cached_usb_status", AsyncMock(side_effect=_slow_usb)),
            patch("snow.core.network.get_active_ip_addresses", side_effect=_slow_ips),
        ):
            async with TestClient(TestServer(server._build_app())) as client:
                await _auth_client_session(client, server)
                t0 = time.monotonic()
                resp = await client.get("/api/status")
                elapsed = time.monotonic() - t0
                body = await resp.json()

                self.assertEqual(resp.status, 200)
                self.assertTrue(body["success"])
                # Serial 5 * 0.55s = 2.75s; parallel must finish cleanly well under 1.5s.
                self.assertLess(elapsed, 1.5, f"/api/status appears serialized ({elapsed:.2f}s)")

                # Verify overall deadline also protects against a multi-second hang.
                async def _hung_sys_info():
                    await asyncio.sleep(4.5)
                    return {"success": True, "data": {}}

                bridge.windows_system_info = AsyncMock(side_effect=_hung_sys_info)
                with (
                    patch.object(server, "_get_cached_usb_status", AsyncMock(return_value={"adb_available": True})),
                    patch("snow.core.network.get_active_ip_addresses", return_value=["127.0.0.1"]),
                ):
                    t0 = time.monotonic()
                    resp2 = await client.get("/api/status")
                    elapsed2 = time.monotonic() - t0
                self.assertEqual(resp2.status, 200)
                self.assertLess(elapsed2, 2.2)

    async def test_telemetry_cache_ttl_singleflight_bounded_lru_and_error_skip(self) -> None:
        bridge = MagicMock()
        bridge.daemon_manager = None
        bridge.list_devices = AsyncMock(
            return_value={
                "success": True,
                "status": "SUCCESS",
                "data": {"devices": [{"device_id": "phone-1", "platform": "android", "is_connected": True}]},
            }
        )
        bridge.list_discovered_peers = AsyncMock(return_value={"success": True, "data": {"peers": []}})

        call_counter = 0

        async def _bat_probe(device_id: str):
            nonlocal call_counter
            call_counter += 1
            await asyncio.sleep(0.05)
            return {"success": True, "data": {"battery": 75 + call_counter}}

        bridge.android_battery = AsyncMock(side_effect=_bat_probe)
        server = SnowWebServer(host="127.0.0.1", port=_find_free_port(), bridge=bridge, auto_open_browser=False)

        async with TestClient(TestServer(server._build_app())) as client:
            await _auth_client_session(client, server)

            # Two concurrent requests for same uncached device coalesce into 1 probe via singleflight lock.
            r1, r2 = await asyncio.gather(client.get("/api/devices"), client.get("/api/devices"))
            p1, p2 = await r1.json(), await r2.json()
            self.assertEqual(call_counter, 1)
            statuses = {p1["devices"][0]["telemetry_status"], p2["devices"][0]["telemetry_status"]}
            self.assertTrue(statuses <= {"live", "cached"})

            # Next hit within TTL returns cached telemetry with telemetry_cached=True.
            r3 = await client.get("/api/devices")
            p3 = await r3.json()
            self.assertEqual(call_counter, 1)
            self.assertEqual(p3["devices"][0]["telemetry_status"], "cached")
            self.assertTrue(p3["devices"][0].get("telemetry_cached"))

            # Expire cache timestamp manually -> next call probes live again.
            old_ts, old_val = server._device_telemetry_cache["phone-1"]
            server._device_telemetry_cache["phone-1"] = (old_ts - 10.0, old_val)
            r4 = await client.get("/api/devices")
            p4 = await r4.json()
            self.assertEqual(call_counter, 2)
            self.assertEqual(p4["devices"][0]["telemetry_status"], "live")

        # Bounded LRU max size check.
        server._device_telemetry_cache = OrderedDict()
        for idx in range(TELEMETRY_CACHE_MAX_ENTRIES + 10):
            server._store_cached_telemetry(f"dev-{idx}", {"battery": 50})
        self.assertEqual(len(server._device_telemetry_cache), TELEMETRY_CACHE_MAX_ENTRIES)
        self.assertNotIn("dev-0", server._device_telemetry_cache)
        self.assertIn(f"dev-{TELEMETRY_CACHE_MAX_ENTRIES + 9}", server._device_telemetry_cache)

        # Errors must never be cached.
        server._device_telemetry_cache.clear()
        bridge.android_battery = AsyncMock(side_effect=RuntimeError("boom"))
        tel, st, _ = await server._fetch_device_telemetry(
            "phone-err", asyncio.Semaphore(4), time.monotonic() + 2.0
        )
        self.assertIsNone(tel)
        self.assertEqual(st, "unavailable")
        self.assertNotIn("phone-err", server._device_telemetry_cache)


class TestUnit2TrayMonitorLoop(unittest.TestCase):
    """Verify persistent monitor asyncio loop reuse, error isolation, shutdown, and flags."""

    def test_background_monitor_single_loop_identity_and_clean_stop(self) -> None:
        bridge = MagicMock()
        seen_loop_ids: list[int] = []
        tick_counter = 0
        three_ticks_done = threading.Event()

        async def _fake_call(method: str, params=None):
            nonlocal tick_counter
            if method == "get_device_status":
                tick_counter += 1
                seen_loop_ids.append(id(asyncio.get_running_loop()))
                if tick_counter == 2:
                    raise RuntimeError("transient IPC error on tick 2")
                if tick_counter >= 3:
                    three_ticks_done.set()
                return {"success": True, "data": {"devices": []}}
            return {"success": True}

        bridge.call = AsyncMock(side_effect=_fake_call)
        core_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        core_sock.bind(("127.0.0.1", 0))
        core_sock.listen(5)
        fake_port = int(core_sock.getsockname()[1])
        dm = MagicMock()
        dm.get_tracked_pid.return_value = None
        db = MagicMock()
        db.list_paired_devices.return_value = []
        tray = SnowTrayApp(core_port=fake_port, daemon_manager=dm, db_manager=db)
        tray.bridge = bridge

        orig_new_loop = asyncio.new_event_loop
        created_loops: list[asyncio.AbstractEventLoop] = []

        def _counting_new_loop():
            lp = orig_new_loop()
            created_loops.append(lp)
            return lp

        try:
            with (
                patch.object(tray._stop_event, "wait", side_effect=lambda timeout=None: tray._stop_event.is_set()),
                patch("snow.tray.app.asyncio.new_event_loop", side_effect=_counting_new_loop),
            ):
                tray._status_thread = threading.Thread(target=tray._background_monitor, daemon=True)
                tray._status_thread.start()
                self.assertTrue(three_ticks_done.wait(timeout=5.0), "Monitor did not survive past tick 2 error")
                tray.stop()
        finally:
            core_sock.close()

        self.assertEqual(len(created_loops), 1, "Monitor must create exactly one persistent event loop")
        self.assertTrue(created_loops[0].is_closed(), "Monitor loop must be closed cleanly on stop()")
        self.assertGreaterEqual(len(seen_loop_ids), 3)
        self.assertEqual(len(set(seen_loop_ids)), 1, f"Loop ID changed across ticks: {seen_loop_ids}")
        self.assertIsNone(tray._status_thread)

    def test_tray_dashboard_worker_uses_new_process_group_on_win32(self) -> None:
        if sys.platform != "win32":
            self.skipTest("Windows creationflags check applies only on win32")

        tray = SnowTrayApp(daemon_manager=MagicMock(), db_manager=MagicMock())
        popen_kwargs: dict[str, object] = {}

        def _fake_popen(cmd, **kwargs):
            popen_kwargs.update(kwargs)
            m = MagicMock()
            m.poll.return_value = 0
            return m

        with (
            patch.object(tray, "is_dashboard_listening", side_effect=[False, True]),
            patch("snow.tray.app.webbrowser.open", return_value=True),
            patch("subprocess.Popen", side_effect=_fake_popen),
        ):
            tray._dashboard_startup_worker()

        flags = int(popen_kwargs.get("creationflags", 0))
        self.assertTrue(flags & CREATE_NEW_PROCESS_GROUP, f"Missing CREATE_NEW_PROCESS_GROUP in {flags:#x}")


class _CdpClient:
    """Minimal asyncio Chrome DevTools Protocol client over websockets."""

    def __init__(self, ws_url: str) -> None:
        self._ws_url = ws_url
        self._ws = None
        self._next_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self.exceptions: list[str] = []
        self.console_errors: list[str] = []
        self._reader_task: asyncio.Task | None = None

    async def connect(self) -> None:
        import websockets

        self._ws = await websockets.connect(self._ws_url, max_size=16 * 1024 * 1024)
        self._reader_task = asyncio.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        assert self._ws is not None
        try:
            async for raw in self._ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        if "error" in msg:
                            fut.set_exception(RuntimeError(f"CDP error: {msg['error']}"))
                        else:
                            fut.set_result(msg.get("result", {}))
                else:
                    method = msg.get("method")
                    params = msg.get("params", {})
                    if method == "Runtime.exceptionThrown":
                        self.exceptions.append(json.dumps(params))
                    elif method == "Runtime.consoleAPICalled" and params.get("type") == "error":
                        self.console_errors.append(json.dumps(params.get("args", [])))
        except asyncio.CancelledError:
            raise
        except Exception:
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(RuntimeError("CDP disconnected"))

    async def call(self, method: str, params: dict | None = None) -> dict:
        assert self._ws is not None
        self._next_id += 1
        cid = self._next_id
        fut = asyncio.get_running_loop().create_future()
        self._pending[cid] = fut
        await self._ws.send(json.dumps({"id": cid, "method": method, "params": params or {}}))
        return await asyncio.wait_for(fut, timeout=10.0)

    async def eval(self, expression: str):
        res = await self.call(
            "Runtime.evaluate",
            {
                "expression": expression,
                "awaitPromise": True,
                "returnByValue": True,
            },
        )
        if "exceptionDetails" in res:
            raise AssertionError(f"JS exception during evaluate: {res['exceptionDetails']}")
        return res.get("result", {}).get("value")

    async def close(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._ws is not None:
            await self._ws.close()


class TestUnit2BrowserPollingCDP(unittest.IsolatedAsyncioTestCase):
    """Execute actual src/snow/web/static/app.js in headless Chromium V8 DOM via CDP."""

    async def test_app_js_polling_backoff_visibility_screen_capture_and_unload(self) -> None:
        browser_bin = _find_chromium_binary()
        if not browser_bin:
            self.skipTest("No Chrome/Edge browser binary available for CDP verification")

        static_dir = PROJECT_ROOT / "src" / "snow" / "web" / "static"
        app = web.Application()
        app.router.add_get("/", lambda req: web.FileResponse(static_dir / "index.html"))
        app.router.add_static("/static", static_dir)
        # Fallback handlers if any native unstubbed asset probe hits server
        app.router.add_route("*", "/{tail:.*}", lambda req: web.json_response({"success": True}))

        runner = web.AppRunner(app)
        await runner.setup()
        port = _find_free_port()
        site = web.TCPSite(runner, "127.0.0.1", port)
        await site.start()

        user_data_dir = tempfile.mkdtemp(prefix="snow_cdp_u2_")
        browser_proc: subprocess.Popen | None = None
        cdp: _CdpClient | None = None
        try:
            browser_proc = subprocess.Popen(
                [
                    browser_bin,
                    "--headless=new",
                    "--remote-debugging-port=0",
                    f"--user-data-dir={user_data_dir}",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-gpu",
                    "about:blank",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Wait up to 8s for DevToolsActivePort written by Chromium.
            devtools_port = None
            devtools_file = Path(user_data_dir) / "DevToolsActivePort"
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline:
                if devtools_file.exists():
                    lines = devtools_file.read_text(encoding="utf-8").splitlines()
                    if lines and lines[0].strip().isdigit():
                        devtools_port = int(lines[0].strip())
                        break
                await asyncio.sleep(0.1)
            self.assertIsNotNone(devtools_port, "Headless Chromium did not publish DevToolsActivePort")

            with urllib.request.urlopen(f"http://127.0.0.1:{devtools_port}/json/list", timeout=3.0) as resp:
                targets = json.loads(resp.read().decode("utf-8"))
            page_ws = next(t["webSocketDebuggerUrl"] for t in targets if t.get("type") == "page")

            cdp = _CdpClient(page_ws)
            await cdp.connect()
            await cdp.call("Page.enable")
            await cdp.call("Runtime.enable")

            harness_script = r"""
(() => {
    // Virtual timer + clock harness inside real browser DOM before app.js loads
    let nowMs = 1_700_000_000_000;
    Date.now = () => nowMs;
    let nextTimerId = 1;
    const timeouts = new Map();
    const intervals = new Map();

    const origSetTimeout = window.setTimeout.bind(window);
    const origClearTimeout = window.clearTimeout.bind(window);
    const origSetInterval = window.setInterval.bind(window);
    const origClearInterval = window.clearInterval.bind(window);

    window.setTimeout = (fn, delay = 0, ...args) => {
        const ms = Number(delay) || 0;
        // Let Promise microtask drains with 0ms use real 0ms or tracked virtual queue
        const id = nextTimerId++;
        timeouts.set(id, { id, delay: ms, fireAt: nowMs + ms, fn, args });
        return id;
    };
    window.clearTimeout = (id) => {
        timeouts.delete(id);
        origClearTimeout(id);
    };
    window.setInterval = (fn, delay = 0, ...args) => {
        const ms = Math.max(1, Number(delay) || 0);
        const id = nextTimerId++;
        intervals.set(id, { id, delay: ms, fireAt: nowMs + ms, fn, args });
        return id;
    };
    window.clearInterval = (id) => {
        intervals.delete(id);
        origClearInterval(id);
    };

    let mockHidden = false;
    Object.defineProperty(document, "hidden", {
        configurable: true,
        get: () => mockHidden,
    });

    const fetchLog = [];
    const mockState = {
        statusOk: true,
        daemonOnline: true,
        captureConsentRequired: true,
        captureLatestFilename: "",
    };

    window.fetch = async (url, opts = {}) => {
        const urlStr = String(url);
        fetchLog.push({ url: urlStr, method: (opts && opts.method) || "GET", t: nowMs });
        if (urlStr.startsWith("/api/status")) {
            if (!mockState.statusOk) {
                return new Response(JSON.stringify({ success: false, daemon_online: false }), {
                    status: 500,
                    headers: { "Content-Type": "application/json" },
                });
            }
            return new Response(
                JSON.stringify({
                    success: true,
                    daemon_online: mockState.daemonOnline,
                    csrf_token: "test-csrf",
                    snow_id: "SNW-TEST",
                    device_id: "local",
                    device_name: "TestHost (Host)",
                    telemetry: {},
                }),
                { status: 200, headers: { "Content-Type": "application/json" } }
            );
        }
        if (urlStr.startsWith("/api/system/status")) {
            return new Response(JSON.stringify({ success: true, is_paused: false }), {
                status: 200,
                headers: { "Content-Type": "application/json" },
            });
        }
        if (urlStr.startsWith("/api/federation/grants")) {
            return new Response(JSON.stringify({ success: true, grants: [] }), {
                status: 200,
                headers: { "Content-Type": "application/json" },
            });
        }
        if (urlStr.startsWith("/api/devices")) {
            return new Response(
                JSON.stringify({
                    success: true,
                    devices: [
                        { device_id: "local", is_local: true, is_connected: true, platform: "windows" },
                        {
                            device_id: "phone-1",
                            device_name: "Pixel Phone",
                            platform: "android",
                            device_type: "phone",
                            is_connected: true,
                            telemetry: { battery: 88 },
                        },
                    ],
                }),
                { status: 200, headers: { "Content-Type": "application/json" } }
            );
        }
        if (urlStr.startsWith("/api/approvals") || urlStr.startsWith("/api/screen/stream")) {
            return new Response(JSON.stringify({ success: true, pending: [], streaming: false, active: false }), {
                status: 200,
                headers: { "Content-Type": "application/json" },
            });
        }
        if (urlStr.startsWith("/api/screen/status")) {
            return new Response(JSON.stringify({ success: true, streaming: false, active: false }), {
                status: 200,
                headers: { "Content-Type": "application/json" },
            });
        }
        if (urlStr.startsWith("/api/screen/capture-phone")) {
            if (mockState.captureConsentRequired) {
                return new Response(
                    JSON.stringify({ success: false, status: "SCREEN_CAPTURE_CONSENT_REQUIRED", error: "SCREEN_CAPTURE_CONSENT_REQUIRED" }),
                    { status: 200, headers: { "Content-Type": "application/json" } }
                );
            }
            return new Response(JSON.stringify({ success: true, file_name: "cap_direct.png" }), {
                status: 200,
                headers: { "Content-Type": "application/json" },
            });
        }
        if (urlStr.startsWith("/api/screen/capture-latest")) {
            if (mockState.captureLatestFilename) {
                return new Response("PNG", {
                    status: 200,
                    headers: { "X-Snow-Filename": mockState.captureLatestFilename },
                });
            }
            return new Response(JSON.stringify({ success: false }), {
                status: 404,
                headers: { "Content-Type": "application/json" },
            });
        }
        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    };

    const yieldTurn = () => new Promise(resolve => {
        const mc = new MessageChannel();
        mc.port1.onmessage = () => resolve();
        mc.port2.postMessage(null);
    });

    window.__TEST_HARNESS__ = {
        getState: () => mockState,
        realSleep: async (ms = 10) => {
            const ticks = Math.max(6, Math.ceil(Number(ms || 10) / 4));
            for (let i = 0; i < ticks; i++) {
                await yieldTurn();
            }
        },
        setHidden: (val) => {
            mockHidden = Boolean(val);
            document.dispatchEvent(new Event("visibilitychange"));
        },
        dispatchUnload: (evtName) => {
            window.dispatchEvent(new Event(evtName));
        },
        getPendingTimeouts: () => Array.from(timeouts.values()).map(t => ({ id: t.id, delay: t.delay, fireAt: t.fireAt })),
        getPendingIntervalCount: () => intervals.size,
        getFetchCount: (prefix) => fetchLog.filter(f => f.url.startsWith(prefix)).length,
        clearFetchLog: () => { fetchLog.length = 0; },
        flushMicrotasks: async () => {
            for (let i = 0; i < 12; i++) {
                await Promise.resolve();
            }
        },
        stepNextTimeout: async (minDelay = 100) => {
            const list = Array.from(timeouts.values()).filter(t => t.delay >= minDelay).sort((a, b) => a.fireAt - b.fireAt);
            if (!list.length) return null;
            const next = list[0];
            nowMs = next.fireAt;
            timeouts.delete(next.id);
            next.fn(...next.args);
            for (let i = 0; i < 18; i++) {
                await yieldTurn();
            }
            return next.delay;
        },
        advanceMs: async (ms) => {
            const target = nowMs + ms;
            while (true) {
                const list = Array.from(timeouts.values()).filter(t => t.delay >= 100 && t.fireAt <= target).sort((a, b) => a.fireAt - b.fireAt);
                if (!list.length) break;
                const next = list[0];
                nowMs = next.fireAt;
                timeouts.delete(next.id);
                next.fn(...next.args);
                for (let i = 0; i < 14; i++) {
                    await yieldTurn();
                }
            }
            nowMs = target;
            for (let i = 0; i < 8; i++) {
                await yieldTurn();
            }
        },
    };
})();
"""
            await cdp.call("Page.addScriptToEvaluateOnNewDocument", {"source": harness_script})
            await cdp.call("Page.navigate", {"url": f"http://127.0.0.1:{port}/"})
            # Allow DOMContentLoaded and initial async initSession/startDashboard microtasks to settle.
            await asyncio.sleep(0.5)
            await cdp.eval("window.__TEST_HARNESS__.flushMicrotasks()")

            # 1. Verify initial boot succeeded with single scheduled 3000ms timer and zero setIntervals.
            interval_count = await cdp.eval("window.__TEST_HARNESS__.getPendingIntervalCount()")
            self.assertEqual(interval_count, 0, "Expected zero raw setInterval pollers during normal steady state")
            timeouts = await cdp.eval("window.__TEST_HARNESS__.getPendingTimeouts().filter(t => t.delay >= 1000)")
            self.assertEqual(len(timeouts), 1, f"Expected 1 scheduled poll timeout, got {timeouts}")
            self.assertEqual(timeouts[0]["delay"], 3000)

            # 2. Verify offline exponential backoff sequence: 3000 -> 6000 -> 12000 -> 15000 -> 15000 -> reset 3000
            await cdp.eval("window.__TEST_HARNESS__.getState().statusOk = false;")
            # First scheduled 3000ms timer fires failure #1, then backoff schedules 3000 -> 6000 -> 12000 -> 15000 -> 15000
            initial_tick = await cdp.eval("window.__TEST_HARNESS__.stepNextTimeout(1000)")
            self.assertEqual(initial_tick, 3000)
            observed_delays = []
            for _ in range(5):
                fired_delay = await cdp.eval("window.__TEST_HARNESS__.stepNextTimeout(1000)")
                observed_delays.append(fired_delay)
            self.assertEqual(observed_delays, [3000, 6000, 12000, 15000, 15000])

            # Next timer queued after 5 failures is capped at 15000; recover server and verify reset to 3000!
            await cdp.eval("window.__TEST_HARNESS__.getState().statusOk = true;")
            await cdp.eval("window.__TEST_HARNESS__.stepNextTimeout(1000)")
            next_after_recovery = await cdp.eval(
                "window.__TEST_HARNESS__.getPendingTimeouts().filter(t => t.delay >= 1000).map(t => t.delay)"
            )
            self.assertEqual(next_after_recovery, [3000], f"Expected reset to 3000ms after recovery, got {next_after_recovery}")

            # 3. Verify visibility pause stops all background fetches and resume runs single non-overlapping refresh.
            await cdp.eval("window.__TEST_HARNESS__.setHidden(true);")
            hidden_timers = await cdp.eval(
                "window.__TEST_HARNESS__.getPendingTimeouts().filter(t => t.delay >= 1000)"
            )
            self.assertEqual(len(hidden_timers), 0, "Hidden tab must clear pending poll timers")
            await cdp.eval("window.__TEST_HARNESS__.clearFetchLog();")
            await cdp.eval("window.__TEST_HARNESS__.advanceMs(20000);")
            hidden_fetches = await cdp.eval("window.__TEST_HARNESS__.getFetchCount('/api/status')")
            self.assertEqual(hidden_fetches, 0, "Hidden tab must perform 0 /api/status fetches")

            # Rapid visible/hidden toggles -> only 1 refresh + 1 pending timer on visible settle.
            await cdp.eval("""
                (async () => {
                    window.__TEST_HARNESS__.clearFetchLog();
                    window.__TEST_HARNESS__.setHidden(false);
                    window.__TEST_HARNESS__.setHidden(true);
                    window.__TEST_HARNESS__.setHidden(false);
                    await window.__TEST_HARNESS__.flushMicrotasks();
                    await window.__TEST_HARNESS__.realSleep(20);
                })();
            """)
            await asyncio.sleep(0.15)
            resume_fetches = await cdp.eval("window.__TEST_HARNESS__.getFetchCount('/api/status')")
            self.assertEqual(resume_fetches, 1, f"Rapid visibility toggle caused duplicate refreshes: {resume_fetches}")
            resume_timers = await cdp.eval("window.__TEST_HARNESS__.getPendingTimeouts().filter(t => t.delay >= 1000)")
            self.assertEqual(len(resume_timers), 1)

            # 4. Screen capture polling lifecycle: start, pause on hide, cancel duplicate, complete, timeout, unload.
            await cdp.eval("""
                (async () => {
                    window.__TEST_HARNESS__.clearFetchLog();
                    const btn = document.getElementById("btn-qa-screen");
                    btn.click();
                    await window.__TEST_HARNESS__.realSleep(30);
                })();
            """)
            await asyncio.sleep(0.15)
            cap_timers = await cdp.eval("window.__TEST_HARNESS__.getPendingTimeouts().filter(t => t.delay === 1000)")
            self.assertEqual(len(cap_timers), 1, f"Expected 1 screen capture timer, got {cap_timers}")

            # Duplicate trigger replaces old timer rather than stacking 2 timers.
            await cdp.eval("""
                (async () => {
                    document.getElementById("btn-qa-screen").click();
                    await window.__TEST_HARNESS__.realSleep(30);
                })();
            """)
            await asyncio.sleep(0.15)
            cap_timers_after_dup = await cdp.eval("window.__TEST_HARNESS__.getPendingTimeouts().filter(t => t.delay === 1000)")
            self.assertEqual(len(cap_timers_after_dup), 1, "Duplicate screen capture trigger created multiple timers")

            # Hidden pauses screen capture polling.
            await cdp.eval("window.__TEST_HARNESS__.setHidden(true); window.__TEST_HARNESS__.clearFetchLog();")
            await cdp.eval("window.__TEST_HARNESS__.advanceMs(5000);")
            hidden_cap_fetches = await cdp.eval("window.__TEST_HARNESS__.getFetchCount('/api/screen/capture-latest')")
            self.assertEqual(hidden_cap_fetches, 0, "Screen capture polling kept running while hidden")

            # Visible resumes and completes on X-Snow-Filename.
            await cdp.eval("window.__TEST_HARNESS__.getState().captureLatestFilename = 'cap_done.png';")
            await cdp.eval("window.__TEST_HARNESS__.setHidden(false);")
            await asyncio.sleep(0.15)
            cap_timers_after_done = await cdp.eval("window.__TEST_HARNESS__.getPendingTimeouts().filter(t => t.delay === 1000)")
            self.assertEqual(len(cap_timers_after_done), 0, "Screen capture timer leaked after capture completed")

            # Verify 25s screen-capture timeout stops cleanly without leaving leaked timers.
            await cdp.eval("""
                (async () => {
                    window.__TEST_HARNESS__.getState().captureLatestFilename = '';
                    document.getElementById("btn-qa-screen").click();
                    await window.__TEST_HARNESS__.realSleep(30);
                })();
            """)
            await cdp.eval("window.__TEST_HARNESS__.advanceMs(26000);")
            cap_timers_after_timeout = await cdp.eval("window.__TEST_HARNESS__.getPendingTimeouts().filter(t => t.delay === 1000)")
            self.assertEqual(len(cap_timers_after_timeout), 0, "Screen capture timer leaked after 25s timeout")

            # 5. pagehide / beforeunload cleanly stops both dashboard and screen-capture polling.
            await cdp.eval("""
                (async () => {
                    window.__TEST_HARNESS__.getState().captureLatestFilename = '';
                    document.getElementById("btn-qa-screen").click();
                    await window.__TEST_HARNESS__.realSleep(30);
                })();
            """)
            await asyncio.sleep(0.15)
            await cdp.eval("window.__TEST_HARNESS__.dispatchUnload('pagehide');")
            await cdp.eval("window.__TEST_HARNESS__.clearFetchLog();")
            await cdp.eval("window.__TEST_HARNESS__.setHidden(false);")
            await cdp.eval("window.__TEST_HARNESS__.advanceMs(30000);")
            post_unload_timers = await cdp.eval(
                "window.__TEST_HARNESS__.getPendingTimeouts().filter(t => t.delay >= 1000)"
            )
            post_unload_status = await cdp.eval("window.__TEST_HARNESS__.getFetchCount('/api/status')")
            post_unload_cap = await cdp.eval("window.__TEST_HARNESS__.getFetchCount('/api/screen/capture-latest')")
            self.assertEqual(post_unload_timers, [], "Timers leaked after pagehide teardown")
            self.assertEqual(post_unload_status, 0, "Dashboard polled after pagehide")
            self.assertEqual(post_unload_cap, 0, "Screen capture polled after pagehide")

            # Also verify beforeunload on a clean reload tears down dashboard timers & listeners.
            await cdp.call("Page.navigate", {"url": f"http://127.0.0.1:{port}/"})
            await asyncio.sleep(0.4)
            await cdp.eval("window.__TEST_HARNESS__.flushMicrotasks()")
            await cdp.eval("window.__TEST_HARNESS__.dispatchUnload('beforeunload');")
            await cdp.eval("window.__TEST_HARNESS__.clearFetchLog();")
            await cdp.eval("window.__TEST_HARNESS__.setHidden(false);")
            await cdp.eval("window.__TEST_HARNESS__.advanceMs(15000);")
            post_bu_timers = await cdp.eval("window.__TEST_HARNESS__.getPendingTimeouts().filter(t => t.delay >= 1000)")
            post_bu_status = await cdp.eval("window.__TEST_HARNESS__.getFetchCount('/api/status')")
            self.assertEqual(post_bu_timers, [], "Timers leaked after beforeunload teardown")
            self.assertEqual(post_bu_status, 0, "Dashboard polled after beforeunload")

            # Verify zero runtime JS exceptions or console errors occurred across full CDP run.
            self.assertEqual(cdp.exceptions, [], f"Uncaught JS exceptions in browser: {cdp.exceptions}")
            self.assertEqual(cdp.console_errors, [], f"Console errors in browser: {cdp.console_errors}")
        finally:
            if cdp is not None:
                try:
                    await cdp.close()
                except Exception:
                    pass
            if browser_proc is not None and browser_proc.poll() is None:
                try:
                    browser_proc.terminate()
                    browser_proc.wait(timeout=3.0)
                except Exception:
                    try:
                        browser_proc.kill()
                    except Exception:
                        pass
            await runner.cleanup()
            shutil.rmtree(user_data_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
