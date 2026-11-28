"""Milestone 4.6 Web UI & Headless Microsoft Edge CDP Audit Suite.

Validates:
1. 3-consecutive-failure hysteresis for Core Offline + immediate 1st-poll recovery.
2. Skipped /api/notifications when no Android phone has is_connected === true,
   and skipped dead #clipboard-items-container fetch.
3. Removal of duplicate screen-share bindings in initFilesView().
4. Truthful Remote AI Link state (never infers enabled=true on /api/mcp/tunnel/status failure).
5. Clean 2-step SNOW ID -> PIN pairing UX (Devices & #connect-modal), no legacy accordions,
   and removal of standalone Hub Identity from Web Dashboard Binding.
6. Device-aware adaptive Home Quick Actions (Host, Remote Windows PC, Android Phone).
7. Concurrent multi-file transfers (MAX_CONCURRENT_TRANSFERS = 3 + queue + cancelTransferById)
   and /api/files monotonic sequence guard (filesLoadSeq) + 15000ms timeout.
8. Light & Dark theme responsive audit across 1366x768, 1280x720, and 390x844 with zero
   JS/console errors, zero horizontal overflows, and zero overlapping controls.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

from aiohttp import web

from tests.test_m41_unit2_lifecycle_web import _CdpClient, _find_chromium_binary

REPO_ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = REPO_ROOT / "src" / "snow" / "web" / "static"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class TestM46WebUiStaticContracts(unittest.TestCase):
    """Static verification of Milestone 4.6 HTML, CSS, and JS contracts."""

    def setUp(self) -> None:
        self.html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
        self.css = (STATIC_DIR / "app.css").read_text(encoding="utf-8")
        self.js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")

    def test_legacy_pairing_accordions_and_hub_identity_removed(self) -> None:
        for legacy_id in (
            "paste-qr-json-accordion",
            "modal-paste-qr-accordion",
            "connect-advanced-accordion",
            "pairing-pin-input",
            "modal-connect-pin-input",
            "connect-peer-host",
            "btn-connect-peer-submit",
            "diag-network-key-id",
        ):
            self.assertNotIn(legacy_id, self.html, f"Legacy ID '{legacy_id}' still in index.html")
            self.assertNotIn(legacy_id, self.js, f"Legacy ID '{legacy_id}' still in app.js")

        self.assertNotIn("Hub Identity", self.html)
        for dead_fn in ("validateQrJsonInput", "acceptQrJsonInput", "handleUnifiedConnectInput"):
            self.assertNotIn(dead_fn, self.js)

    def test_single_file_transfer_globals_replaced_with_concurrent_map(self) -> None:
        for legacy_sym in ("activeUploadXhr", "activeUploadTransferId", "activeDownloadController", "updateTransferProgressUi"):
            self.assertNotIn(legacy_sym, self.js, f"Legacy single-transfer symbol '{legacy_sym}' still in app.js")
        self.assertIn("MAX_CONCURRENT_TRANSFERS = 3", self.js)
        self.assertIn("activeTransfers = new Map()", self.js)
        self.assertIn("function cancelTransferById(", self.js)
        self.assertIn("filesLoadSeq", self.js)
        self.assertIn("timeoutMs: 15000", self.js)

    def test_hysteresis_quick_actions_and_no_duplicate_screen_listeners(self) -> None:
        self.assertIn("consecutiveCoreOfflinePolls", self.js)
        self.assertIn("function applyQuickActionsForTarget(", self.js)
        for qa_id in (
            "btn-qa-lock-pc",
            "btn-qa-ring",
            "btn-qa-screen",
            "btn-qa-camera",
            "btn-qa-send-files",
            "btn-qa-browse-files",
            "btn-qa-media",
            "btn-qa-share-pc-screen",
            "btn-qa-sync-clipboard",
            "btn-qa-open-folder",
            "btn-qa-share-note",
        ):
            self.assertIn(f'id="{qa_id}"', self.html)

        # Ensure initFilesView no longer duplicates screen-share click listeners bound in initHomeHub
        share_bindings = re.findall(r'getElementById\("btn-share-pc-screen"\)\?\.addEventListener\("click"', self.js)
        self.assertEqual(len(share_bindings), 1, f"Expected 1 btn-share-pc-screen binding, got {len(share_bindings)}")
        stop_bindings = re.findall(r'getElementById\("btn-stop-screen-stream"\)\?\.addEventListener\("click"', self.js)
        self.assertEqual(len(stop_bindings), 1, f"Expected 1 btn-stop-screen-stream binding, got {len(stop_bindings)}")

    def test_zero_inline_handlers_and_zero_external_cdns(self) -> None:
        combined = self.html + self.js + self.css
        self.assertNotIn("onclick=", combined.lower())
        self.assertNotIn("onerror=", combined.lower())
        for cdn in ("cdn.", "fonts.googleapis", "fonts.gstatic", "unpkg.com", "jsdelivr"):
            self.assertNotIn(cdn, combined.lower())


class TestM46WebUiHeadlessEdgeCDPAudit(unittest.IsolatedAsyncioTestCase):
    """Run real SNOW Web UI in headless Microsoft Edge / Chromium V8 DOM via CDP."""

    async def _launch_browser_and_server(self, harness_source: str):
        browser_bin = _find_chromium_binary()
        if not browser_bin:
            self.skipTest("No Chrome/Edge browser binary available for M4.6 CDP audit")

        async def _index(_req: web.Request) -> web.Response:
            return web.FileResponse(STATIC_DIR / "index.html")

        async def _fallback(_req: web.Request) -> web.Response:
            return web.json_response({"success": True})

        app = web.Application()
        app.router.add_get("/", _index)
        app.router.add_static("/static", STATIC_DIR)
        app.router.add_route("*", "/{tail:.*}", _fallback)

        runner = web.AppRunner(app)
        await runner.setup()
        port = _find_free_port()
        site = web.TCPSite(runner, "127.0.0.1", port)
        await site.start()

        user_data_dir = tempfile.mkdtemp(prefix="snow_m46_cdp_")
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

        import urllib.request

        cdp = None
        try:
            devtools_port = None
            devtools_file = Path(user_data_dir) / "DevToolsActivePort"
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline:
                if devtools_file.exists():
                    try:
                        lines = devtools_file.read_text(encoding="utf-8").splitlines()
                        if lines and lines[0].strip().isdigit():
                            devtools_port = int(lines[0].strip())
                            break
                    except (PermissionError, OSError):
                        pass
                await asyncio.sleep(0.1)
            if devtools_port is None:
                self.fail("Headless Edge/Chromium did not publish DevToolsActivePort")

            with urllib.request.urlopen(f"http://127.0.0.1:{devtools_port}/json/list", timeout=3.0) as resp:
                targets = json.loads(resp.read().decode("utf-8"))
            page_ws = next(t["webSocketDebuggerUrl"] for t in targets if t.get("type") == "page")

            cdp = _CdpClient(page_ws)
            await cdp.connect()
            await cdp.call("Page.enable")
            await cdp.call("Runtime.enable")
            await cdp.call("Page.addScriptToEvaluateOnNewDocument", {"source": harness_source})
            await cdp.call("Page.navigate", {"url": f"http://127.0.0.1:{port}/?token=m46cdp"})
            await asyncio.sleep(0.6)
            return runner, browser_proc, user_data_dir, cdp
        except Exception:
            await self._shutdown(runner, browser_proc, user_data_dir, cdp)
            raise

    async def _shutdown(self, runner, browser_proc, user_data_dir, cdp) -> None:
        if cdp is not None:
            try:
                await cdp.close()
            except Exception:
                pass
        if browser_proc is not None and browser_proc.poll() is None:
            browser_proc.terminate()
            try:
                browser_proc.wait(timeout=3.0)
            except Exception:
                browser_proc.kill()
        shutil.rmtree(user_data_dir, ignore_errors=True)
        await runner.cleanup()

    async def test_m46_themes_viewports_layout_and_zero_overlaps(self) -> None:
        live_svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="#000"/></svg>'
        harness = rf"""
(() => {{
    window.fetch = async (url) => {{
        const u = String(url);
        const ok = (obj) => new Response(JSON.stringify({{ success: true, ...obj }}), {{
            status: 200, headers: {{ "Content-Type": "application/json" }},
        }});
        if (u.startsWith("/api/status")) {{
            return ok({{
                daemon_online: true, csrf_token: "m46-csrf", snow_id: "SNW-M460-HOST",
                device_id: "local", device_name: "Test Laptop", lan_ips: ["192.168.1.10"],
                telemetry: {{ cpu_percent: 18, ram_percent: 42 }},
            }});
        }}
        if (u.startsWith("/api/devices")) {{
            return ok({{
                devices: [
                    {{ device_id: "local", is_local: true, is_connected: true, platform: "windows", snow_id: "SNW-M460-HOST", device_name: "Test Laptop" }},
                    {{ device_id: "phone-1", is_local: false, is_connected: true, platform: "android", device_type: "phone", snow_id: "SNW-PHN1-AAAA", device_name: "Pixel Phone", telemetry: {{ battery_level: 85 }} }},
                ],
            }});
        }}
        if (u.startsWith("/api/pair/state")) {{
            return ok({{ snow_id: "SNW-M460-HOST", network_id: null, has_active_pin: false, svg: {json.dumps(live_svg)} }});
        }}
        if (u.startsWith("/api/network/identity")) {{
            return ok({{ identity: {{ network_id: null, network_formed: false }} }});
        }}
        if (u.startsWith("/api/mcp/tunnel/status")) {{
            return ok({{ enabled: false, active: false, configured_render_url: "https://snow-relay.onrender.com/u/SNW-M460-HOST/mcp" }});
        }}
        return ok({{ pending: [], grants: [], items: [], clients: [], files: [], apps: [], notifications: [] }});
    }};
}})();
"""
        runner, proc, tmpdir, cdp = await self._launch_browser_and_server(harness)
        try:
            for theme in ("light", "dark"):
                await cdp.eval(f"document.getElementById('theme-opt-{theme}')?.click();")
                await asyncio.sleep(0.08)
                applied_cls = await cdp.eval("document.documentElement.className")
                self.assertIn(f"theme-{theme}", applied_cls)

                for vw, vh in ((1366, 768), (1280, 720), (390, 844)):
                    await cdp.call("Emulation.setDeviceMetricsOverride", {
                        "width": vw, "height": vh, "deviceScaleFactor": 1, "mobile": vw < 600,
                    })
                    for tab in ("overview", "clipboard", "files", "devices", "settings"):
                        metrics = await cdp.eval(rf"""
(async () => {{
    document.querySelector('.nav-item[data-tab="{tab}"]')?.click();
    await new Promise(r => setTimeout(r, 90));
    const doc = document.documentElement;
    const topbar = document.querySelector('.topbar');
    const body = document.querySelector('.content-body');
    const checkOverlaps = (selector) => {{
        const els = Array.from(document.querySelectorAll(selector)).filter(el => {{
            const s = getComputedStyle(el);
            const r = el.getBoundingClientRect();
            return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0;
        }});
        const overlaps = [];
        for (let i = 0; i < els.length; i++) {{
            const a = els[i].getBoundingClientRect();
            for (let j = i + 1; j < els.length; j++) {{
                const b = els[j].getBoundingClientRect();
                const ix = Math.min(a.right, b.right) - Math.max(a.left, b.left);
                const iy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
                if (ix > 2 && iy > 2) overlaps.push([els[i].id || els[i].className, els[j].id || els[j].className]);
            }}
        }}
        return overlaps;
    }};
    const overlaps = [
        ...checkOverlaps('.topbar button'),
        ...checkOverlaps('.quick-actions-grid .action-tile'),
        ...checkOverlaps('#pair-pane-qr button, #pair-pane-qr input'),
        ...checkOverlaps('.ai-assistant-grid .ai-card'),
        ...checkOverlaps('#remote-ai-link-card input, #remote-ai-link-card button'),
    ];
    return {{
        docScroll: doc.scrollWidth,
        docClient: doc.clientWidth,
        topbarScroll: topbar ? topbar.scrollWidth : 0,
        topbarClient: topbar ? topbar.clientWidth : 0,
        bodyScroll: body ? body.scrollWidth : 0,
        bodyClient: body ? body.clientWidth : 0,
        overlaps,
    }};
}})()
""")
                        self.assertLessEqual(
                            metrics["docScroll"], metrics["docClient"] + 2,
                            f"Doc overflow in theme={theme} {vw}x{vh} tab={tab}: {metrics}",
                        )
                        self.assertLessEqual(
                            metrics["topbarScroll"], metrics["topbarClient"] + 2,
                            f"Topbar overflow in theme={theme} {vw}x{vh} tab={tab}: {metrics}",
                        )
                        self.assertLessEqual(
                            metrics["bodyScroll"], metrics["bodyClient"] + 2,
                            f"Body overflow in theme={theme} {vw}x{vh} tab={tab}: {metrics}",
                        )
                        self.assertEqual(
                            metrics["overlaps"], [],
                            f"Overlaps in theme={theme} {vw}x{vh} tab={tab}: {metrics['overlaps']}",
                        )

                    # Also verify #connect-modal Step 1 & Step 2 have zero overflows/overlaps at this viewport & theme
                    modal_metrics = await cdp.eval(r"""
(async () => {
    document.getElementById('btn-topbar-connect')?.click();
    await new Promise(r => setTimeout(r, 60));
    const card = document.querySelector('#connect-modal .modal-card');
    const checkRects = () => {
        const els = Array.from(document.querySelectorAll('#connect-modal button, #connect-modal input')).filter(el => {
            const s = getComputedStyle(el);
            const r = el.getBoundingClientRect();
            return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0;
        });
        const overlaps = [];
        for (let i = 0; i < els.length; i++) {
            const a = els[i].getBoundingClientRect();
            for (let j = i + 1; j < els.length; j++) {
                const b = els[j].getBoundingClientRect();
                const ix = Math.min(a.right, b.right) - Math.max(a.left, b.left);
                const iy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
                if (ix > 2 && iy > 2) overlaps.push([els[i].id, els[j].id]);
            }
        }
        return overlaps;
    };
    const step1Overlaps = checkRects();
    const step1Scroll = card ? card.scrollWidth : 0;
    const step1Client = card ? card.clientWidth : 0;

    // Switch modal to Step 2 and check Step 2 layout too
    document.getElementById('modal-step1-container')?.classList.add('d-none');
    document.getElementById('modal-step2-container')?.classList.remove('d-none');
    await new Promise(r => setTimeout(r, 30));
    const step2Overlaps = checkRects();
    const step2Scroll = card ? card.scrollWidth : 0;
    const step2Client = card ? card.clientWidth : 0;

    document.getElementById('btn-close-connect-modal')?.click();
    return { step1Overlaps, step1Scroll, step1Client, step2Overlaps, step2Scroll, step2Client };
})()
""")
                    self.assertLessEqual(
                        modal_metrics["step1Scroll"], modal_metrics["step1Client"] + 2,
                        f"Modal Step 1 overflow in theme={theme} {vw}x{vh}: {modal_metrics}",
                    )
                    self.assertEqual(
                        modal_metrics["step1Overlaps"], [],
                        f"Modal Step 1 overlaps in theme={theme} {vw}x{vh}: {modal_metrics['step1Overlaps']}",
                    )
                    self.assertLessEqual(
                        modal_metrics["step2Scroll"], modal_metrics["step2Client"] + 2,
                        f"Modal Step 2 overflow in theme={theme} {vw}x{vh}: {modal_metrics}",
                    )
                    self.assertEqual(
                        modal_metrics["step2Overlaps"], [],
                        f"Modal Step 2 overlaps in theme={theme} {vw}x{vh}: {modal_metrics['step2Overlaps']}",
                    )

            self.assertEqual(cdp.exceptions, [], f"Uncaught JS exceptions: {cdp.exceptions}")
            self.assertEqual(cdp.console_errors, [], f"Console errors: {cdp.console_errors}")
        finally:
            await self._shutdown(runner, proc, tmpdir, cdp)

    async def test_m46_hysteresis_notifications_tunnel_2step_qa_transfers_and_files_seq(self) -> None:
        live_svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="#000"/></svg>'
        harness = rf"""
(() => {{
    window.__M46__ = {{
        statusMode: "online",          // "online" | "fail" | "daemon_false"
        tunnelMode: "fail",            // "fail" | "starting" | "active"
        devicesMode: "host_only",      // "host_only" | "disconnected_phone" | "win_peer_only" | "all_devices"
        calls: [],
        pendingDownloads: new Map(),
        abortedDownloadIds: [],
        cancelPayloads: [],
        activeXhrs: [],
        abortedXhrFiles: [],
        fileLoads: new Map(),
        filesResponseMode: "auto",     // "auto" | "deferred"
    }};

    class MockXHR {{
        constructor() {{
            this.upload = {{}};
            this.status = 0;
            this.responseText = "";
            this._aborted = false;
            this._fileName = "";
        }}
        open(method, url) {{
            this.method = method;
            this.url = url;
        }}
        setRequestHeader() {{}}
        send(formData) {{
            const f = formData && formData.get ? formData.get("file") : null;
            this._fileName = f ? f.name : "upload";
            window.__M46__.activeXhrs.push(this);
            if (this.upload.onprogress) {{
                this.upload.onprogress({{ lengthComputable: true, loaded: 50, total: 100 }});
            }}
        }}
        abort() {{
            this._aborted = true;
            window.__M46__.abortedXhrFiles.push(this._fileName);
            const idx = window.__M46__.activeXhrs.indexOf(this);
            if (idx !== -1) window.__M46__.activeXhrs.splice(idx, 1);
            if (this.onabort) this.onabort();
        }}
        completeOk() {{
            this.status = 200;
            this.responseText = JSON.stringify({{ success: true }});
            const idx = window.__M46__.activeXhrs.indexOf(this);
            if (idx !== -1) window.__M46__.activeXhrs.splice(idx, 1);
            if (this.onload) this.onload();
        }}
    }}
    window.XMLHttpRequest = MockXHR;

    window.fetch = async (url, opts = {{}}) => {{
        const u = String(url);
        const method = (opts && opts.method) || "GET";
        const bodyText = opts && typeof opts.body === "string" ? opts.body : "";
        window.__M46__.calls.push({{ url: u, method, body: bodyText }});
        const ok = (obj, status = 200) => new Response(JSON.stringify({{ success: true, ...obj }}), {{
            status, headers: {{ "Content-Type": "application/json" }},
        }});
        const errResp = (obj, status = 500) => new Response(JSON.stringify({{ success: false, ...obj }}), {{
            status, headers: {{ "Content-Type": "application/json" }},
        }});

        if (u.startsWith("/api/status")) {{
            if (window.__M46__.statusMode === "fail") {{
                return errResp({{ daemon_online: false, error: "Core offline" }}, 500);
            }}
            if (window.__M46__.statusMode === "daemon_false") {{
                return ok({{ daemon_online: false, csrf_token: "m46-csrf", snow_id: "SNW-M460-HOST", device_id: "local", device_name: "Host PC" }});
            }}
            return ok({{
                daemon_online: true, csrf_token: "m46-csrf", snow_id: "SNW-M460-HOST",
                device_id: "local", device_name: "Host PC", lan_ips: ["192.168.1.10"],
                telemetry: {{ cpu_percent: 14, ram_percent: 40 }},
            }});
        }}

        if (u.startsWith("/api/devices/connect-peer")) {{
            const body = JSON.parse(bodyText || "{{}}");
            if (body.step === "resolve") {{
                if (body.snow_id === "SNW-SAVE-1111") {{
                    return ok({{ already_paired: true, snow_id: "SNW-SAVE-1111" }});
                }}
                return errResp({{ requires_pin: true, status: "PIN_REQUIRED", snow_id: body.snow_id }}, 200);
            }}
            if (body.pin === "000000") {{
                return errResp({{ status: "INVALID_PIN", attempts_remaining: 2, error: "Wrong PIN" }}, 401);
            }}
            return ok({{
                snow_id: body.snow_id,
                network_conflict: true,
                merge_tx_id: "tx-m46-merge",
                source_network_id: "SNW-NET-AAAA1111",
                target_network_id: "SNW-NET-BBBB2222",
            }});
        }}

        if (u.startsWith("/api/devices")) {{
            const m = window.__M46__.devicesMode;
            const localDev = {{ device_id: "local", is_local: true, is_connected: true, platform: "windows", snow_id: "SNW-M460-HOST", device_name: "Host PC" }};
            const phoneOff = {{ device_id: "phone-1", is_local: false, is_connected: false, platform: "android", device_type: "phone", snow_id: "SNW-PHN1-AAAA", device_name: "Pixel Phone" }};
            const phoneOn = {{ device_id: "phone-1", is_local: false, is_connected: true, platform: "android", device_type: "phone", snow_id: "SNW-PHN1-AAAA", device_name: "Pixel Phone", telemetry: {{ battery_level: 88 }} }};
            const winPeer = {{ device_id: "win-peer-1", is_local: false, is_connected: true, platform: "windows", device_type: "windows", snow_id: "SNW-WIN2-BBBB", device_name: "Workstation B" }};
            if (m === "host_only") return ok({{ devices: [localDev] }});
            if (m === "disconnected_phone") return ok({{ devices: [localDev, phoneOff] }});
            if (m === "win_peer_only") return ok({{ devices: [localDev, winPeer] }});
            return ok({{ devices: [localDev, winPeer, phoneOn] }});
        }}

        if (u.startsWith("/api/notifications")) {{
            return ok({{
                notifications: [
                    {{ key: "n-1", app_name: "Messages", title: "Alex", body: "Ready for demo", can_reply: true }}
                ],
            }});
        }}

        if (u.startsWith("/api/mcp/tunnel/status")) {{
            if (window.__M46__.tunnelMode === "fail") {{
                return errResp({{ error: "Tunnel status unavailable" }}, 500);
            }}
            if (window.__M46__.tunnelMode === "starting") {{
                return ok({{
                    enabled: true, active: false, provider: "render",
                    configured_render_url: "https://snow-relay.onrender.com/u/SNW-M460-HOST/mcp",
                }});
            }}
            return ok({{
                enabled: true, active: true, provider: "render",
                configured_render_url: "https://snow-relay.onrender.com/u/SNW-M460-HOST/mcp",
                mcp_endpoint: "https://snow-relay.onrender.com/u/SNW-M460-HOST/mcp",
            }});
        }}

        if (u.startsWith("/api/identity/device")) {{
            return ok({{ snow_id: "SNW-M460-HOST", permanent_mcp_url: "https://snow-relay.onrender.com/u/SNW-M460-HOST/mcp" }});
        }}
        if (u.startsWith("/api/network/identity")) {{
            return ok({{ identity: {{ network_id: null, network_formed: false }} }});
        }}
        if (u.startsWith("/api/pair/state")) {{
            return ok({{ snow_id: "SNW-M460-HOST", network_id: null, has_active_pin: false, svg: {json.dumps(live_svg)} }});
        }}

        if (u.startsWith("/api/files/transfer/cancel")) {{
            const body = JSON.parse(bodyText || "{{}}");
            window.__M46__.cancelPayloads.push(body);
            return ok({{ cancelled: 1 }});
        }}

        if (u.startsWith("/api/files/download")) {{
            const body = JSON.parse(bodyText || "{{}}");
            const tid = body.client_transfer_id || body.file_name;
            return await new Promise((resolve, reject) => {{
                window.__M46__.pendingDownloads.set(tid, {{ resolve, reject, file: body.file_name }});
                if (opts && opts.signal) {{
                    if (opts.signal.aborted) {{
                        window.__M46__.abortedDownloadIds.push(tid);
                        window.__M46__.pendingDownloads.delete(tid);
                        reject(new DOMException("Aborted", "AbortError"));
                        return;
                    }}
                    opts.signal.addEventListener("abort", () => {{
                        window.__M46__.abortedDownloadIds.push(tid);
                        window.__M46__.pendingDownloads.delete(tid);
                        reject(new DOMException("Aborted", "AbortError"));
                    }}, {{ once: true }});
                }}
            }});
        }}

        if (u.startsWith("/api/files?")) {{
            const parsedUrl = new URL(u, "http://127.0.0.1");
            const subpath = parsedUrl.searchParams.get("subpath") || "";
            if (window.__M46__.filesResponseMode === "deferred") {{
                return await new Promise((resolve) => {{
                    window.__M46__.fileLoads.set(subpath, resolve);
                }});
            }}
            if (subpath === "") {{
                return ok({{
                    storage_mode: "saf_tree",
                    items: [
                        {{ name: "SlowDir", is_dir: true }},
                        {{ name: "FastDir", is_dir: true }},
                        {{ name: "a.bin", is_dir: false, size_bytes: 1024 }},
                        {{ name: "b.bin", is_dir: false, size_bytes: 2048 }},
                        {{ name: "c.bin", is_dir: false, size_bytes: 3072 }},
                        {{ name: "d.bin", is_dir: false, size_bytes: 4096 }},
                    ],
                }});
            }}
            return ok({{ storage_mode: "saf_tree", items: [{{ name: `${{subpath}}_file.txt`, is_dir: false, size_bytes: 512 }}] }});
        }}

        return ok({{ pending: [], grants: [], items: [], clients: [], apps: [] }});
    }};
}})();
"""
        runner, proc, tmpdir, cdp = await self._launch_browser_and_server(harness)
        try:
            await cdp.call("Emulation.setDeviceMetricsOverride", {
                "width": 1366, "height": 768, "deviceScaleFactor": 1, "mobile": False,
            })

            # 1. Verify 3-poll Core Offline hysteresis + immediate 1st-poll recovery
            hyst = await cdp.eval(r"""
(async () => {
    const snap = () => ({
        text: document.getElementById('core-status-text')?.textContent?.trim(),
        dot: document.getElementById('core-status-dot')?.className,
    });
    const t0 = snap();

    window.__M46__.statusMode = "fail";
    document.getElementById('btn-global-refresh')?.click();
    await new Promise(r => setTimeout(r, 90));
    const t1 = snap();

    window.__M46__.statusMode = "daemon_false";
    document.getElementById('btn-global-refresh')?.click();
    await new Promise(r => setTimeout(r, 90));
    const t2 = snap();

    window.__M46__.statusMode = "fail";
    document.getElementById('btn-global-refresh')?.click();
    await new Promise(r => setTimeout(r, 90));
    const t3 = snap();

    window.__M46__.statusMode = "online";
    document.getElementById('btn-global-refresh')?.click();
    await new Promise(r => setTimeout(r, 90));
    const t4 = snap();

    return { t0, t1, t2, t3, t4 };
})()
""")
            self.assertEqual(hyst["t0"]["text"], "Core Online")
            self.assertEqual(hyst["t1"]["text"], "Core Online", "1st failure flipped Core Offline prematurely")
            self.assertEqual(hyst["t2"]["text"], "Core Online", "2nd failure flipped Core Offline prematurely")
            self.assertEqual(hyst["t3"]["text"], "Core Offline", "3rd consecutive failure did not flip Core Offline")
            self.assertIn("dot-offline", hyst["t3"]["dot"])
            self.assertEqual(hyst["t4"]["text"], "Core Online", "1st success did not immediately recover Core Online")
            self.assertIn("dot-active", hyst["t4"]["dot"])

            # 2. Verify /api/notifications skipped unless a remote Android phone has is_connected === true
            #    and dead #clipboard-items-container fetch is skipped
            notif_check = await cdp.eval(r"""
(async () => {
    const countCalls = (prefix) => window.__M46__.calls.filter(c => c.url.startsWith(prefix)).length;

    window.__M46__.calls.length = 0;
    window.__M46__.devicesMode = "host_only";
    document.getElementById('btn-global-refresh')?.click();
    await new Promise(r => setTimeout(r, 90));
    const hostNotifs = countCalls("/api/notifications");
    const hostClips = countCalls("/api/clipboard/buffer");

    window.__M46__.calls.length = 0;
    window.__M46__.devicesMode = "disconnected_phone";
    document.getElementById('btn-global-refresh')?.click();
    await new Promise(r => setTimeout(r, 90));
    const discPhoneNotifs = countCalls("/api/notifications");

    window.__M46__.calls.length = 0;
    window.__M46__.devicesMode = "win_peer_only";
    document.getElementById('btn-global-refresh')?.click();
    await new Promise(r => setTimeout(r, 90));
    const winPeerNotifs = countCalls("/api/notifications");

    window.__M46__.calls.length = 0;
    window.__M46__.devicesMode = "all_devices";
    document.getElementById('btn-global-refresh')?.click();
    await new Promise(r => setTimeout(r, 110));
    const connPhoneNotifs = countCalls("/api/notifications");
    const renderedNotifs = document.querySelectorAll('#notifications-container .notif-card').length;

    return { hostNotifs, hostClips, discPhoneNotifs, winPeerNotifs, connPhoneNotifs, renderedNotifs };
})()
""")
            self.assertEqual(notif_check["hostNotifs"], 0)
            self.assertEqual(notif_check["hostClips"], 0)
            self.assertEqual(notif_check["discPhoneNotifs"], 0)
            self.assertEqual(notif_check["winPeerNotifs"], 0)
            self.assertGreaterEqual(notif_check["connPhoneNotifs"], 1)
            self.assertEqual(notif_check["renderedNotifs"], 1)

            # 3. Verify truthful Remote AI Link state + no standalone Hub Identity in Web Dashboard Binding
            tunnel_check = await cdp.eval(r"""
(async () => {
    window.__M46__.tunnelMode = "fail";
    document.querySelector('.nav-item[data-tab="settings"]')?.click();
    await new Promise(r => setTimeout(r, 120));
    const failBadge = document.getElementById('mcp-tunnel-status')?.textContent?.trim();
    const failChecked = document.getElementById('chk-mcp-tunnel-toggle')?.checked;

    window.__M46__.tunnelMode = "starting";
    document.getElementById('btn-global-refresh')?.click();
    await new Promise(r => setTimeout(r, 120));
    const startBadge = document.getElementById('mcp-tunnel-status')?.textContent?.trim();
    const startChecked = document.getElementById('chk-mcp-tunnel-toggle')?.checked;

    window.__M46__.tunnelMode = "active";
    document.getElementById('btn-global-refresh')?.click();
    await new Promise(r => setTimeout(r, 120));
    const activeBadge = document.getElementById('mcp-tunnel-status')?.textContent?.trim();
    const activeChecked = document.getElementById('chk-mcp-tunnel-toggle')?.checked;

    const advDetails = document.querySelector('#advanced-diagnostics-card details.advanced-accordion');
    if (advDetails) advDetails.open = true;
    const bindingText = document.getElementById('diag-port')?.parentElement?.innerText || "";
    const hasNetKeyEl = Boolean(document.getElementById('diag-network-key-id'));

    return { failBadge, failChecked, startBadge, startChecked, activeBadge, activeChecked, bindingText, hasNetKeyEl };
})()
""")
            self.assertEqual(tunnel_check["failBadge"], "Off")
            self.assertFalse(tunnel_check["failChecked"])
            self.assertEqual(tunnel_check["startBadge"], "Starting...")
            self.assertTrue(tunnel_check["startChecked"])
            self.assertEqual(tunnel_check["activeBadge"], "Active • 60 Tools Ready")
            self.assertTrue(tunnel_check["activeChecked"])
            self.assertNotIn("Hub Identity", tunnel_check["bindingText"])
            self.assertFalse(tunnel_check["hasNetKeyEl"])

            # 4. Verify 2-step SNOW ID -> PIN flow in #connect-modal (saved auto-connect, new ID Step 2, wrong PIN, Change ID, verify)
            pairing_check = await cdp.eval(r"""
(async () => {
    // Saved ID auto-connects and closes modal
    document.getElementById('btn-topbar-connect')?.click();
    await new Promise(r => setTimeout(r, 60));
    document.getElementById('modal-connect-input').value = "snw-save-1111";
    document.getElementById('btn-modal-connect-submit')?.click();
    await new Promise(r => setTimeout(r, 120));
    const modalClosedAfterSaved = document.getElementById('connect-modal')?.classList.contains('d-none');
    const inputClearedAfterSaved = document.getElementById('modal-connect-input')?.value === "";

    // New ID transitions to Step 2 and keeps #connect-modal open
    document.getElementById('btn-topbar-connect')?.click();
    await new Promise(r => setTimeout(r, 60));
    document.getElementById('modal-connect-input').value = "SNW-NEWP-2222";
    document.getElementById('btn-modal-connect-submit')?.click();
    await new Promise(r => setTimeout(r, 120));
    const modalOpenStep2 = !document.getElementById('connect-modal')?.classList.contains('d-none');
    const step2Visible = !document.getElementById('modal-step2-container')?.classList.contains('d-none');
    const step2Label = document.getElementById('modal-step2-label')?.textContent?.trim();

    // Wrong PIN keeps Step 2 open, SNOW ID intact, shows attempts remaining error
    document.getElementById('modal-step2-pin').value = "000000";
    document.getElementById('btn-modal-verify-pin')?.click();
    await new Promise(r => setTimeout(r, 120));
    const stillOpenWrongPin = !document.getElementById('connect-modal')?.classList.contains('d-none')
        && !document.getElementById('modal-step2-container')?.classList.contains('d-none');
    const snowIdIntact = document.getElementById('modal-connect-input')?.value === "SNW-NEWP-2222";
    const wrongPinErr = document.getElementById('modal-step2-error')?.textContent?.trim();

    // Change ID returns to Step 1 preserving SNOW ID
    document.getElementById('btn-modal-change-id')?.click();
    await new Promise(r => setTimeout(r, 40));
    const backToStep1 = !document.getElementById('modal-step1-container')?.classList.contains('d-none')
        && document.getElementById('modal-step2-container')?.classList.contains('d-none')
        && document.getElementById('modal-connect-input')?.value === "SNW-NEWP-2222";

    // Re-enter Step 2 and verify valid PIN opens merge modal & closes connect modal
    document.getElementById('btn-modal-connect-submit')?.click();
    await new Promise(r => setTimeout(r, 100));
    document.getElementById('modal-step2-pin').value = "654321";
    document.getElementById('btn-modal-verify-pin')?.click();
    await new Promise(r => setTimeout(r, 140));
    const modalClosedAfterPair = document.getElementById('connect-modal')?.classList.contains('d-none');
    const mergeOpen = !document.getElementById('network-merge-decision-modal')?.classList.contains('d-none');
    document.getElementById('btn-close-merge-modal')?.click();

    return {
        modalClosedAfterSaved, inputClearedAfterSaved,
        modalOpenStep2, step2Visible, step2Label,
        stillOpenWrongPin, snowIdIntact, wrongPinErr, backToStep1,
        modalClosedAfterPair, mergeOpen,
    };
})()
""")
            self.assertTrue(pairing_check["modalClosedAfterSaved"])
            self.assertTrue(pairing_check["inputClearedAfterSaved"])
            self.assertTrue(pairing_check["modalOpenStep2"])
            self.assertTrue(pairing_check["step2Visible"])
            self.assertEqual(pairing_check["step2Label"], "Enter the 6-digit PIN shown on SNW-NEWP-2222")
            self.assertTrue(pairing_check["stillOpenWrongPin"])
            self.assertTrue(pairing_check["snowIdIntact"])
            self.assertEqual(pairing_check["wrongPinErr"], "Incorrect PIN — 2 attempts remaining. Please re-enter.")
            self.assertTrue(pairing_check["backToStep1"])
            self.assertTrue(pairing_check["modalClosedAfterPair"])
            self.assertTrue(pairing_check["mergeOpen"])

            # 5. Verify Host / Remote Windows PC / Android Phone Quick Actions switching
            qa_check = await cdp.eval(r"""
(async () => {
    document.querySelector('.nav-item[data-tab="overview"]')?.click();
    await new Promise(r => setTimeout(r, 100));

    const visibleQuickActions = () => Array.from(document.querySelectorAll('.quick-actions-grid .action-tile'))
        .filter(el => !el.classList.contains('d-none'))
        .map(el => ({ id: el.id, label: el.querySelector('.qa-tile-label')?.textContent?.trim() }));

    // Select Host (This PC)
    document.getElementById('topbar-device-capsule')?.click();
    document.getElementById('island-local-host')?.click();
    await new Promise(r => setTimeout(r, 80));
    const hostQa = visibleQuickActions();

    // Select Remote Windows PC
    document.getElementById('topbar-device-capsule')?.click();
    const items1 = Array.from(document.querySelectorAll('#island-paired-devices .island-item'));
    items1.find(el => el.innerText.includes('Workstation B'))?.click();
    await new Promise(r => setTimeout(r, 80));
    const remotePcQa = visibleQuickActions();

    // Select Android Phone
    document.getElementById('topbar-device-capsule')?.click();
    const items2 = Array.from(document.querySelectorAll('#island-paired-devices .island-item'));
    items2.find(el => el.innerText.includes('Pixel Phone'))?.click();
    await new Promise(r => setTimeout(r, 80));
    const phoneQa = visibleQuickActions();

    return { hostQa, remotePcQa, phoneQa };
})()
""")
            self.assertEqual(
                [x["id"] for x in qa_check["hostQa"]],
                ["btn-qa-lock-pc", "btn-qa-screen", "btn-qa-media", "btn-qa-sync-clipboard", "btn-qa-open-folder", "btn-qa-share-note"],
            )
            self.assertEqual(next(x["label"] for x in qa_check["hostQa"] if x["id"] == "btn-qa-screen"), "Capture PC Screen")

            self.assertEqual(
                [x["id"] for x in qa_check["remotePcQa"]],
                ["btn-qa-lock-pc", "btn-qa-send-files", "btn-qa-browse-files", "btn-qa-media", "btn-qa-share-pc-screen", "btn-qa-share-note"],
            )

            self.assertEqual(
                [x["id"] for x in qa_check["phoneQa"]],
                ["btn-qa-ring", "btn-qa-screen", "btn-qa-camera", "btn-qa-send-files", "btn-qa-media", "btn-qa-share-note"],
            )
            self.assertEqual(next(x["label"] for x in qa_check["phoneQa"] if x["id"] == "btn-qa-screen"), "Capture Screen")

            # 6. Verify /api/files stale sequence guard (filesLoadSeq) + 3 concurrent transfers w/ independent cancel
            files_and_tx = await cdp.eval(r"""
(async () => {
    document.querySelector('.nav-item[data-tab="files"]')?.click();
    await new Promise(r => setTimeout(r, 120));

    // Step A: Stale response sequence guard
    window.__M46__.filesResponseMode = "deferred";
    const openBtns = Array.from(document.querySelectorAll('#file-table-body .btn-open-dir'));
    const slowBtn = openBtns[0];
    const fastBtn = openBtns[1];
    slowBtn?.click();
    await new Promise(r => setTimeout(r, 20));
    fastBtn?.click();
    await new Promise(r => setTimeout(r, 20));

    // Resolve FastDir BEFORE SlowDir
    const okResp = (items) => new Response(JSON.stringify({ success: true, storage_mode: "saf_tree", items }), {
        status: 200, headers: { "Content-Type": "application/json" },
    });
    window.__M46__.fileLoads.get("FastDir")?.(okResp([{ name: "fast_only.txt", is_dir: false, size_bytes: 120 }]));
    await new Promise(r => setTimeout(r, 60));
    const afterFast = Array.from(document.querySelectorAll('#file-table-body tr[data-filename]')).map(tr => tr.dataset.filename);

    // Resolve SlowDir AFTER FastDir -> must NOT overwrite FastDir table!
    window.__M46__.fileLoads.get("SlowDir")?.(okResp([{ name: "stale_dir.txt", is_dir: false, size_bytes: 999 }]));
    await new Promise(r => setTimeout(r, 60));
    const afterStale = Array.from(document.querySelectorAll('#file-table-body tr[data-filename]')).map(tr => tr.dataset.filename);

    // Step B: Reload root cleanly and trigger 4 concurrent downloads (3 active + 1 queued)
    window.__M46__.filesResponseMode = "auto";
    document.getElementById('btn-file-up')?.click();
    await new Promise(r => setTimeout(r, 120));

    const dlBtns = Array.from(document.querySelectorAll('#file-table-body .btn-dl-file'));
    dlBtns.slice(0, 4).forEach(b => b.click());
    await new Promise(r => setTimeout(r, 90));

    const activeCountBeforeCancel = window.__M46__.pendingDownloads.size;
    const rowsBeforeCancel = Array.from(document.querySelectorAll('#files-active-transfer-rows .transfer-row')).map(r => ({
        tid: r.dataset.transferId,
        name: r.querySelector('.transfer-row-name')?.textContent?.trim(),
        dir: r.querySelector('.transfer-row-dir')?.textContent?.trim(),
        speed: r.querySelector('.transfer-row-speed')?.textContent?.trim(),
        pct: r.querySelector('.transfer-row-pct')?.textContent?.trim(),
    }));
    const homeRowsBeforeCancel = document.querySelectorAll('#active-transfer-rows .transfer-row').length;

    // Cancel ONLY row 0 (a.bin) -> b.bin & c.bin must stay active, d.bin promotes from Queued!
    const firstCancelBtn = document.querySelector('#files-active-transfer-rows .transfer-row .btn-transfer-row-cancel');
    const cancelledTid = rowsBeforeCancel[0]?.tid;
    firstCancelBtn?.click();
    await new Promise(r => setTimeout(r, 100));

    const activeFilesAfterCancel = Array.from(window.__M46__.pendingDownloads.values()).map(v => v.file);
    const abortedIds = [...window.__M46__.abortedDownloadIds];
    const cancelPayloads = [...window.__M46__.cancelPayloads];

    // Finish remaining downloads cleanly
    for (const [tid, d] of Array.from(window.__M46__.pendingDownloads.entries())) {
        d.resolve(new Response(JSON.stringify({ success: true, destination_dir: "C:/Snow" }), {
            status: 200, headers: { "Content-Type": "application/json" },
        }));
    }
    await new Promise(r => setTimeout(r, 100));
    const rowsAfterAllDone = document.querySelectorAll('#files-active-transfer-rows .transfer-row').length;

    // Step C: Trigger 4 concurrent uploads via #file-upload-input (3 active XHRs + 1 queued) and cancel only #1
    const dt = new DataTransfer();
    ['up1.txt', 'up2.txt', 'up3.txt', 'up4.txt'].forEach(n => dt.items.add(new File(['hello'], n)));
    const fileInp = document.getElementById('file-upload-input');
    Object.defineProperty(fileInp, 'files', { configurable: true, value: dt.files });
    fileInp.dispatchEvent(new Event('change'));
    await new Promise(r => setTimeout(r, 90));

    const activeXhrBefore = window.__M46__.activeXhrs.map(x => x._fileName);
    const upRowsBefore = document.querySelectorAll('#files-active-transfer-rows .transfer-row').length;
    document.querySelector('#files-active-transfer-rows .transfer-row .btn-transfer-row-cancel')?.click();
    await new Promise(r => setTimeout(r, 90));
    const activeXhrAfterCancel = window.__M46__.activeXhrs.map(x => x._fileName);
    const abortedXhrFiles = [...window.__M46__.abortedXhrFiles];
    for (const x of [...window.__M46__.activeXhrs]) x.completeOk();
    await new Promise(r => setTimeout(r, 90));
    const upRowsAfterDone = document.querySelectorAll('#files-active-transfer-rows .transfer-row').length;

    return {
        afterFast, afterStale,
        activeCountBeforeCancel, rowsBeforeCancel, homeRowsBeforeCancel,
        cancelledTid, activeFilesAfterCancel, abortedIds, cancelPayloads, rowsAfterAllDone,
        activeXhrBefore, upRowsBefore, activeXhrAfterCancel, abortedXhrFiles, upRowsAfterDone,
    };
})()
""")
            self.assertEqual(files_and_tx["afterFast"], ["fast_only.txt"])
            self.assertEqual(files_and_tx["afterStale"], ["fast_only.txt"], "Stale /api/files response overwrote newer folder!")
            self.assertEqual(files_and_tx["activeCountBeforeCancel"], 3, "Expected MAX_CONCURRENT_TRANSFERS = 3 active")
            self.assertEqual(len(files_and_tx["rowsBeforeCancel"]), 4)
            self.assertEqual(files_and_tx["homeRowsBeforeCancel"], 4)
            self.assertEqual([r["name"] for r in files_and_tx["rowsBeforeCancel"]], ["a.bin", "b.bin", "c.bin", "d.bin"])
            self.assertEqual(files_and_tx["rowsBeforeCancel"][3]["speed"], "Queued")
            self.assertEqual(files_and_tx["rowsBeforeCancel"][3]["pct"], "Queued")
            self.assertEqual(files_and_tx["abortedIds"], [files_and_tx["cancelledTid"]])
            self.assertEqual(files_and_tx["cancelPayloads"][0]["transfer_id"], files_and_tx["cancelledTid"])
            self.assertEqual(sorted(files_and_tx["activeFilesAfterCancel"]), ["b.bin", "c.bin", "d.bin"])
            self.assertEqual(files_and_tx["rowsAfterAllDone"], 0)
            self.assertEqual(files_and_tx["activeXhrBefore"], ["up1.txt", "up2.txt", "up3.txt"])
            self.assertEqual(files_and_tx["upRowsBefore"], 4)
            self.assertEqual(files_and_tx["abortedXhrFiles"], ["up1.txt"])
            self.assertEqual(files_and_tx["activeXhrAfterCancel"], ["up2.txt", "up3.txt", "up4.txt"])
            self.assertEqual(files_and_tx["upRowsAfterDone"], 0)

            self.assertEqual(cdp.exceptions, [], f"Uncaught JS exceptions in M4.6 CDP audit: {cdp.exceptions}")
            self.assertEqual(cdp.console_errors, [], f"Console errors in M4.6 CDP audit: {cdp.console_errors}")
        finally:
            await self._shutdown(runner, proc, tmpdir, cdp)


if __name__ == "__main__":
    unittest.main()
