/**
 * SNOW V5 Flagship Web Client — Windows Web V5 Architecture
 * Live Loopback REST / WebSocket Bridge Client for Headless SNOW Core.
 * Strictly offline-first: Zero CDNs, zero inline handlers (CSP strict), 100% route parity.
 */

(function () {
    "use strict";

    // =========================================================================
    // Core Utilities & Constants
    // =========================================================================

    function escapeHtml(str) {
        if (str === null || str === undefined) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function formatBytes(bytes) {
        if (bytes === null || bytes === undefined || isNaN(bytes) || bytes < 0) return "--";
        if (bytes === 0) return "0 B";
        const gb = bytes / (1024 * 1024 * 1024);
        if (gb >= 1) return gb.toFixed(1) + " GB";
        const mb = bytes / (1024 * 1024);
        if (mb >= 1) return mb.toFixed(1) + " MB";
        const kb = bytes / 1024;
        if (kb >= 1) return kb.toFixed(0) + " KB";
        return bytes + " B";
    }

    function formatTimestamp(ts) {
        if (!ts && ts !== 0) return "";
        try {
            if (typeof ts === "number" || (/^\d+(\.\d+)?$/.test(String(ts).trim()))) {
                const rawNum = Number(ts);
                const ms = rawNum > 1e12 ? rawNum : rawNum * 1000;
                const d = new Date(ms);
                if (!isNaN(d.getTime())) {
                    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
                }
            }
            const d = new Date(ts);
            if (!isNaN(d.getTime())) {
                return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
            }
        } catch (e) {}
        return String(ts);
    }

    function showNotificationToast(msg, type = "info") {
        if (!msg) return;
        let container = document.getElementById("toast-container");
        if (!container) {
            container = document.createElement("div");
            container.id = "toast-container";
            document.body.appendChild(container);
        }

        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        if (type === "error") {
            toast.style.borderColor = "var(--snow-accent-rose)";
            toast.style.color = "var(--snow-status-rose-text)";
        } else if (type === "success") {
            toast.style.borderColor = "var(--snow-accent-emerald)";
            toast.style.color = "var(--snow-status-emerald-text)";
        } else if (type === "warning") {
            toast.style.borderColor = "var(--snow-accent-amber)";
            toast.style.color = "var(--snow-status-amber-text)";
        }
        toast.textContent = msg;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transition = "opacity 0.2s ease";
            setTimeout(() => toast.remove(), 250);
        }, 3500);
    }
    window.showNotificationToast = showNotificationToast;

    const TITLE_MAP = {
        overview: "Home",
        devices: "Devices & Network",
        files: "Files & Apps",
        clipboard: "Clipboard History",
        apps: "Android Applications",
        settings: "AI & Settings",
    };

    // Global Application State
    let csrfToken = "";
    let currentTab = "overview";
    let activeDeviceId = "";
    let hasUserSelectedDevice = false;
    let currentSubpath = "";
    let currentRemoteParent = "";
    let currentStorageMode = "saf_tree";
    let isCorePaused = false;
    let isCoreOnline = true;
    let registeredDevices = [];
    let federationGrants = [];
    let activeNotifications = [];
    let pollIntervalTimer = null;
    let qrCountdownTimer = null;
    let currentDeviceFilter = "all";
    let currentFilesSegment = "files";
    let replyingNotificationKey = "";
    const openNotificationReplyKeys = new Set();
    const notificationReplyDrafts = new Map();
    let localHostIdentity = "This PC";
    let localHostDeviceId = "";
    let localHostTelemetry = {};
    let canonicalSnowId = "SNW-LOCAL";
    let activeUploadXhr = null;
    let activeDownloadController = null;
    let pcTransfersDestDir = "";
    let pendingUpdateMeta = null;
    let modalPurposeMode = "share"; // "share" | "clipboard"
    let screenStreamTimer = null;
    let isScreenStatusPolling = false;
    let isScreenFrameInFlight = false;
    let isPollStateInFlight = false;
    let pollStateSeq = 0;
    let isHomeWidgetsInFlight = false;
    let homeWidgetsSeq = 0;
    let screenFrameErrorCount = 0;
    let lastKnownStreamState = "IDLE";
    let isCaptureStreamActive = false;
    let selectedScreenSenderId = "";
    let activeScreenSenders = [];
    let isPcScreenSharing = false;
    let eligiblePcShareTargets = [];
    let lastCaptureTitle = "Capture Preview";
    let lastFocusedBeforeLightbox = null;
    let revealedIpcSecret = "";
    let lastPairingSnapshotHasActivePin = false;
    let lastStatusSnapshot = null;

    async function withButtonLoading(btn, loadingLabel, asyncFn) {
        if (!btn) {
            return await asyncFn();
        }
        if (btn.dataset.loading === "1") {
            return null;
        }
        const originalHtml = btn.innerHTML;
        const originalDisabled = btn.disabled;
        btn.dataset.loading = "1";
        btn.disabled = true;
        btn.classList.add("btn-loading");
        btn.setAttribute("aria-busy", "true");
        if (loadingLabel) {
            btn.textContent = loadingLabel;
        }
        try {
            return await asyncFn();
        } finally {
            delete btn.dataset.loading;
            btn.classList.remove("btn-loading");
            btn.removeAttribute("aria-busy");
            btn.innerHTML = originalHtml;
            btn.disabled = originalDisabled;
        }
    }

    function clearRevealedIpcSecret() {
        revealedIpcSecret = "";
        const inp = document.getElementById("diag-ipc-secret-value");
        const toggleBtn = document.getElementById("btn-ipc-secret-toggle");
        if (inp) {
            inp.type = "password";
            inp.value = "••••••••••••••••";
        }
        if (toggleBtn) toggleBtn.textContent = "Reveal";
    }

    // =========================================================================
    // API Helpers & Identity Classification
    // =========================================================================

    async function apiRequest(endpoint, method = "GET", data = null, reqOpts = {}) {
        const headers = { "Content-Type": "application/json" };
        if (csrfToken && method !== "GET" && method !== "HEAD") {
            headers["X-CSRF-Token"] = csrfToken;
        }

        const timeoutMs = (reqOpts && Number(reqOpts.timeoutMs) > 0) ? Number(reqOpts.timeoutMs) : 5000;
        const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
        const timeoutId = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

        const options = { method, headers };
        if (controller) options.signal = controller.signal;
        if (data !== null && (method === "POST" || method === "PUT" || method === "DELETE")) {
            options.body = JSON.stringify(data);
        }

        try {
            const resp = await fetch(endpoint, options);
            if (resp.status === 401 || resp.status === 403) {
                clearRevealedIpcSecret();
            }
            if (resp.status === 403) {
                const errData = await resp.json().catch(() => ({}));
                if (errData.status === "SESSION_EXPIRED" || errData.status === "INVALID_TOKEN") {
                    showNotificationToast("Session expired. Reconnecting...", "warning");
                    window.location.reload();
                }
                return errData;
            }
            return await resp.json();
        } catch (err) {
            if (err && err.name === "AbortError") {
                return { success: false, status: "TIMEOUT", error: "Request timed out" };
            }
            return { success: false, error: err.message || "Network request failed" };
        } finally {
            if (timeoutId !== null) clearTimeout(timeoutId);
        }
    }

    function isLocalNode(d) {
        if (!d) return false;
        return Boolean(
            d.is_local ||
            d.device_id === "local" ||
            d.device_id === "desktop-core" ||
            (localHostDeviceId && d.device_id === localHostDeviceId) ||
            (canonicalSnowId && canonicalSnowId !== "SNW-LOCAL" && d.snow_id === canonicalSnowId) ||
            d.transport === "local" ||
            (d.device_name && (d.device_name.includes("(This PC)") || d.device_name.includes("(Host)")))
        );
    }

    function isAndroidDevice(d) {
        if (!d) return false;
        return d.platform === "android" || d.device_type === "phone" || d.device_type === "android";
    }

    function resolveTransportLabel(dev) {
        if (!dev) return "Offline";
        if (isLocalNode(dev)) return "Host";
        const t = String(dev.transport || "").toLowerCase();
        const ep = String(dev.endpoint || "");
        if (t === "usb" || ep.includes("127.0.0.1")) return "USB";
        if (t === "relay" || ep.includes("/v1/tunnel")) return "Remote";
        if (t === "peer") return "Direct Peer";
        return "Wi-Fi";
    }

    function parseHostAndPort(rawInput) {
        const trimmed = String(rawInput || "").trim();
        if (!trimmed) return null;
        if (trimmed.includes(":")) {
            const parts = trimmed.split(":");
            const port = parseInt(parts[parts.length - 1], 10);
            const host = parts.slice(0, -1).join(":").trim();
            if (host && !isNaN(port) && port > 0 && port <= 65535) {
                return { host, port };
            }
        }
        return { host: trimmed, port: 8765 };
    }

    // =========================================================================
    // 1. Session Bootstrap & Lifecycle
    // =========================================================================

    async function initSession() {
        const hash = window.location.hash.substring(1);
        const params = new URLSearchParams(hash);
        const bootstrapToken = params.get("token");

        if (bootstrapToken) {
            history.replaceState(null, "", window.location.pathname);
        }

        const authStatus = document.getElementById("auth-status-text");
        const authOverlay = document.getElementById("auth-overlay");

        try {
            if (bootstrapToken) {
                if (authStatus) authStatus.textContent = "Verifying single-use bootstrap token...";
                const res = await fetch("/api/auth/session", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ token: bootstrapToken }),
                });
                const data = await res.json();
                if (data.success && data.csrf_token) {
                    csrfToken = data.csrf_token;
                    if (authOverlay) authOverlay.classList.add("d-none");
                    startDashboard();
                    return;
                }
            }

            // Probe existing session via /api/status
            const statusRes = await fetch("/api/status");
            if (statusRes.ok) {
                const statusData = await statusRes.json();
                if (statusData && statusData.csrf_token) {
                    csrfToken = statusData.csrf_token;
                    if (authOverlay) authOverlay.classList.add("d-none");
                    startDashboard();
                    return;
                }
            }

            if (authOverlay) authOverlay.classList.add("d-none");
            startDashboard();
        } catch (err) {
            if (authStatus) authStatus.textContent = "SNOW Core unreachable on 127.0.0.1:8769.";
            if (authOverlay) authOverlay.classList.add("d-none");
            startDashboard();
        }
    }

    function startDashboard() {
        initTheming();
        initSidebar();
        initNavigation();
        initDeviceIsland();
        initCommandPalette();
        initHomeHub();
        initDevicesView();
        initFilesView();
        initClipboardView();
        initAiSettingsView();
        initModals();

        refreshAllData();
        if (pollIntervalTimer) clearInterval(pollIntervalTimer);
        pollIntervalTimer = setInterval(pollStateUpdates, 3000);
    }

    // =========================================================================
    // 2. Theming (System, Light Mode, Dark Mode)
    // =========================================================================

    function initTheming() {
        const savedTheme = localStorage.getItem("snow_theme") || "system";
        applyTheme(savedTheme);

        const btnThemeToggle = document.getElementById("btn-theme-toggle");
        if (btnThemeToggle) {
            btnThemeToggle.addEventListener("click", () => {
                const isDarkNow = document.documentElement.classList.contains("theme-dark");
                const next = isDarkNow ? "light" : "dark";
                localStorage.setItem("snow_theme", next);
                applyTheme(next);
            });
        }

        ["system", "light", "dark"].forEach(themeKey => {
            const radio = document.getElementById(`theme-opt-${themeKey}`);
            if (radio) {
                radio.checked = (savedTheme === themeKey);
                radio.addEventListener("change", () => {
                    if (radio.checked) {
                        localStorage.setItem("snow_theme", themeKey);
                        applyTheme(themeKey);
                    }
                });
            }
        });

        if (window.matchMedia) {
            window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
                const current = localStorage.getItem("snow_theme") || "system";
                if (current === "system") {
                    applyTheme("system");
                }
            });
        }
    }

    function applyTheme(themeChoice) {
        let isDark = false;
        if (themeChoice === "dark") {
            isDark = true;
        } else if (themeChoice === "light") {
            isDark = false;
        } else {
            isDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
        }

        document.documentElement.className = isDark ? "theme-dark" : "theme-light";

        const sunIcon = document.getElementById("theme-icon-sun");
        const moonIcon = document.getElementById("theme-icon-moon");
        if (sunIcon && moonIcon) {
            sunIcon.classList.toggle("d-none", !isDark);
            moonIcon.classList.toggle("d-none", isDark);
        }

        ["system", "light", "dark"].forEach(k => {
            const radio = document.getElementById(`theme-opt-${k}`);
            if (radio) radio.checked = (themeChoice === k);
        });
    }

    // =========================================================================
    // 3. Sidebar Rail & Core Controls
    // =========================================================================

    function initSidebar() {
        const sidebar = document.getElementById("main-sidebar");
        const toggleBtn = document.getElementById("btn-sidebar-toggle");
        const isCollapsed = localStorage.getItem("snow_sidebar_collapsed") === "true";

        if (sidebar && isCollapsed) {
            sidebar.classList.add("collapsed");
        }

        if (toggleBtn && sidebar) {
            toggleBtn.addEventListener("click", () => {
                sidebar.classList.toggle("collapsed");
                localStorage.setItem("snow_sidebar_collapsed", String(sidebar.classList.contains("collapsed")));
            });
        }

        const btnDisconnectAll = document.getElementById("btn-desktop-disconnect-all");
        if (btnDisconnectAll) {
            btnDisconnectAll.addEventListener("click", async () => {
                await withButtonLoading(btnDisconnectAll, "Disconnecting...", async () => {
                    const res = await apiRequest("/api/devices/disconnect-all", "POST", {});
                    if (res && res.success) {
                        const count = Number(res.disconnected_count ?? res.data?.disconnected_count ?? 0);
                        showNotificationToast(
                            count > 0
                                ? `Disconnected ${count} active session(s). Pairings preserved.`
                                : "No active remote device sessions.",
                            "info"
                        );
                        refreshAllData();
                    } else {
                        showNotificationToast(res?.error || "Failed disconnecting devices", "error");
                    }
                });
            });
        }

        const btnPoweroff = document.getElementById("btn-desktop-poweroff");
        const poweroffModal = document.getElementById("poweroff-modal");
        const btnPoweroffCancel = document.getElementById("btn-poweroff-cancel");
        const btnPoweroffConfirm = document.getElementById("btn-poweroff-confirm");

        if (btnPoweroff && poweroffModal) {
            btnPoweroff.addEventListener("click", () => poweroffModal.classList.remove("d-none"));
        }
        if (btnPoweroffCancel && poweroffModal) {
            btnPoweroffCancel.addEventListener("click", () => poweroffModal.classList.add("d-none"));
        }
        if (btnPoweroffConfirm) {
            btnPoweroffConfirm.addEventListener("click", async () => {
                showNotificationToast("Initiating SNOW Desktop shutdown...", "warning");
                await apiRequest("/api/system/shutdown", "POST", { reason: "Owner initiated power-off" });
                if (poweroffModal) poweroffModal.classList.add("d-none");
                document.body.innerHTML = `
                    <div style="display:flex;height:100vh;align-items:center;justify-content:center;flex-direction:column;background:var(--snow-bg-canvas);color:var(--snow-text-primary);text-align:center;gap:12px;">
                        <h2 style="font-size:20px;font-weight:700;">SNOW Desktop Core Has Shut Down</h2>
                        <p class="text-sm text-muted">All local background processes have terminated cleanly. You may close this tab.</p>
                    </div>
                `;
            });
        }
    }

    function updateCoreStatusBadge() {
        const dot = document.getElementById("core-status-dot");
        const text = document.getElementById("core-status-text");

        if (!dot || !text) return;
        if (!isCoreOnline) {
            dot.className = "status-dot dot-offline";
            text.textContent = "Core Offline";
        } else if (isCorePaused) {
            dot.className = "status-dot dot-paused";
            text.textContent = "Core Paused";
        } else {
            dot.className = "status-dot dot-active";
            text.textContent = "Core Online";
        }
    }

    // =========================================================================
    // 4. Navigation & Views Switching
    // =========================================================================

    function initNavigation() {
        document.querySelectorAll(".nav-menu .nav-item").forEach(item => {
            item.addEventListener("click", () => {
                const tab = item.getAttribute("data-tab");
                if (tab) switchTab(tab);
            });
        });

        const btnBell = document.getElementById("btn-topbar-approvals");
        if (btnBell) {
            btnBell.addEventListener("click", () => {
                switchTab("settings");
                document.querySelector(".approvals-activity-card")?.scrollIntoView({ behavior: "smooth" });
            });
        }

        const refreshBtn = document.getElementById("btn-global-refresh");
        if (refreshBtn) {
            refreshBtn.addEventListener("click", () => {
                refreshAllData();
                showNotificationToast("Refreshed live data.", "info");
            });
        }
    }

    function switchTab(tabId) {
        if (currentTab !== tabId) {
            clearRevealedIpcSecret();
        }
        currentTab = tabId;
        if (TITLE_MAP[tabId]) {
            document.title = `SNOW — ${TITLE_MAP[tabId]}`;
        }

        document.querySelectorAll(".nav-item").forEach(item => {
            const isMatch = item.getAttribute("data-tab") === tabId;
            item.classList.toggle("active", isMatch);
            item.setAttribute("aria-selected", isMatch ? "true" : "false");
        });

        document.querySelectorAll(".tab-pane").forEach(pane => {
            pane.classList.toggle("active", pane.id === `section-${tabId}`);
        });

        if (tabId === "overview") {
            const dev = getSelectedDeviceObj();
            updateHeroCard(dev);
            loadHomeWidgets();
        } else if (tabId === "devices") {
            renderDevicesView();
        } else if (tabId === "files") {
            loadFiles(currentSubpath);
            loadRemoteApps();
        } else if (tabId === "clipboard") {
            loadClipboardItems();
        } else if (tabId === "settings") {
            loadAiSettingsView();
        }
    }

    // =========================================================================
    // 5. Floating Device Selector Island
    // =========================================================================

    function getSelectedDeviceObj() {
        if (!activeDeviceId || activeDeviceId === "local") return null;
        return registeredDevices.find(d => d.device_id === activeDeviceId) || null;
    }

    function initDeviceIsland() {
        const capsule = document.getElementById("topbar-device-capsule");
        const container = document.getElementById("device-island-container");
        const btnIslandConnect = document.getElementById("btn-island-connect");

        if (capsule && container) {
            capsule.addEventListener("click", (e) => {
                e.stopPropagation();
                container.classList.toggle("d-none");
            });
            container.addEventListener("click", (e) => {
                if (e.target === container) container.classList.add("d-none");
            });
        }

        if (btnIslandConnect) {
            btnIslandConnect.addEventListener("click", () => {
                container?.classList.add("d-none");
                openConnectModal();
            });
        }

        document.getElementById("btn-topbar-connect")?.addEventListener("click", openConnectModal);
    }

    function renderDeviceIsland() {
        const pairedContainer = document.getElementById("island-paired-devices");
        const networkIdBadge = document.getElementById("island-network-id");
        const localNameEl = document.getElementById("island-local-name");
        const localHostRow = document.getElementById("island-local-host");
        const fedContainer = document.getElementById("island-federation-peers");
        const fedEmpty = document.getElementById("island-federation-empty");

        if (networkIdBadge) networkIdBadge.textContent = canonicalSnowId;
        if (localNameEl) localNameEl.textContent = localHostIdentity;

        if (localHostRow) {
            const isLocalActive = !activeDeviceId || activeDeviceId === "local";
            localHostRow.classList.toggle("active", isLocalActive);
            localHostRow.onclick = () => {
                selectActiveDevice("local", true);
                document.getElementById("device-island-container")?.classList.add("d-none");
            };
        }

        if (pairedContainer) {
            pairedContainer.innerHTML = "";
            const nonLocal = registeredDevices.filter(d => !isLocalNode(d));
            if (nonLocal.length === 0) {
                pairedContainer.innerHTML = `<span class="text-xs text-muted" style="padding: 4px;">No paired devices yet. Click Connect to pair.</span>`;
            } else {
                nonLocal.forEach(dev => {
                    const isSelected = (dev.device_id === activeDeviceId);
                    const isConn = Boolean(dev.is_connected);
                    const row = document.createElement("div");
                    row.className = `island-item ${isSelected ? "active" : ""}`;

                    const transport = resolveTransportLabel(dev);
                    const dotClass = isConn ? "dot-active" : "dot-paused";
                    const batVal = dev.telemetry?.battery_level ?? dev.battery?.level ?? dev.battery_level;
                    const batPart = (batVal !== null && batVal !== undefined) ? ` • ${batVal}%` : "";
                    const iconSvg = isAndroidDevice(dev)
                        ? `<svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><rect height="20" rx="2" ry="2" width="14" x="5" y="2"></rect><line x1="12" x2="12.01" y1="18" y2="18"></line></svg>`
                        : `<svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><rect height="12" rx="2" width="20" x="2" y="4"></rect><line x1="2" x2="22" y1="20" y2="20"></line></svg>`;

                    row.innerHTML = `
                        <div class="island-device-info min-w-0">
                            <div class="island-icon-box">${iconSvg}</div>
                            <div class="flex flex-col min-w-0">
                                <span class="text-sm font-semibold text-primary leading-tight truncate">${escapeHtml(dev.device_name || "Device")}</span>
                                <span class="text-xs text-muted flex items-center gap-1">
                                    <span class="status-dot ${dotClass}" style="width:6px;height:6px;"></span>
                                    <span>${isConn ? transport : "Offline"}${batPart} • ${escapeHtml((dev.snow_id || dev.device_id).slice(0, 13).replace(/-$/, ""))}</span>
                                </span>
                            </div>
                        </div>
                        ${isSelected ? `<svg class="svg-icon svg-icon-sm text-cyan" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg>` : ""}
                    `;

                    row.addEventListener("click", () => {
                        selectActiveDevice(dev.device_id, true);
                        document.getElementById("device-island-container")?.classList.add("d-none");
                    });
                    pairedContainer.appendChild(row);
                });
            }
        }

        // Render Section 2: OTHER NETWORKS (Active Federated Grants)
        if (fedContainer && fedEmpty) {
            fedContainer.innerHTML = "";
            const activeGrants = (federationGrants || []).filter(g => String(g.status || "ACTIVE").toUpperCase() === "ACTIVE");
            if (activeGrants.length === 0) {
                fedEmpty.classList.remove("d-none");
            } else {
                fedEmpty.classList.add("d-none");
                activeGrants.forEach(g => {
                    const row = document.createElement("div");
                    row.className = "island-item";
                    const peerLabel = g.network_name || g.peer_node_name || g.peer_node_id || g.grant_id;
                    const caps = Array.isArray(g.allowed_capabilities) && g.allowed_capabilities.length > 0
                        ? g.allowed_capabilities.slice(0, 2).join(", ")
                        : "Scoped Access";
                    row.innerHTML = `
                        <div class="island-device-info min-w-0">
                            <div class="island-icon-box">
                                <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="2" x2="22" y1="12" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
                            </div>
                            <div class="flex flex-col min-w-0">
                                <span class="text-sm font-semibold text-primary truncate">${escapeHtml(peerLabel)}</span>
                                <span class="text-xs text-muted truncate">${escapeHtml(g.direction || "INBOUND")} • ${escapeHtml(caps)}</span>
                            </div>
                        </div>
                        <span class="chip chip-sm chip-cyan">Federated</span>
                    `;
                    row.addEventListener("click", () => {
                        document.getElementById("device-island-container")?.classList.add("d-none");
                        switchTab("devices");
                    });
                    fedContainer.appendChild(row);
                });
            }
        }

        // Sync hidden selects for Files & Topbar
        syncDeviceSelectDropdowns();
    }

    function syncDeviceSelectDropdowns() {
        const filesSel = document.getElementById("files-device-select");
        if (filesSel) {
            filesSel.innerHTML = `<option value="local">${escapeHtml(localHostIdentity)} (Host)</option>`;
            registeredDevices.filter(d => !isLocalNode(d)).forEach(d => {
                const opt = document.createElement("option");
                opt.value = d.device_id;
                const st = d.is_connected ? resolveTransportLabel(d) : "Offline";
                opt.textContent = `${d.device_name || "Device"} (${st})`;
                if (d.device_id === activeDeviceId) opt.selected = true;
                filesSel.appendChild(opt);
            });
            if (!activeDeviceId || activeDeviceId === "local") {
                filesSel.value = "local";
            }
        }
    }

    function updateTopbarCapsule(dev) {
        const nameEl = document.getElementById("topbar-device-name");
        const chipEl = document.getElementById("topbar-device-transport-chip");
        const dotEl = document.getElementById("topbar-device-dot");

        if (!dev || isLocalNode(dev)) {
            if (nameEl) nameEl.textContent = localHostIdentity;
            if (chipEl) {
                chipEl.textContent = "Host";
                chipEl.className = "chip chip-sm chip-emerald";
            }
            if (dotEl) dotEl.className = isCoreOnline ? "status-dot dot-active" : "status-dot dot-offline";
        } else {
            const isConn = Boolean(dev.is_connected);
            const transport = isConn ? resolveTransportLabel(dev) : "Disconnected";
            if (nameEl) nameEl.textContent = dev.device_name || "Device";
            if (chipEl) {
                chipEl.textContent = transport;
                chipEl.className = isConn ? "chip chip-sm chip-cyan" : "chip chip-sm chip-amber";
            }
            if (dotEl) dotEl.className = isConn ? "status-dot dot-active" : "status-dot dot-paused";
        }
    }

    function selectActiveDevice(deviceId, userExplicit = false) {
        activeDeviceId = deviceId || "local";
        if (userExplicit) hasUserSelectedDevice = true;
        currentSubpath = "";
        currentRemoteParent = "";

        const dev = getSelectedDeviceObj();
        updateTopbarCapsule(dev);
        renderDeviceIsland();

        if (currentTab === "overview") updateHeroCard(dev);
        else if (currentTab === "devices") renderDevicesView();
        else if (currentTab === "files") {
            loadFiles(currentSubpath);
            loadRemoteApps();
        }
    }

    // =========================================================================
    // 6. View 1: Home Hub (Hero, Transfers, Quick Actions, Media, Clip, Notifs)
    // =========================================================================

    function initHomeHub() {
        const wallpaperImg = document.getElementById("desktop-wallpaper-img");
        const wallpaperFallback = document.getElementById("wallpaper-fallback");
        if (wallpaperImg) {
            wallpaperImg.addEventListener("error", () => {
                wallpaperImg.style.display = "none";
                if (wallpaperFallback) wallpaperFallback.style.display = "flex";
            });
            wallpaperImg.addEventListener("load", () => {
                wallpaperImg.style.display = "block";
                if (wallpaperFallback) wallpaperFallback.style.display = "none";
            });
        }

        const mediaPreviewImg = document.getElementById("media-preview-img");
        if (mediaPreviewImg) {
            mediaPreviewImg.addEventListener("error", () => {
                mediaPreviewImg.alt = "Preview unavailable";
            });
        }

        document.getElementById("btn-hero-lock-pc")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Locking...", async () => {
                const res = await apiRequest("/api/desktop/lock", "POST", {});
                if (res && res.success) {
                    showNotificationToast("Windows workstation locked.", "success");
                } else {
                    showNotificationToast(res?.error || "Failed locking workstation", "error");
                }
            });
        });

        const fileInput = document.getElementById("file-upload-input");
        document.getElementById("btn-hero-send-file")?.addEventListener("click", () => {
            if (fileInput) fileInput.click();
        });
        document.getElementById("btn-hero-ring-phone")?.addEventListener("click", (e) => triggerRingPhone(e.currentTarget));
        document.getElementById("btn-hero-capture-screen")?.addEventListener("click", (e) => triggerScreenCapture(e.currentTarget));
        document.getElementById("btn-hero-retry-link")?.addEventListener("click", () => {
            refreshAllData();
            showNotificationToast("Checking device connection...", "info");
        });
        document.getElementById("btn-hero-switch-device")?.addEventListener("click", () => {
            document.getElementById("device-island-container")?.classList.remove("d-none");
        });

        // Quick Actions 2x3 Grid
        document.getElementById("btn-qa-ring")?.addEventListener("click", (e) => triggerRingPhone(e.currentTarget));
        document.getElementById("btn-qa-screen")?.addEventListener("click", (e) => triggerScreenCapture(e.currentTarget));
        document.getElementById("btn-qa-camera")?.addEventListener("click", (e) => triggerCameraCapture(e.currentTarget));
        document.getElementById("btn-qa-media")?.addEventListener("click", () => triggerMediaAction("play_pause"));
        document.getElementById("btn-qa-send-files")?.addEventListener("click", () => {
            if (fileInput) fileInput.click();
        });
        document.getElementById("btn-qa-share-note")?.addEventListener("click", () => openTextModal("share"));

        // Media Controls Bar (Prev, Play/Pause, Next, Mute, Volume)
        document.getElementById("btn-media-prev")?.addEventListener("click", () => triggerMediaAction("prev"));
        document.getElementById("btn-media-play")?.addEventListener("click", () => triggerMediaAction("play_pause"));
        document.getElementById("btn-media-next")?.addEventListener("click", () => triggerMediaAction("next"));
        document.getElementById("btn-media-mute")?.addEventListener("click", () => triggerMediaAction("mute"));

        const volSlider = document.getElementById("now-playing-volume");
        if (volSlider) {
            volSlider.addEventListener("change", () => {
                const level = Math.max(0, Math.min(100, parseInt(volSlider.value, 10) || 0));
                triggerMediaAction("volume_set", { value: level });
            });
        }

        // Clipboard Instant Sync toggle sync
        const homeSyncToggle = document.getElementById("clipboard-instant-sync-toggle");
        if (homeSyncToggle) {
            homeSyncToggle.addEventListener("change", async () => {
                const clipSyncToggle = document.getElementById("clipview-instant-sync-toggle");
                if (clipSyncToggle) clipSyncToggle.checked = homeSyncToggle.checked;
                await apiRequest("/api/clipboard/sync", "POST", { direction: "both", device_id: resolveTargetDeviceId() });
                showNotificationToast(`Instant clipboard sync ${homeSyncToggle.checked ? "triggered" : "paused"}.`, "info");
            });
        }

        // Active Transfer Cancel (supports both upload XHR and active downloads)
        document.getElementById("btn-active-transfer-cancel")?.addEventListener("click", cancelActiveTransfer);
        document.getElementById("btn-files-transfer-cancel")?.addEventListener("click", cancelActiveTransfer);

        document.getElementById("btn-share-pc-screen")?.addEventListener("click", openPcSharePicker);
        document.getElementById("btn-stop-pc-share")?.addEventListener("click", stopPcScreenShare);
        document.getElementById("btn-close-pc-share-modal")?.addEventListener("click", () => {
            document.getElementById("pc-share-targets-modal")?.classList.add("d-none");
        });
        document.getElementById("btn-pc-share-cancel")?.addEventListener("click", () => {
            document.getElementById("pc-share-targets-modal")?.classList.add("d-none");
        });
        document.getElementById("btn-pc-share-confirm")?.addEventListener("click", confirmStartPcScreenShare);
        document.getElementById("btn-stop-screen-stream")?.addEventListener("click", stopRemoteScreenStream);
        document.getElementById("btn-enlarge-capture")?.addEventListener("click", () => {
            const latestImg = document.getElementById("latest-capture-img");
            if (latestImg && latestImg.getAttribute("src")) {
                openMediaPreview(latestImg.src, lastCaptureTitle, isCaptureStreamActive);
            }
        });
        document.getElementById("btn-retry-screen-stream")?.addEventListener("click", () => {
            screenFrameErrorCount = 0;
            pollScreenStreamStatus();
        });
        document.addEventListener("visibilitychange", () => {
            if (!document.hidden && isCaptureStreamActive) {
                fetchNextScreenFrame();
            }
        });

        document.getElementById("btn-hero-refresh-wallpaper")?.addEventListener("click", () => {
            const img = document.getElementById("desktop-wallpaper-img");
            if (img) img.src = `/api/desktop/wallpaper?t=${Date.now()}`;
            showNotificationToast("Refreshing desktop wallpaper...", "info");
        });
    }

    function resolveTargetDeviceId() {
        if (activeDeviceId && activeDeviceId !== "local") return activeDeviceId;
        const firstPhone = registeredDevices.find(d => !isLocalNode(d) && d.is_connected);
        return firstPhone ? firstPhone.device_id : "";
    }

    async function triggerRingPhone(triggerBtn = null) {
        const targetId = resolveTargetDeviceId();
        if (!targetId) {
            showNotificationToast("Select or connect an online Android phone first.", "warning");
            return;
        }
        await withButtonLoading(triggerBtn instanceof Element ? triggerBtn : null, "", async () => {
            const res = await apiRequest("/api/devices/ring", "POST", { device_id: targetId, duration_seconds: 5 });
            if (res && res.success) {
                showNotificationToast("Phone ringer triggered!", "success");
            } else {
                showNotificationToast(res?.error || "Failed triggering ringer", "error");
            }
        });
    }

    async function triggerScreenCapture(triggerBtn = null) {
        const targetId = resolveTargetDeviceId();
        if (!targetId) {
            showNotificationToast("Select or connect an online phone for screen capture.", "warning");
            return;
        }
        const statusText = document.getElementById("latest-capture-status-text");
        if (statusText) statusText.textContent = "Awaiting phone consent for one-time screen capture...";

        let baselineFilename = "";
        try {
            const preResp = await fetch(`/api/screen/capture-latest?t=${Date.now()}`);
            if (preResp.status === 200) baselineFilename = preResp.headers.get("X-Snow-Filename") || "";
        } catch (e) {}

        const res = await withButtonLoading(triggerBtn instanceof Element ? triggerBtn : null, "", () =>
            apiRequest("/api/screen/capture-phone", "POST", { device_id: targetId })
        );
        if (res && res.success) {
            const fileName = res.file_name || res.data?.file_name;
            if (fileName) {
                const capUrl = `/api/captures/${encodeURIComponent(fileName)}?t=${Date.now()}`;
                showCapturePreview(capUrl, "Remote Screen Capture");
                showNotificationToast("Screen capture received!", "success");
                return;
            }
        }

        const errStr = String(res?.error || res?.status || "");
        const awaitingConsent = res?.success || errStr.includes("SCREEN_CAPTURE_CONSENT_REQUIRED") || errStr.includes("consent");
        if (!awaitingConsent && res && !res.success) {
            if (statusText) statusText.textContent = errStr || "Screen capture failed";
            showNotificationToast(errStr || "Failed initiating screen capture", "error");
            return;
        }

        if (errStr.includes("SCREEN_CAPTURE_CONSENT_REQUIRED")) {
            showNotificationToast("Tap the Screen Capture notification on your phone to capture.", "info");
        }

        let attempts = 0;
        let inFlight = false;
        const pollTimer = setInterval(async () => {
            if (inFlight) return;
            inFlight = true;
            try {
                attempts++;
                const capResp = await fetch(`/api/screen/capture-latest?t=${Date.now()}`);
                if (capResp.status === 200) {
                    const fname = capResp.headers.get("X-Snow-Filename") || "";
                    if (fname && fname !== baselineFilename) {
                        clearInterval(pollTimer);
                        showCapturePreview(`/api/captures/${encodeURIComponent(fname)}?t=${Date.now()}`, "Remote Screen Capture");
                        showNotificationToast("Screen capture received!", "success");
                        return;
                    }
                }
                if (attempts >= 25) {
                    clearInterval(pollTimer);
                    if (statusText) statusText.textContent = "Screen capture consent timed out or was cancelled.";
                    showNotificationToast("Screen capture consent timed out or was cancelled.", "warning");
                }
            } finally {
                inFlight = false;
            }
        }, 1000);
    }

    function setScreenViewerState(mode, subtitle = "") {
        const badge = document.getElementById("screen-stream-badge");
        const stopBtn = document.getElementById("btn-stop-screen-stream");
        const enlargeBtn = document.getElementById("btn-enlarge-capture");
        const img = document.getElementById("latest-capture-img");
        const placeholder = document.getElementById("latest-capture-placeholder");
        const statusText = document.getElementById("latest-capture-status-text");
        const retryBtn = document.getElementById("btn-retry-screen-stream");
        const metaEl = document.getElementById("screen-stream-meta");

        if (mode === "STREAMING") {
            isCaptureStreamActive = true;
            if (badge) {
                badge.textContent = "Live Stream";
                badge.className = "chip chip-sm chip-emerald";
            }
            stopBtn?.classList.remove("d-none");
            retryBtn?.classList.add("d-none");
            if (metaEl) {
                metaEl.textContent = subtitle || "Streaming live from Android";
                metaEl.classList.remove("d-none");
            }
        } else if (mode === "ERROR") {
            isCaptureStreamActive = false;
            if (badge) {
                badge.textContent = "Stream Error";
                badge.className = "chip chip-sm chip-rose";
            }
            stopBtn?.classList.add("d-none");
            if (img) img.style.display = "none";
            enlargeBtn?.classList.add("d-none");
            placeholder?.classList.remove("d-none");
            if (statusText) statusText.textContent = subtitle || "Failed loading live screen frame.";
            retryBtn?.classList.remove("d-none");
            metaEl?.classList.add("d-none");
        } else if (mode === "STOPPED") {
            isCaptureStreamActive = false;
            if (badge) {
                badge.textContent = "Stopped";
                badge.className = "chip chip-sm chip-amber";
            }
            stopBtn?.classList.add("d-none");
            retryBtn?.classList.add("d-none");
            if (img && !img.getAttribute("src")) {
                placeholder?.classList.remove("d-none");
                enlargeBtn?.classList.add("d-none");
            }
            if (statusText) statusText.textContent = subtitle || "Live screen stream stopped.";
            if (metaEl) {
                metaEl.textContent = subtitle || "Live stream ended";
                metaEl.classList.remove("d-none");
            }
        } else {
            isCaptureStreamActive = false;
            if (badge) {
                badge.textContent = "Standby";
                badge.className = "chip chip-sm chip-neutral";
            }
            stopBtn?.classList.add("d-none");
            retryBtn?.classList.add("d-none");
            metaEl?.classList.add("d-none");
        }

        const lbStop = document.getElementById("btn-lightbox-stop-stream");
        const lbBadge = document.getElementById("media-preview-stream-badge");
        lbStop?.classList.toggle("d-none", !isCaptureStreamActive);
        lbBadge?.classList.toggle("d-none", !isCaptureStreamActive);
    }

    function renderSenderSwitcher(senders) {
        const container = document.getElementById("screen-sender-switcher");
        if (!container) return;
        const list = Array.isArray(senders) ? senders : [];
        if (list.length === 0) {
            container.innerHTML = "";
            container.classList.add("d-none");
            return;
        }
        container.classList.remove("d-none");
        if (!selectedScreenSenderId || !list.some(s => (s.sender_device_id || s.device_id) === selectedScreenSenderId)) {
            selectedScreenSenderId = list[0].sender_device_id || list[0].device_id || "";
        }
        container.innerHTML = "";
        list.forEach(s => {
            const sid = s.sender_device_id || s.device_id || "";
            const name = s.sender_name || sid || "Sender";
            const badge = s.route_badge ? ` • ${s.route_badge}` : "";
            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = `sender-pill${sid === selectedScreenSenderId ? " active" : ""}`;
            btn.textContent = `${name}${badge}`;
            btn.dataset.senderId = sid;
            btn.addEventListener("click", () => {
                selectedScreenSenderId = sid;
                renderSenderSwitcher(activeScreenSenders);
                fetchNextScreenFrame();
            });
            container.appendChild(btn);
        });
    }

    function updatePcSharingUi(pcSharing) {
        const bar = document.getElementById("pc-screen-share-bar");
        const label = document.getElementById("pc-screen-share-targets-label");
        const shareBtn = document.getElementById("btn-share-pc-screen");
        const state = String(pcSharing?.state || "IDLE").toUpperCase();
        isPcScreenSharing = state === "STREAMING";
        if (isPcScreenSharing) {
            const targetIds = Array.isArray(pcSharing?.target_device_ids) ? pcSharing.target_device_ids : [];
            const names = targetIds.map(tid => {
                const match = registeredDevices.find(d => d.device_id === tid);
                return match?.device_name || tid;
            });
            if (label) {
                label.textContent = names.length > 0
                    ? `Sharing PC Screen -> ${names.join(", ")}`
                    : "Sharing PC Screen";
            }
            bar?.classList.remove("d-none");
            if (shareBtn) shareBtn.textContent = "Sharing";
        } else {
            bar?.classList.add("d-none");
            if (shareBtn) shareBtn.textContent = "Share PC Screen";
        }
    }

    async function openPcSharePicker() {
        const sendersRes = await apiRequest("/api/screen/senders");
        let eligible = Array.isArray(sendersRes?.eligible_targets) ? sendersRes.eligible_targets : [];
        if (eligible.length === 0 && Array.isArray(registeredDevices)) {
            eligible = registeredDevices
                .filter(d => !isLocalNode(d) && d.is_connected && String(d.permission_profile || "full_control").toLowerCase() === "full_control")
                .map(d => ({
                    device_id: d.device_id,
                    device_name: d.device_name || d.device_id,
                    platform: d.platform || "android",
                    route_badge: resolveTransportLabel(d),
                }));
        }
        eligiblePcShareTargets = eligible;
        if (eligible.length === 0) {
            showNotificationToast("Connect an authorized Full Control device to share your PC screen.", "warning");
            return;
        }
        const modal = document.getElementById("pc-share-targets-modal");
        const listEl = document.getElementById("pc-share-targets-list");
        if (!modal || !listEl) return;
        listEl.innerHTML = "";
        eligible.forEach((dev, idx) => {
            const labelEl = document.createElement("label");
            labelEl.className = "share-target-option";
            const left = document.createElement("div");
            left.className = "flex items-center gap-2";
            const cb = document.createElement("input");
            cb.type = "checkbox";
            cb.className = "pc-share-target-cb";
            cb.value = dev.device_id;
            cb.checked = idx === 0;
            const nameSpan = document.createElement("span");
            nameSpan.className = "text-sm fw-600";
            nameSpan.textContent = dev.device_name || dev.device_id;
            left.appendChild(cb);
            left.appendChild(nameSpan);

            const right = document.createElement("span");
            right.className = "chip chip-sm chip-neutral";
            right.textContent = dev.route_badge || dev.platform || "Full Control";

            labelEl.appendChild(left);
            labelEl.appendChild(right);
            listEl.appendChild(labelEl);
        });
        modal.classList.remove("d-none");
    }

    async function confirmStartPcScreenShare() {
        const checkboxes = Array.from(document.querySelectorAll(".pc-share-target-cb"));
        const selectedIds = checkboxes.filter(cb => cb.checked).map(cb => cb.value).filter(Boolean);
        if (selectedIds.length === 0) {
            showNotificationToast("Select at least one authorized Full Control device.", "warning");
            return;
        }
        document.getElementById("pc-share-targets-modal")?.classList.add("d-none");
        const res = await apiRequest("/api/screen/share/start", "POST", { target_device_ids: selectedIds });
        if (res && res.success) {
            showNotificationToast("PC live screen share started.", "success");
            pollScreenStreamStatus();
        } else {
            showNotificationToast(res?.error || "Failed starting PC screen share.", "error");
        }
    }

    async function stopPcScreenShare() {
        const res = await apiRequest("/api/screen/share/stop", "POST", {});
        if (res && res.success) {
            showNotificationToast("PC live screen share stopped.", "info");
            updatePcSharingUi({ state: "IDLE", target_device_ids: [] });
            pollScreenStreamStatus();
        } else {
            showNotificationToast(res?.error || "Failed stopping PC screen share.", "error");
        }
    }

    function stopScreenFramePolling() {
        if (screenStreamTimer) {
            clearInterval(screenStreamTimer);
            screenStreamTimer = null;
        }
        isScreenFrameInFlight = false;
    }

    function fetchNextScreenFrame() {
        if (document.hidden || isScreenFrameInFlight) return;
        isScreenFrameInFlight = true;
        const senderQuery = selectedScreenSenderId ? `&sender_id=${encodeURIComponent(selectedScreenSenderId)}` : "";
        const frameUrl = `/api/screen/frame?t=${Date.now()}${senderQuery}`;
        const preloader = new Image();
        preloader.onload = () => {
            isScreenFrameInFlight = false;
            screenFrameErrorCount = 0;
            const activeSender = activeScreenSenders.find(s => (s.sender_device_id || s.device_id) === selectedScreenSenderId);
            const senderLabel = activeSender?.sender_name ? `${activeSender.sender_name} Screen` : "Live Screen";
            lastCaptureTitle = senderLabel;
            const latestImg = document.getElementById("latest-capture-img");
            const enlargeBtn = document.getElementById("btn-enlarge-capture");
            const placeholder = document.getElementById("latest-capture-placeholder");
            if (latestImg) {
                latestImg.src = frameUrl;
                latestImg.style.display = "block";
                latestImg.onclick = () => openMediaPreview(latestImg.src, senderLabel, isCaptureStreamActive);
            }
            enlargeBtn?.classList.remove("d-none");
            placeholder?.classList.add("d-none");

            const mediaModal = document.getElementById("media-preview-modal");
            const mediaPreviewImg = document.getElementById("media-preview-img");
            const dlBtn = document.getElementById("btn-download-preview");
            if (mediaModal && !mediaModal.classList.contains("d-none") && mediaPreviewImg) {
                mediaPreviewImg.src = frameUrl;
                if (dlBtn) dlBtn.href = frameUrl;
            }
        };
        preloader.onerror = () => {
            isScreenFrameInFlight = false;
            screenFrameErrorCount++;
            if (screenFrameErrorCount >= 3) {
                stopScreenFramePolling();
                setScreenViewerState("ERROR", "Unable to fetch live frames. Check connection and retry.");
            }
        };
        preloader.src = frameUrl;
    }

    async function pollScreenStreamStatus() {
        if (document.hidden || isScreenStatusPolling) return;
        isScreenStatusPolling = true;
        try {
            const stUrl = selectedScreenSenderId
                ? `/api/screen/status?sender_id=${encodeURIComponent(selectedScreenSenderId)}`
                : "/api/screen/status";
            const st = await apiRequest(stUrl);
            updatePcSharingUi(st?.pc_sharing || { state: "IDLE" });
            activeScreenSenders = Array.isArray(st?.senders) ? st.senders : [];
            renderSenderSwitcher(activeScreenSenders);

            const state = String(st?.state || "IDLE").toUpperCase();
            if (state === "STREAMING") {
                const fpsText = st?.fps ? `${Number(st.fps).toFixed(1)} FPS` : "Live";
                const dimText = (st?.frame_width && st?.frame_height) ? `${st.frame_width}x${st.frame_height}` : "";
                const senderTag = st?.sender_name ? `${st.sender_name}` : "";
                setScreenViewerState("STREAMING", [senderTag, fpsText, dimText].filter(Boolean).join(" • "));
                if (st?.has_frame && !screenStreamTimer) {
                    screenFrameErrorCount = 0;
                    fetchNextScreenFrame();
                    screenStreamTimer = setInterval(fetchNextScreenFrame, 500);
                } else if (st?.has_frame) {
                    fetchNextScreenFrame();
                }
            } else {
                stopScreenFramePolling();
                const latestImg = document.getElementById("latest-capture-img");
                if (lastKnownStreamState === "STREAMING" && (state === "STOPPED" || state === "REVOKED" || state === "IDLE")) {
                    if (latestImg) {
                        latestImg.removeAttribute("src");
                        latestImg.style.display = "none";
                    }
                    const mediaModal = document.getElementById("media-preview-modal");
                    if (mediaModal && !mediaModal.classList.contains("d-none") && isCaptureStreamActive) {
                        closeMediaPreview();
                    }
                    setScreenViewerState("STOPPED", state === "REVOKED" ? "Screen share revoked on sender" : "Live stream stopped");
                } else if (state === "ERROR") {
                    setScreenViewerState("ERROR", st?.error || "Screen stream error");
                } else if (screenFrameErrorCount === 0) {
                    setScreenViewerState("IDLE");
                }
            }
            lastKnownStreamState = state;
        } finally {
            isScreenStatusPolling = false;
        }
    }

    async function stopRemoteScreenStream() {
        stopScreenFramePolling();
        const res = await apiRequest("/api/screen/stop", "POST", selectedScreenSenderId ? { sender_id: selectedScreenSenderId } : {});
        lastKnownStreamState = "STOPPED";
        const latestImg = document.getElementById("latest-capture-img");
        if (latestImg) {
            latestImg.removeAttribute("src");
            latestImg.style.display = "none";
        }
        setScreenViewerState("STOPPED", "Live stream stopped");
        if (res && res.success) {
            showNotificationToast("Live screen stream stopped.", "info");
        } else {
            showNotificationToast(res?.error || "Failed stopping live stream", "error");
        }
    }

    async function triggerCameraCapture() {
        const targetId = resolveTargetDeviceId();
        if (!targetId) {
            showNotificationToast("Select or connect an online phone for camera capture.", "warning");
            return;
        }
        const statusText = document.getElementById("latest-capture-status-text");
        if (statusText) statusText.textContent = "Requesting camera photo on phone...";
        showNotificationToast("Requesting phone camera capture...", "info");

        let baselineFilename = "";
        try {
            const preResp = await fetch(`/api/camera/latest?t=${Date.now()}`);
            if (preResp.status === 200) baselineFilename = preResp.headers.get("X-Snow-Filename") || "";
        } catch (e) {}

        const res = await apiRequest("/api/camera/capture", "POST", { device_id: targetId });
        if (res && res.success) {
            const fileName = res.file_name || res.data?.file_name;
            showNotificationToast("Camera photo captured!", "success");
            const imgSrc = fileName
                ? `/api/captures/${encodeURIComponent(fileName)}?t=${Date.now()}`
                : `/api/camera/latest?t=${Date.now()}`;
            showCapturePreview(imgSrc, "Camera Photo", false);
            return;
        }

        const errStr = String(res?.error || res?.status || "");
        const awaitingTap = errStr.includes("FOREGROUND_USER_INTERACTION_REQUIRED")
            || errStr.includes("CAMERA_PERMISSION_REQUIRED")
            || errStr.includes("CAMERA_APPROVAL_NOTIFICATION_POSTED")
            || errStr.toLowerCase().includes("notification");
        if (!awaitingTap) {
            if (statusText) statusText.textContent = errStr || "Camera capture failed";
            showNotificationToast(errStr || "Failed capturing camera photo", "error");
            return;
        }

        if (statusText) statusText.textContent = "Tap 'Camera Photo Requested' on your phone, snap a photo, and confirm...";
        showNotificationToast("Tap the Camera notification on your phone to capture & send photo.", "info");

        let attempts = 0;
        let inFlight = false;
        const pollTimer = setInterval(async () => {
            if (document.hidden || inFlight) return;
            inFlight = true;
            try {
                attempts++;
                const camResp = await fetch(`/api/camera/latest?t=${Date.now()}`);
                if (camResp.status === 200) {
                    const fname = camResp.headers.get("X-Snow-Filename") || "";
                    if (fname && fname !== baselineFilename) {
                        clearInterval(pollTimer);
                        showCapturePreview(`/api/camera/latest?t=${Date.now()}`, "Camera Photo", false);
                        showNotificationToast("Camera photo received!", "success");
                        return;
                    }
                }
                if (attempts >= 35) {
                    clearInterval(pollTimer);
                    if (statusText) statusText.textContent = "Camera photo request timed out or was cancelled.";
                    showNotificationToast("Camera photo request timed out.", "warning");
                }
            } finally {
                inFlight = false;
            }
        }, 1200);
    }

    function showCapturePreview(imgUrl, title, autoOpenModal = false) {
        lastCaptureTitle = title || "Capture Preview";
        const latestImg = document.getElementById("latest-capture-img");
        const enlargeBtn = document.getElementById("btn-enlarge-capture");
        const placeholder = document.getElementById("latest-capture-placeholder");
        if (latestImg && placeholder) {
            latestImg.src = imgUrl;
            latestImg.style.display = "block";
            latestImg.onclick = () => openMediaPreview(latestImg.src, lastCaptureTitle, isCaptureStreamActive);
            enlargeBtn?.classList.remove("d-none");
            placeholder.classList.add("d-none");
        }
        if (autoOpenModal) {
            openMediaPreview(imgUrl, lastCaptureTitle, isCaptureStreamActive);
        }
    }

    async function triggerMediaAction(action, extra = {}) {
        const dev = getSelectedDeviceObj();
        const target = (dev && isAndroidDevice(dev)) ? "phone" : "windows";
        const payload = { action, target, device_id: resolveTargetDeviceId(), ...extra };
        const res = await apiRequest("/api/media", "POST", payload);
        if (res && res.success) {
            const d = res.data || res;
            const volSlider = document.getElementById("now-playing-volume");
            const muteBtn = document.getElementById("btn-media-mute");
            if (volSlider && typeof d.volume_percent === "number") {
                volSlider.value = String(d.volume_percent);
            }
            if (muteBtn && typeof d.muted === "boolean") {
                muteBtn.classList.toggle("text-rose", d.muted);
                muteBtn.title = d.muted ? "Unmute Audio" : "Mute Audio";
            }
            if (action !== "volume_set" && action !== "volume") {
                showNotificationToast(`Media: ${action}`, "info");
            }
        } else {
            showNotificationToast(res?.error || "Media control failed", "error");
        }
    }

    function applyOfflineUsbDimming(isOffline) {
        const heroCard = document.querySelector(".hero-desktop-card");
        const qaBadge = document.getElementById("qa-offline-badge");
        if (heroCard) {
            heroCard.classList.toggle("offline-dimmed", Boolean(isOffline));
        }
        if (qaBadge) {
            qaBadge.classList.toggle("d-none", !isOffline);
        }
    }

    function updateHeroCard(device) {
        const heroCard = document.getElementById("hero-card");
        const bezelFrame = document.getElementById("hero-bezel-frame");
        const wallImg = document.getElementById("desktop-wallpaper-img");
        const wallFallback = document.getElementById("wallpaper-fallback");
        const glassBar = document.getElementById("hero-glass-bar");
        const phoneContent = document.getElementById("phone-bezel-content");
        const phoneIconEl = document.getElementById("hero-device-icon");
        const phoneClock = document.getElementById("phone-bezel-clock");
        const phoneSub = document.getElementById("phone-bezel-sub");

        const nameEl = document.getElementById("hero-device-name");
        const transportEl = document.getElementById("hero-transport-pill");
        const batteryInd = document.getElementById("hero-battery-indicator");
        const batteryText = document.getElementById("hero-battery-text");
        const ramText = document.getElementById("hero-ram-text");
        const storageText = document.getElementById("hero-storage-text");
        const resProgress = document.getElementById("hero-resource-progress");

        const ringBtn = document.getElementById("btn-hero-ring-phone");
        const lockBtn = document.getElementById("btn-hero-lock-pc");
        const sendBtn = document.getElementById("btn-hero-send-file");
        const capBtn = document.getElementById("btn-hero-capture-screen");
        const badgeType = document.getElementById("hero-device-type-badge");
        const primaryActions = document.getElementById("hero-primary-actions");
        const offlineActions = document.getElementById("hero-offline-actions");

        // 1. Local Windows PC Host presentation
        if (!device || isLocalNode(device)) {
            if (heroCard) heroCard.classList.remove("phone-mode");
            if (bezelFrame) bezelFrame.classList.remove("phone-bezel");
            if (wallImg) {
                wallImg.classList.remove("d-none");
                if (csrfToken && !wallImg.dataset.loaded) {
                    wallImg.dataset.loaded = "1";
                    wallImg.src = `/api/desktop/wallpaper?t=${Date.now()}`;
                }
            }
            if (wallFallback && wallImg && wallImg.style.display === "none") wallFallback.style.display = "flex";
            if (glassBar) glassBar.classList.remove("d-none");
            if (phoneContent) phoneContent.classList.add("d-none");

            if (nameEl) nameEl.textContent = localHostIdentity;
            if (badgeType) badgeType.textContent = "Windows PC";
            if (transportEl) {
                transportEl.textContent = isCoreOnline ? "Host Active" : "Core Offline";
                transportEl.className = isCoreOnline ? "chip chip-emerald" : "chip chip-rose";
            }

            const tel = localHostTelemetry || {};
            const cpuPct = tel.cpu_percent ?? tel.cpu?.utilization_percent;
            const memInfo = tel.memory || {};
            const diskInfo = tel.disk || {};
            const ramTot = tel.ram_total_bytes || tel.total_memory_bytes || (memInfo.total_mb ? memInfo.total_mb * 1024 * 1024 : null);
            const ramAvail = tel.ram_available_bytes || tel.available_memory_bytes ||
                (ramTot && memInfo.used_mb !== undefined ? Math.max(0, ramTot - memInfo.used_mb * 1024 * 1024) : null);
            const ramPct = tel.ram_percent ?? memInfo.percent;
            const diskFree = tel.storage_available_bytes || tel.disk_free_bytes ||
                (diskInfo.total_gb != null && diskInfo.used_gb != null ? Math.max(0, (diskInfo.total_gb - diskInfo.used_gb) * 1024 * 1024 * 1024) : null);

            if (batteryInd) {
                const pct = tel.battery_percent;
                if (typeof pct === "number") {
                    batteryInd.classList.remove("d-none");
                    if (batteryText) batteryText.textContent = `${Math.round(pct)}%${tel.battery_charging ? " Charging" : ""}`;
                } else if (tel.battery_status === "NO_BATTERY") {
                    batteryInd.classList.remove("d-none");
                    if (batteryText) batteryText.textContent = "AC Power";
                } else {
                    batteryInd.classList.add("d-none");
                }
            }
            if (ramText) {
                const cpuPart = (typeof cpuPct === "number") ? `CPU ${Math.round(cpuPct)}% • ` : "";
                if (ramTot && ramAvail != null) {
                    ramText.textContent = `${cpuPart}RAM ${formatBytes(ramTot - ramAvail)} / ${formatBytes(ramTot)}`;
                } else if (typeof ramPct === "number") {
                    ramText.textContent = `${cpuPart}RAM ${Math.round(ramPct)}%`;
                } else {
                    ramText.textContent = "Host CPU & RAM Ready";
                }
            }
            if (storageText) {
                storageText.textContent = diskFree != null ? `${formatBytes(diskFree)} free` : "Local Storage Active";
            }
            if (resProgress) {
                const pct = (ramTot && ramAvail != null)
                    ? Math.round(((ramTot - ramAvail) / ramTot) * 100)
                    : (typeof ramPct === "number" ? Math.round(ramPct) : 25);
                resProgress.style.width = `${Math.min(100, Math.max(5, pct))}%`;
            }

            const hasOnlinePhone = registeredDevices.some(d => !isLocalNode(d) && Boolean(d.is_connected));
            if (lockBtn) {
                lockBtn.classList.remove("d-none");
                lockBtn.disabled = !isCoreOnline;
            }
            if (ringBtn) {
                ringBtn.classList.add("d-none");
                ringBtn.disabled = true;
            }
            if (sendBtn) {
                sendBtn.classList.remove("d-none");
                sendBtn.disabled = !isCoreOnline || !hasOnlinePhone;
                sendBtn.title = hasOnlinePhone ? "Send files to connected phone" : "Connect a phone to send files";
            }
            if (capBtn) {
                capBtn.classList.remove("d-none");
                capBtn.disabled = !isCoreOnline || !hasOnlinePhone;
                capBtn.title = hasOnlinePhone ? "Capture connected phone screen" : "Connect a phone to capture screen";
            }
            if (primaryActions) primaryActions.classList.remove("d-none");
            if (offlineActions) offlineActions.classList.add("d-none");
            applyOfflineUsbDimming(!isCoreOnline);
            return;
        }

        // 2. Remote Peer / Android Device Presentation
        const isAndroid = isAndroidDevice(device);
        const isConn = Boolean(device.is_connected);

        if (heroCard) heroCard.classList.toggle("phone-mode", isAndroid);
        if (bezelFrame) bezelFrame.classList.toggle("phone-bezel", isAndroid);

        if (isAndroid) {
            if (wallImg) wallImg.classList.add("d-none");
            if (wallFallback) wallFallback.style.display = "none";
            if (glassBar) glassBar.classList.add("d-none");
            if (phoneContent) phoneContent.classList.remove("d-none");
            if (phoneIconEl) phoneIconEl.classList.toggle("text-amber", !isConn);
            if (phoneClock) phoneClock.textContent = isConn ? new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "Offline";
            if (phoneSub) phoneSub.textContent = isConn ? `${resolveTransportLabel(device)} Link` : "Unreachable";
        } else {
            if (wallImg) wallImg.classList.remove("d-none");
            if (glassBar) glassBar.classList.remove("d-none");
            if (phoneContent) phoneContent.classList.add("d-none");
        }

        if (nameEl) nameEl.textContent = device.device_name || (isAndroid ? "Android Phone" : "Remote Peer");
        if (badgeType) badgeType.textContent = isAndroid ? "Android Phone" : "Remote PC";

        if (transportEl) {
            if (isConn) {
                transportEl.textContent = `Connected • ${resolveTransportLabel(device)}`;
                transportEl.className = "chip chip-emerald";
            } else {
                transportEl.textContent = "Disconnected";
                transportEl.className = "chip chip-amber";
            }
        }

        const tel = device.telemetry || {};
        const batLevel = tel.battery_level ?? tel.level ?? tel.battery_percent ?? device.battery?.level ?? device.battery_level;
        const charging = tel.charging ?? device.battery?.charging;
        const tempC = tel.temperature_celsius;
        if (batteryInd) {
            if (batLevel !== null && batLevel !== undefined) {
                batteryInd.classList.remove("d-none");
                const tempPart = (typeof tempC === "number") ? ` • ${tempC.toFixed(1)}°C` : "";
                if (batteryText) batteryText.textContent = `${batLevel}%${charging ? " Charging" : ""}${tempPart}`;
            } else {
                batteryInd.classList.add("d-none");
            }
        }

        const ramTot = tel.ram_total_bytes;
        const ramAvail = tel.ram_available_bytes;
        const diskAvail = tel.storage_available_bytes;

        if (ramText) {
            if (ramTot && ramAvail) {
                const used = ramTot - ramAvail;
                ramText.textContent = `RAM ${formatBytes(used)} / ${formatBytes(ramTot)}`;
                if (resProgress) resProgress.style.width = `${Math.min(100, Math.max(5, Math.round((used / ramTot) * 100)))}%`;
            } else {
                ramText.textContent = isConn ? "RAM: Active" : "RAM: Last known state";
                if (resProgress) resProgress.style.width = isConn ? "35%" : "0%";
            }
        }
        if (storageText) {
            storageText.textContent = diskAvail ? `Storage ${formatBytes(diskAvail)} free` : (isConn ? "Storage: Ready" : "Device Offline");
        }

        if (lockBtn) {
            lockBtn.classList.toggle("d-none", isAndroid);
            lockBtn.disabled = isAndroid || !isConn;
        }
        if (ringBtn) {
            ringBtn.classList.toggle("d-none", !isAndroid);
            ringBtn.disabled = !isAndroid || !isConn;
        }
        if (sendBtn) {
            sendBtn.classList.remove("d-none");
            sendBtn.disabled = !isConn;
            sendBtn.title = isConn ? "Send files to device" : "Device is offline";
        }
        if (capBtn) {
            capBtn.classList.toggle("d-none", !isAndroid);
            capBtn.disabled = !isAndroid || !isConn;
            capBtn.title = isConn ? "Capture phone screen" : "Device is offline";
        }

        if (offlineActions) offlineActions.classList.toggle("d-none", isConn);
        applyOfflineUsbDimming(!isConn);
    }

    async function loadHomeWidgets() {
        const seq = ++homeWidgetsSeq;
        isHomeWidgetsInFlight = true;
        try {
        // 1. Shared Clipboard Preview
        const clipRes = await apiRequest("/api/clipboard/buffer");
        if (seq !== homeWidgetsSeq) return;
        const clipContainer = document.getElementById("clipboard-items-container");
        const clipBadge = document.getElementById("clipboard-count-badge");
        const clipEmpty = document.getElementById("clipboard-empty-state");

        if (clipContainer) {
            const items = (clipRes && Array.isArray(clipRes.items)) ? clipRes.items : (clipRes?.data?.items || []);
            if (clipBadge) clipBadge.textContent = items.length;
            clipContainer.innerHTML = "";

            if (items.length === 0) {
                clipEmpty?.classList.remove("d-none");
            } else {
                clipEmpty?.classList.add("d-none");
                items.slice(0, 4).forEach(item => {
                    const id = item.item_id || item.id || "";
                    const type = item.content_type || item.type || "text";
                    const text = item.text_content || item.text || item.preview || item.preview_text || "";
                    const source = item.source_device_name || item.source_device || "Device";
                    const isImg = type === "image";

                    const row = document.createElement("div");
                    row.className = "clipboard-item-row";
                    const thumbHtml = isImg
                        ? `<img class="clipboard-thumb" src="/api/clipboard/image/${encodeURIComponent(id)}" alt="Clip" />`
                        : `<div class="island-icon-box"><svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path></svg></div>`;

                    row.innerHTML = `
                        <div class="flex items-center gap-2 min-w-0">
                            ${thumbHtml}
                            <div class="flex flex-col min-w-0">
                                <span class="text-xs font-semibold text-primary truncate">${escapeHtml(isImg ? `Image • ${source}` : (text || "Snippet"))}</span>
                                <span class="text-xs text-muted">${escapeHtml(source)} • ${formatBytes(item.size_bytes)}</span>
                            </div>
                        </div>
                        <div class="flex items-center gap-1">
                            <button class="icon-btn btn-copy-clip" style="width: 28px; height: 28px;" title="Copy & Apply">
                                <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><rect height="13" rx="2" ry="2" width="13" x="9" y="9"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                            </button>
                            <button class="icon-btn btn-share-clip" style="width: 28px; height: 28px;" title="Share to Device">
                                <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"></circle><circle cx="6" cy="12" r="3"></circle><circle cx="18" cy="19" r="3"></circle><line x1="8.59" x2="15.42" y1="13.51" y2="17.49"></line><line x1="15.41" x2="8.59" y1="6.51" y2="10.49"></line></svg>
                            </button>
                        </div>
                    `;
                    const homeThumb = row.querySelector("img.clipboard-thumb");
                    if (homeThumb) {
                        homeThumb.addEventListener("error", () => {
                            const fallback = document.createElement("div");
                            fallback.className = "island-icon-box";
                            fallback.title = "Image preview unavailable";
                            fallback.innerHTML = `<svg class="svg-icon svg-icon-sm text-muted" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>`;
                            homeThumb.replaceWith(fallback);
                        }, { once: true });
                    }

                    row.querySelector(".btn-copy-clip").onclick = async (e) => {
                        await withButtonLoading(e.currentTarget, "", async () => {
                            const res = await apiRequest("/api/clipboard/buffer/apply", "POST", { item_id: id, target: "pc" });
                            if (res && res.success) {
                                if (navigator.clipboard && text) navigator.clipboard.writeText(text).catch(() => {});
                                showNotificationToast("Applied to PC clipboard!", "success");
                            } else {
                                showNotificationToast(res?.error || "Failed applying clipboard entry", "error");
                            }
                        });
                    };
                    row.querySelector(".btn-share-clip").onclick = async (e) => {
                        const targetDev = resolveTargetDeviceId();
                        if (!targetDev) {
                            showNotificationToast("Connect an eligible remote device first.", "warning");
                            return;
                        }
                        await withButtonLoading(e.currentTarget, "", async () => {
                            const res = await apiRequest("/api/clipboard/buffer/apply", "POST", { item_id: id, target: targetDev });
                            if (res && res.success) {
                                showNotificationToast("Pushed clipboard entry to target.", "success");
                            } else {
                                showNotificationToast(res?.error || "Failed pushing clipboard entry", "error");
                            }
                        });
                    };
                    clipContainer.appendChild(row);
                });
            }
        }

        // 2. Phone Notifications
        const targetId = resolveTargetDeviceId();
        const notifUrl = targetId ? "/api/notifications?device_id=" + encodeURIComponent(targetId) : "/api/notifications";
        const notifRes = await apiRequest(notifUrl);
        if (seq !== homeWidgetsSeq) return;
        const notifContainer = document.getElementById("notifications-container");
        const notifBadge = document.getElementById("notifications-count-badge");
        const notifEmpty = document.getElementById("notifications-empty-state");

        if (notifContainer) {
            activeNotifications = (notifRes && Array.isArray(notifRes.notifications)) ? notifRes.notifications : [];
            if (notifBadge) notifBadge.textContent = activeNotifications.length;
            const visibleList = activeNotifications.slice(0, 6);

            if (visibleList.length === 0) {
                notifContainer.replaceChildren();
                openNotificationReplyKeys.clear();
                notificationReplyDrafts.clear();
                notifEmpty?.classList.remove("d-none");
            } else {
                notifEmpty?.classList.add("d-none");
                const desiredKeys = new Set();
                const existingCards = new Map();
                notifContainer.querySelectorAll(".notif-card[data-notif-key]").forEach(el => {
                    const k = el.dataset.notifKey || "";
                    if (k) existingCards.set(k, el);
                });

                const renderedEntries = visibleList.map((n, idx) => {
                    const rawKey = n.key || n.id || "";
                    const domKey = rawKey || `${n.app_name || "Android"}::${n.title || "Notification"}::${idx}`;
                    desiredKeys.add(domKey);
                    return { n, rawKey, domKey };
                });

                // Prune removed notifications without touching active reply composers
                existingCards.forEach((el, k) => {
                    if (!desiredKeys.has(k)) {
                        el.remove();
                        openNotificationReplyKeys.delete(k);
                        notificationReplyDrafts.delete(k);
                    }
                });
                Array.from(openNotificationReplyKeys).forEach(k => {
                    if (!desiredKeys.has(k)) openNotificationReplyKeys.delete(k);
                });
                Array.from(notificationReplyDrafts.keys()).forEach(k => {
                    if (!desiredKeys.has(k)) notificationReplyDrafts.delete(k);
                });

                const activeEl = document.activeElement;
                const focusedKey = activeEl && notifContainer.contains(activeEl) && activeEl.classList.contains("notif-reply-inp")
                    ? activeEl.closest(".notif-card[data-notif-key]")?.dataset?.notifKey
                    : null;
                const selStart = focusedKey ? activeEl.selectionStart : null;
                const selEnd = focusedKey ? activeEl.selectionEnd : null;

                renderedEntries.forEach(({ n, rawKey, domKey }, idx) => {
                    const titleText = n.title || n.app_name || "Notification";
                    const appLabel = n.app_name || "Android";
                    const bodyText = n.body || n.text || "";
                    const canReply = n.can_reply !== false;

                    let card = existingCards.get(domKey);
                    if (!card) {
                        card = document.createElement("div");
                        card.className = "notif-card";
                        card.dataset.notifKey = domKey;
                        card.dataset.notifActionKey = rawKey;
                        card.innerHTML = `
                            <div class="flex items-center justify-between gap-2">
                                <span class="text-xs font-bold text-primary truncate notif-title-text"></span>
                                <span class="chip chip-sm chip-cyan notif-app-chip"></span>
                            </div>
                            <span class="text-xs text-secondary notif-body-text"></span>
                            <div class="flex items-center justify-between gap-2 mt-1">
                                <div class="flex gap-2">
                                    <button class="btn btn-xs btn-primary btn-toggle-reply">Reply</button>
                                </div>
                            </div>
                            <div class="notif-inline-reply d-none">
                                <span class="text-xs text-muted">Replying as PC Host</span>
                                <div class="flex gap-2">
                                    <input type="text" class="form-input text-xs notif-reply-inp" placeholder="Type reply..." />
                                    <button class="btn btn-xs btn-tonal btn-reply-cancel">Cancel</button>
                                    <button class="btn btn-xs btn-primary btn-reply-send">Send</button>
                                </div>
                            </div>
                        `;

                        const inlineBox = card.querySelector(".notif-inline-reply");
                        const replyInp = card.querySelector(".notif-reply-inp");
                        const toggleBtn = card.querySelector(".btn-toggle-reply");

                        if (toggleBtn && inlineBox) {
                            toggleBtn.onclick = () => {
                                const cKey = card.dataset.notifKey || "";
                                const willShow = inlineBox.classList.contains("d-none");
                                inlineBox.classList.toggle("d-none", !willShow);
                                if (willShow) {
                                    openNotificationReplyKeys.add(cKey);
                                    replyingNotificationKey = cKey;
                                    if (replyInp) replyInp.focus();
                                } else {
                                    openNotificationReplyKeys.delete(cKey);
                                    if (replyingNotificationKey === cKey) replyingNotificationKey = "";
                                }
                            };
                        }

                        replyInp?.addEventListener("input", () => {
                            const cKey = card.dataset.notifKey || "";
                            notificationReplyDrafts.set(cKey, replyInp.value);
                        });

                        card.querySelector(".btn-reply-cancel")?.addEventListener("click", () => {
                            const cKey = card.dataset.notifKey || "";
                            inlineBox?.classList.add("d-none");
                            openNotificationReplyKeys.delete(cKey);
                            notificationReplyDrafts.delete(cKey);
                            if (replyInp) replyInp.value = "";
                            if (replyingNotificationKey === cKey) replyingNotificationKey = "";
                        });

                        const dispatchReply = async () => {
                            const cKey = card.dataset.notifKey || "";
                            const actKey = card.dataset.notifActionKey || cKey;
                            const txt = replyInp ? replyInp.value.trim() : "";
                            if (!txt || !actKey) return;
                            const r = await apiRequest("/api/notifications/reply", "POST", { key: actKey, text: txt, device_id: resolveTargetDeviceId() });
                            if (r && r.success) {
                                openNotificationReplyKeys.delete(cKey);
                                notificationReplyDrafts.delete(cKey);
                                if (replyInp) replyInp.value = "";
                                inlineBox?.classList.add("d-none");
                                if (replyingNotificationKey === cKey) replyingNotificationKey = "";
                                showNotificationToast("Reply sent to phone!", "success");
                                loadHomeWidgets();
                            } else {
                                showNotificationToast(r?.error || "Failed sending reply", "error");
                            }
                        };
                        card.querySelector(".btn-reply-send")?.addEventListener("click", dispatchReply);
                        replyInp?.addEventListener("keydown", (e) => {
                            if (e.key === "Enter") dispatchReply();
                        });
                    }

                    // Incremental field updates (never recreate active input)
                    card.dataset.notifActionKey = rawKey;
                    const titleEl = card.querySelector(".notif-title-text");
                    const appEl = card.querySelector(".notif-app-chip");
                    const bodyEl = card.querySelector(".notif-body-text");
                    const toggleBtnEl = card.querySelector(".btn-toggle-reply");
                    const inlineBoxEl = card.querySelector(".notif-inline-reply");
                    const replyInpEl = card.querySelector(".notif-reply-inp");

                    if (titleEl && titleEl.textContent !== titleText) titleEl.textContent = titleText;
                    if (appEl && appEl.textContent !== appLabel) appEl.textContent = appLabel;
                    if (bodyEl && bodyEl.textContent !== bodyText) bodyEl.textContent = bodyText;
                    if (toggleBtnEl) toggleBtnEl.classList.toggle("d-none", !canReply);

                    const isOpen = openNotificationReplyKeys.has(domKey);
                    if (inlineBoxEl) inlineBoxEl.classList.toggle("d-none", !isOpen);
                    if (replyInpEl && document.activeElement !== replyInpEl) {
                        const savedDraft = notificationReplyDrafts.get(domKey);
                        if (typeof savedDraft === "string" && replyInpEl.value !== savedDraft) {
                            replyInpEl.value = savedDraft;
                        }
                    }

                    // Preserve exact DOM slot without moving unchanged elements (prevents focus blur)
                    const currentAtIdx = notifContainer.children[idx];
                    if (currentAtIdx !== card) {
                        notifContainer.insertBefore(card, currentAtIdx || null);
                    }
                });

                if (focusedKey) {
                    const refCard = Array.from(notifContainer.querySelectorAll(".notif-card[data-notif-key]")).find(
                        el => el.dataset.notifKey === focusedKey
                    );
                    const refInp = refCard?.querySelector(".notif-reply-inp");
                    if (refInp && document.activeElement !== refInp) {
                        refInp.focus();
                        if (typeof selStart === "number" && typeof selEnd === "number") {
                            try { refInp.setSelectionRange(selStart, selEnd); } catch (e) {}
                        }
                    }
                }
            }
        }
        } finally {
            if (seq === homeWidgetsSeq) {
                isHomeWidgetsInFlight = false;
            }
        }
    }

    // =========================================================================
    // 7. View 2: Devices & Network
    // =========================================================================

    function initDevicesView() {
        document.getElementById("btn-filter-all")?.addEventListener("click", () => setDeviceFilter("all"));
        document.getElementById("btn-filter-pcs")?.addEventListener("click", () => setDeviceFilter("pcs"));
        document.getElementById("btn-filter-phones")?.addEventListener("click", () => setDeviceFilter("phones"));
        document.getElementById("btn-devices-connect-header")?.addEventListener("click", openConnectModal);

        const tabQr = document.getElementById("btn-pair-tab-qr");
        const tabApk = document.getElementById("btn-pair-tab-apk");
        const paneQr = document.getElementById("pair-pane-qr");
        const paneApk = document.getElementById("pair-pane-apk");

        if (tabQr && tabApk && paneQr && paneApk) {
            tabQr.onclick = () => {
                tabQr.classList.add("active");
                tabApk.classList.remove("active");
                paneQr.classList.remove("d-none");
                paneApk.classList.add("d-none");
                refreshPairingState();
            };
            tabApk.onclick = () => {
                tabApk.classList.add("active");
                tabQr.classList.remove("active");
                paneApk.classList.remove("d-none");
                paneQr.classList.add("d-none");
                loadApkQr();
            };
        }

        document.getElementById("btn-pairing-refresh-qr")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Generating...", async () => {
                const ok = await loadPairingQR();
                if (ok) showNotificationToast("Generated 60s pairing QR & PIN.", "info");
            });
        });
        document.getElementById("btn-modal-generate-pin")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Generating...", async () => {
                const ok = await loadPairingQR();
                if (ok) showNotificationToast("Generated 60s pairing QR & PIN.", "info");
            });
        });
        document.getElementById("btn-pairing-cancel-pin")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Cancelling...", cancelPairingPin);
        });

        const btnPairConnect = document.getElementById("btn-pairing-connect");
        const inputPair = document.getElementById("pairing-input");
        if (btnPairConnect && inputPair) {
            btnPairConnect.onclick = async () => {
                await withButtonLoading(btnPairConnect, "Connecting...", async () => {
                    await handleUnifiedConnectInput(inputPair.value.trim());
                });
            };
        }

        // Federation Controls
        document.getElementById("btn-federation-gen-invite")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Generating...", async () => {
                const permTier = document.getElementById("federation-invite-tier")?.value || "files_and_clipboard";
                const res = await apiRequest("/api/federation/invite", "POST", {
                    ttl_seconds: 600,
                    permission_tier: permTier,
                });
                const displayInvite = document.getElementById("federation-invite-display");
                const code = res?.code || res?.invite_code;
                if (res && res.success && code && displayInvite) {
                    displayInvite.textContent = code;
                    displayInvite.classList.remove("d-none");
                    showNotificationToast(`Generated 9-digit code: ${code}`, "success");
                } else {
                    showNotificationToast(res?.error || "Could not generate federation invite", "error");
                }
            });
        });

        document.getElementById("btn-federation-join")?.addEventListener("click", async (e) => {
            const inp = document.getElementById("federation-input-code");
            const code = inp ? inp.value.trim() : "";
            if (!code) {
                showNotificationToast("Enter a 9-digit federation invite code.", "warning");
                return;
            }
            await withButtonLoading(e.currentTarget, "Joining...", async () => {
                const res = await apiRequest("/api/federation/accept", "POST", { code });
                if (res && res.success) {
                    showNotificationToast("Joined federated network!", "success");
                    if (inp) inp.value = "";
                    refreshAllData();
                } else {
                    showNotificationToast(res?.error || "Failed joining federation", "error");
                }
            });
        });

        // Kill Switch Modal
        const killModal = document.getElementById("killswitch-modal");
        document.getElementById("btn-federation-kill-switch")?.addEventListener("click", () => {
            killModal?.classList.remove("d-none");
        });
        document.getElementById("btn-killswitch-cancel")?.addEventListener("click", () => {
            killModal?.classList.add("d-none");
        });
        document.getElementById("btn-killswitch-confirm")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Revoking...", async () => {
                const res = await apiRequest("/api/federation/kill-switch", "POST", { reason: "Emergency Kill Switch via Web Dashboard" });
                if (res && res.success) {
                    showNotificationToast("Emergency Kill Switch activated: All federation grants severed.", "warning");
                } else {
                    showNotificationToast(res?.error || "Failed activating kill switch.", "error");
                }
                killModal?.classList.add("d-none");
                refreshAllData();
            });
        });

        // Remote Access Toggle (Zero-config Render Hub by default)
        const chkRelay = document.getElementById("chk-relay-tunnel-toggle");
        if (chkRelay) {
            chkRelay.addEventListener("change", async () => {
                chkRelay.disabled = true;
                try {
                    if (chkRelay.checked) {
                        const res = await apiRequest("/api/relay/tunnel/start", "POST", { provider: "render" });
                        if (res && res.success) {
                            showNotificationToast(
                                res.active ? "Render Hub Remote Access active!" : (res.message || "Render Hub Remote Access enabled."),
                                "success"
                            );
                            if (lastPairingSnapshotHasActivePin) loadPairingQR();
                            else refreshPairingState();
                        } else {
                            chkRelay.checked = false;
                            showNotificationToast(res?.error || "Remote Access unavailable", "error");
                        }
                    } else {
                        const res = await apiRequest("/api/relay/tunnel/stop", "POST", {});
                        if (res && res.success) {
                            showNotificationToast("Remote Access stopped.", "info");
                        } else {
                            showNotificationToast(res?.error || "Failed stopping Remote Access", "error");
                        }
                        if (lastPairingSnapshotHasActivePin) loadPairingQR();
                        else refreshPairingState();
                    }
                    await loadRelayTunnelStatus();
                } finally {
                    chkRelay.disabled = false;
                }
            });
        }

        document.getElementById("btn-usb-unlock-permissions")?.addEventListener("click", async () => {
            const btn = document.getElementById("btn-usb-unlock-permissions");
            const statusEl = document.getElementById("usb-unlock-status");
            if (btn) btn.disabled = true;
            if (statusEl) {
                statusEl.textContent = "Unlocking Android permissions over USB ADB...";
                statusEl.className = "text-xs text-cyan";
            }
            const res = await apiRequest("/api/usb/unlock-permissions", "POST", {});
            if (btn) btn.disabled = false;
            if (res && res.success) {
                if (statusEl) {
                    statusEl.textContent = res.message || "Permissions unlocked via USB.";
                    statusEl.className = "text-xs text-emerald";
                }
                showNotificationToast(res.message || "Phone permissions unlocked!", "success");
            } else {
                const errMsg = res?.error || res?.message || "USB permission unlock failed.";
                if (statusEl) {
                    statusEl.textContent = errMsg;
                    statusEl.className = "text-xs text-rose";
                }
                showNotificationToast(errMsg, "warning");
            }
        });
    }

    async function handleUnifiedConnectInput(rawVal) {
        if (!rawVal) {
            showNotificationToast("Enter a SNOW ID (SNW-...) or 9-digit network invite code.", "warning");
            return;
        }
        const digitsOnly = rawVal.replace(/\D/g, "");
        if (digitsOnly.length === 9 && /^[\d-\s]+$/.test(rawVal)) {
            showNotificationToast("Accepting 9-digit federation invite...", "info");
            const res = await apiRequest("/api/federation/accept", "POST", { code: rawVal });
            if (res && res.success) {
                showNotificationToast("Federation established!", "success");
                refreshAllData();
            } else {
                showNotificationToast(res?.error || "Federation acceptance failed", "error");
            }
            return;
        }

        const cleanId = rawVal.trim().toUpperCase();
        if (/^SNW-(NET-[A-F0-9]{8}|[A-Z0-9]{4}-[A-Z0-9]{4})$/i.test(cleanId)) {
            showNotificationToast(`Resolving SNOW ID ${cleanId}...`, "info");
            const dirRes = await apiRequest(`/api/directory/resolve/${encodeURIComponent(cleanId)}`);
            if (!dirRes || !dirRes.found) {
                showNotificationToast(dirRes?.error || `No online peer found for ${cleanId}.`, "error");
                return;
            }
            if (dirRes.host) {
                const connRes = await apiRequest("/api/devices/connect-peer", "POST", { snow_id: cleanId });
                if (connRes && connRes.success) {
                    showNotificationToast(`Connected to ${cleanId}!`, "success");
                    refreshAllData();
                } else {
                    showNotificationToast(connRes?.error || `Found ${cleanId} via ${dirRes.source || "directory"}, pairing confirmation may be required.`, "info");
                }
                return;
            }
            showNotificationToast(`Resolved ${cleanId} via cloud hub directory!`, "success");
            return;
        }

        const parsed = parseHostAndPort(rawVal);
        if (!parsed) return;
        showNotificationToast(`Connecting to ${parsed.host}:${parsed.port}...`, "info");
        const res = await apiRequest("/api/devices/connect-peer", "POST", { host: parsed.host, port: parsed.port });
        if (res && res.success) {
            showNotificationToast("Connected to peer device!", "success");
            refreshAllData();
        } else {
            showNotificationToast(res?.error || "Connection failed (check Advanced Diagnostics if manual PIN needed)", "error");
        }
    }

    function setDeviceFilter(filter) {
        currentDeviceFilter = filter;
        const btnAll = document.getElementById("btn-filter-all");
        const btnPcs = document.getElementById("btn-filter-pcs");
        const btnPhones = document.getElementById("btn-filter-phones");
        if (btnAll) btnAll.className = `btn btn-sm ${filter === "all" ? "btn-primary" : "btn-tonal"}`;
        if (btnPcs) btnPcs.className = `btn btn-sm ${filter === "pcs" ? "btn-primary" : "btn-tonal"}`;
        if (btnPhones) btnPhones.className = `btn btn-sm ${filter === "phones" ? "btn-primary" : "btn-tonal"}`;
        renderDevicesView();
    }

    function renderDevicesView() {
        const container = document.getElementById("devices-list-container");
        if (!container) return;
        container.innerHTML = "";

        const remoteDevs = registeredDevices.filter(d => !isLocalNode(d));
        const remotePcs = remoteDevs.filter(d => !isAndroidDevice(d));
        const remotePhones = remoteDevs.filter(d => isAndroidDevice(d));

        const cAll = document.getElementById("filter-count-all");
        const cPcs = document.getElementById("filter-count-pcs");
        const cPhones = document.getElementById("filter-count-phones");
        if (cAll) cAll.textContent = String(1 + remoteDevs.length);
        if (cPcs) cPcs.textContent = String(1 + remotePcs.length);
        if (cPhones) cPhones.textContent = String(remotePhones.length);

        let filtered = remoteDevs;
        if (currentDeviceFilter === "pcs") filtered = remotePcs;
        else if (currentDeviceFilter === "phones") filtered = remotePhones;

        // Render Local Host Card
        if (currentDeviceFilter === "all" || currentDeviceFilter === "pcs") {
            const isHostActive = !activeDeviceId || activeDeviceId === "local";
            const hostCard = document.createElement("div");
            hostCard.className = "device-card";
            hostCard.innerHTML = `
                <div class="flex items-center justify-between">
                    <div class="flex items-center gap-3">
                        <div class="island-icon-box">
                            <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><rect height="12" rx="2" width="20" x="2" y="4"></rect><line x1="2" x2="22" y1="20" y2="20"></line></svg>
                        </div>
                        <div class="flex flex-col">
                            <span class="text-sm font-bold text-primary">${escapeHtml(localHostIdentity)} (Host)</span>
                            <span class="text-xs text-muted">This PC • ${escapeHtml(canonicalSnowId)}</span>
                        </div>
                    </div>
                    <span class="chip chip-emerald">${isHostActive ? "Active Host" : "Host"}</span>
                </div>
            `;
            container.appendChild(hostCard);
        }

        if (filtered.length === 0 && currentDeviceFilter === "phones") {
            const emptyCard = document.createElement("div");
            emptyCard.className = "device-card empty-state";
            emptyCard.innerHTML = `<span class="text-sm text-muted">No paired phones found. Scan QR to pair your Android device.</span>`;
            container.appendChild(emptyCard);
        }

        filtered.forEach(dev => {
            const isConn = Boolean(dev.is_connected);
            const isSelected = dev.device_id === activeDeviceId;
            const transport = isConn ? resolveTransportLabel(dev) : "Offline";
            const connMode = dev.connection_mode || "auto";
            const permProf = dev.permission_profile || "full_control";
            const batVal = dev.telemetry?.battery_level ?? dev.battery?.level ?? dev.battery_level;
            const iconSvg = isAndroidDevice(dev)
                ? `<svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><rect height="20" rx="2" ry="2" width="14" x="5" y="2"></rect><line x1="12" x2="12.01" y1="18" y2="18"></line></svg>`
                : `<svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><rect height="12" rx="2" width="20" x="2" y="4"></rect><line x1="2" x2="22" y1="20" y2="20"></line></svg>`;

            const card = document.createElement("div");
            card.className = "device-card";
            card.innerHTML = `
                <div class="flex items-center justify-between gap-2">
                    <div class="flex items-center gap-3 min-w-0">
                        <div class="island-icon-box">${iconSvg}</div>
                        <div class="flex flex-col min-w-0">
                            <span class="text-sm font-bold text-primary truncate">${escapeHtml(dev.device_name || "Device")}</span>
                            <span class="text-xs text-muted">${isConn ? `Connected • ${transport}` : "Disconnected"}${batVal != null ? ` • ${batVal}%` : ""} • ${escapeHtml((dev.snow_id || dev.device_id).slice(0, 13).replace(/-$/, ""))}</span>
                        </div>
                    </div>
                    <span class="chip ${isConn ? "chip-cyan" : "chip-amber"}">${transport}</span>
                </div>

                <div class="flex items-center justify-between gap-2 flex-wrap">
                    <div class="flex items-center gap-2">
                        <select class="form-input text-xs dev-profile-select" style="width: auto; padding: 5px 8px;" title="Permission Profile">
                            <option value="full_control" ${permProf === "full_control" ? "selected" : ""}>Full Control</option>
                            <option value="files_and_clipboard" ${permProf === "files_and_clipboard" ? "selected" : ""}>Files &amp; Clipboard</option>
                            <option value="files_only" ${permProf === "files_only" ? "selected" : ""}>Files Only</option>
                            <option value="clipboard_only" ${permProf === "clipboard_only" ? "selected" : ""}>Clipboard Only</option>
                            <option value="not_allowed" ${permProf === "not_allowed" ? "selected" : ""}>Not Allowed</option>
                        </select>
                        <select class="form-input text-xs dev-connmode-select" style="width: auto; padding: 5px 8px;" title="Connection Mode">
                            <option value="auto" ${connMode === "auto" ? "selected" : ""}>Auto</option>
                            <option value="local_only" ${connMode === "local_only" ? "selected" : ""}>Local Only</option>
                            <option value="remote_only" ${connMode === "remote_only" ? "selected" : ""}>Remote Only</option>
                        </select>
                    </div>
                    <div class="flex items-center gap-2">
                        <button class="btn btn-xs ${isSelected ? "btn-primary" : "btn-tonal"} btn-dev-select">${isSelected ? "Active" : "Switch"}</button>
                        ${isConn
                            ? `<button class="btn btn-xs btn-tonal btn-dev-disconnect">Disconnect</button>`
                            : `<button class="btn btn-xs btn-primary btn-dev-reconnect">Reconnect</button>`}
                        <button class="btn btn-xs btn-danger btn-dev-revoke">Revoke</button>
                    </div>
                </div>
            `;

            card.querySelector(".dev-profile-select").onchange = async (e) => {
                const res = await apiRequest("/api/devices/permission-profile", "POST", { device_id: dev.device_id, profile: e.target.value });
                if (res && res.success) showNotificationToast(`Updated profile for ${dev.device_name || "device"}.`, "success");
                else showNotificationToast(res?.error || "Failed updating permission profile", "error");
            };

            card.querySelector(".dev-connmode-select").onchange = async (e) => {
                const res = await apiRequest("/api/devices/connection-mode", "POST", { device_id: dev.device_id, connection_mode: e.target.value });
                if (res && res.success) showNotificationToast(`Updated connection mode for ${dev.device_name || "device"}.`, "success");
                else showNotificationToast(res?.error || "Failed updating connection mode", "error");
            };

            card.querySelector(".btn-dev-select").onclick = () => {
                selectActiveDevice(dev.device_id, true);
                showNotificationToast(`Switched active target to ${dev.device_name || "device"}.`, "info");
            };

            const disconnectBtn = card.querySelector(".btn-dev-disconnect");
            if (disconnectBtn) {
                disconnectBtn.onclick = async () => {
                    disconnectBtn.disabled = true;
                    const res = await apiRequest("/api/devices/disconnect", "POST", { device_id: dev.device_id });
                    if (res && res.success) {
                        showNotificationToast(`Disconnected ${dev.device_name || "device"}. Pairing preserved.`, "info");
                        refreshAllData();
                    } else {
                        disconnectBtn.disabled = false;
                        showNotificationToast(res?.error || "Could not disconnect device", "error");
                    }
                };
            }

            const reconnectBtn = card.querySelector(".btn-dev-reconnect");
            if (reconnectBtn) {
                reconnectBtn.onclick = async () => {
                    reconnectBtn.disabled = true;
                    const res = await apiRequest("/api/devices/reconnect", "POST", { device_id: dev.device_id });
                    if (res && res.success) {
                        showNotificationToast(
                            res.is_connected
                                ? `Reconnected ${dev.device_name || "device"}!`
                                : `Reconnect authorized for ${dev.device_name || "device"}.`,
                            res.is_connected ? "success" : "info"
                        );
                        refreshAllData();
                    } else {
                        reconnectBtn.disabled = false;
                        showNotificationToast(res?.error || "Reconnect failed", "error");
                    }
                };
            }

            card.querySelector(".btn-dev-revoke").onclick = async () => {
                const res = await apiRequest("/api/devices/revoke", "POST", { device_id: dev.device_id });
                if (res && res.success) {
                    showNotificationToast(`Revoked ${dev.device_name || "device"}.`, "warning");
                    if (activeDeviceId === dev.device_id) activeDeviceId = "local";
                    refreshAllData();
                } else {
                    showNotificationToast(res?.error || "Could not revoke device", "error");
                }
            };

            container.appendChild(card);
        });

        const netIdEl = document.getElementById("devices-net-id");
        const netIpsEl = document.getElementById("devices-net-ips");
        const netStatusEl = document.getElementById("devices-net-status");
        if (netIdEl) netIdEl.textContent = canonicalSnowId;
        if (netIpsEl) {
            const ips = Array.isArray(lastStatusSnapshot?.lan_ips) ? lastStatusSnapshot.lan_ips : [];
            netIpsEl.textContent = ips.length > 0 ? ips.join(", ") : "127.0.0.1 (Loopback)";
        }
        if (netStatusEl) {
            const usbOk = Boolean(lastStatusSnapshot?.usb_connected);
            netStatusEl.textContent = `${isCoreOnline ? "Core Online" : "Core Offline"} • ${usbOk ? "USB Connected" : "USB Idle"}`;
        }

        refreshPairingState();
        loadRelayTunnelStatus();
        loadFederationGrants();
    }

    function renderIdlePairingState(label = "No active PIN", countdownText = "--") {
        lastPairingSnapshotHasActivePin = false;
        if (qrCountdownTimer) {
            clearInterval(qrCountdownTimer);
            qrCountdownTimer = null;
        }
        const qrBox = document.getElementById("pairing-qr-box");
        const modalQrBox = document.getElementById("modal-qr-container");
        const pinEl = document.getElementById("pairing-pin-display");
        const modalPinEl = document.getElementById("modal-pairing-pin");
        const countdownEl = document.getElementById("pairing-countdown-display");
        const cancelBtn = document.getElementById("btn-pairing-cancel-pin");

        const idleMsg = `<span class="text-xs text-muted text-center">Click Generate Pairing QR &amp; PIN when ready</span>`;
        if (qrBox) {
            qrBox.classList.remove("qr-active");
            qrBox.innerHTML = idleMsg;
        }
        if (modalQrBox) {
            modalQrBox.classList.remove("qr-active");
            modalQrBox.innerHTML = idleMsg;
        }
        if (pinEl) pinEl.textContent = label;
        if (modalPinEl) modalPinEl.textContent = label;
        if (countdownEl) countdownEl.textContent = countdownText;
        cancelBtn?.classList.add("d-none");
    }

    function applyPairingState(res, isActiveGeneration = false) {
        const qrBox = document.getElementById("pairing-qr-box");
        const modalQrBox = document.getElementById("modal-qr-container");
        const snowIdEl = document.getElementById("pairing-snow-id");
        const modalNetEl = document.getElementById("modal-network-id");
        const fpEl = document.getElementById("pairing-device-fp");
        const pinEl = document.getElementById("pairing-pin-display");
        const modalPinEl = document.getElementById("modal-pairing-pin");
        const countdownEl = document.getElementById("pairing-countdown-display");
        const cancelBtn = document.getElementById("btn-pairing-cancel-pin");

        const dataObj = res?.data || res || {};
        const effectiveSnowId = dataObj?.snow_id || canonicalSnowId;
        if (snowIdEl) snowIdEl.textContent = effectiveSnowId;
        if (modalNetEl) modalNetEl.textContent = effectiveSnowId;

        const fpVal = res?.data?.fp || res?.fp || res?.data?.cert_fingerprint || res?.cert_fingerprint || "";
        if (fpEl) {
            if (fpVal) {
                fpEl.textContent = `${fpVal.slice(0, 16)}...`;
                fpEl.title = fpVal;
            } else {
                fpEl.textContent = "--";
                fpEl.removeAttribute("title");
            }
        }

        const pinVal = res?.data?.pin || res?.pin || "";
        const hasActivePin = Boolean(
            pinVal && (isActiveGeneration || dataObj?.has_active_pin === true)
        );

        if (!hasActivePin) {
            if (res && res.success === false && qrBox) {
                qrBox.classList.remove("qr-active");
                qrBox.innerHTML = `<span class="text-xs text-muted text-center">Core Offline</span>`;
                if (modalQrBox) {
                    modalQrBox.classList.remove("qr-active");
                    modalQrBox.innerHTML = `<span class="text-xs text-muted text-center">Core Offline</span>`;
                }
                if (pinEl) pinEl.textContent = "Unavailable";
                if (countdownEl) countdownEl.textContent = "--";
                cancelBtn?.classList.add("d-none");
                return;
            }
            renderIdlePairingState("No active PIN", "--");
            return;
        }

        lastPairingSnapshotHasActivePin = true;
        const svgMarkup = res?.svg || res?.qr_svg || res?.data?.svg;
        if (svgMarkup) {
            if (qrBox) {
                qrBox.classList.add("qr-active");
                qrBox.innerHTML = svgMarkup;
            }
            if (modalQrBox) {
                modalQrBox.classList.add("qr-active");
                modalQrBox.innerHTML = svgMarkup;
            }
        } else {
            qrBox?.classList.remove("qr-active");
            modalQrBox?.classList.remove("qr-active");
        }

        const fmtPin = pinVal.length === 6 ? `${pinVal.slice(0, 3)} ${pinVal.slice(3)}` : pinVal;
        if (pinEl) pinEl.textContent = fmtPin;
        if (modalPinEl) modalPinEl.textContent = fmtPin;
        cancelBtn?.classList.remove("d-none");

        let remaining = Number.isFinite(Number(dataObj?.remaining_seconds))
            ? Math.max(1, Math.round(Number(dataObj.remaining_seconds)))
            : 60;
        if (countdownEl) countdownEl.textContent = `${remaining}s`;
        if (qrCountdownTimer) clearInterval(qrCountdownTimer);
        qrCountdownTimer = setInterval(() => {
            remaining--;
            if (countdownEl) countdownEl.textContent = `${Math.max(0, remaining)}s`;
            if (remaining <= 0) {
                clearInterval(qrCountdownTimer);
                qrCountdownTimer = null;
                renderIdlePairingState("Expired", "0s");
            }
        }, 1000);
    }

    async function refreshPairingState() {
        const res = await apiRequest("/api/pair/state");
        applyPairingState(res, false);
    }

    async function cancelPairingPin() {
        const res = await apiRequest("/api/pair/cancel", "POST", {});
        renderIdlePairingState("No active PIN", "--");
        if (res && res.success) {
            showNotificationToast("Pairing PIN cancelled.", "info");
        }
    }

    async function loadPairingQR() {
        const snowIdEl = document.getElementById("pairing-snow-id");
        const modalNetEl = document.getElementById("modal-network-id");
        if (snowIdEl) snowIdEl.textContent = canonicalSnowId;
        if (modalNetEl) modalNetEl.textContent = canonicalSnowId;

        const res = await apiRequest("/api/pair/qr", "POST", { trust_tier: "owner" });
        const svgMarkup = res?.svg || res?.qr_svg || res?.data?.svg;
        const pinVal = res?.data?.pin || res?.pin;
        const fpVal = res?.data?.fp || res?.data?.cert_fingerprint || res?.fp || res?.cert_fingerprint;
        if (res && res.success && (svgMarkup || pinVal || fpVal)) {
            applyPairingState(res, true);
            return true;
        }
        applyPairingState(res, false);
        showNotificationToast(res?.error || "Failed generating pairing QR & PIN", "error");
        return false;
    }

    async function loadApkQr() {
        const apkBox = document.getElementById("apk-qr-box");
        const apkUrlEl = document.getElementById("apk-download-url");
        const dlBtn = document.getElementById("btn-devices-download-apk");
        const res = await apiRequest("/api/app/apk-info");
        const svgMarkup = res?.svg || res?.qr_svg;

        if (res && res.success) {
            if (svgMarkup && apkBox) {
                apkBox.classList.add("qr-active");
                apkBox.innerHTML = svgMarkup;
            } else if (apkBox) {
                apkBox.classList.remove("qr-active");
                apkBox.innerHTML = `<span class="text-xs text-muted text-center">QR unavailable</span>`;
            }
            if (res.apk_available) {
                if (apkUrlEl) apkUrlEl.textContent = res.download_url || "Ready for LAN download";
                if (dlBtn) {
                    dlBtn.href = res.local_download_url || res.download_url || "#";
                    dlBtn.textContent = `Download ${res.file_name || "SNOW-Mobile.apk"} (${res.version || "7.0.0"})`;
                    dlBtn.classList.remove("d-none");
                }
            } else {
                if (apkUrlEl) apkUrlEl.textContent = "APK binary not yet built (run gradlew assembleRelease)";
                dlBtn?.classList.add("d-none");
            }
        }
    }

    async function loadRelayTunnelStatus() {
        const badge = document.getElementById("relay-tunnel-badge");
        const detail = document.getElementById("relay-tunnel-detail");
        const chkRelay = document.getElementById("chk-relay-tunnel-toggle");
        const res = await apiRequest("/api/relay/tunnel/status");

        const isVerifiedActive = Boolean(
            isCoreOnline &&
            res &&
            res.success &&
            res.active &&
            res.public_url
        );
        const isEnabledConnecting = Boolean(
            isCoreOnline &&
            res &&
            res.success &&
            res.enabled &&
            !isVerifiedActive
        );
        if (chkRelay) chkRelay.checked = isVerifiedActive || isEnabledConnecting;
        if (isVerifiedActive) {
            if (badge) {
                badge.textContent = res.provider === "render" ? "Active • Render Hub" : "Active";
                badge.className = "chip chip-sm chip-emerald";
            }
            if (detail) {
                detail.textContent = `Remote relay access active via ${res.public_url}.`;
            }
        } else if (isEnabledConnecting) {
            if (badge) {
                badge.textContent = "Connecting";
                badge.className = "chip chip-sm chip-amber";
            }
            if (detail) {
                detail.textContent = res.public_url
                    ? `Establishing Render Hub connection (${res.public_url})...`
                    : "Establishing Render Hub connection...";
            }
        } else {
            if (badge) {
                badge.textContent = isCoreOnline ? "Offline" : "Unavailable";
                badge.className = "chip chip-sm chip-neutral";
            }
            if (detail) {
                detail.textContent = isCoreOnline
                    ? "Off-network relay is stopped."
                    : "Core offline — Remote Access disabled.";
            }
        }
    }

    async function loadFederationGrants() {
        const container = document.getElementById("federation-grants-container");
        const res = await apiRequest("/api/federation/grants");
        federationGrants = (res && Array.isArray(res.grants)) ? res.grants : [];
        if (!container) return;
        container.innerHTML = "";

        if (federationGrants.length > 0) {
            federationGrants.forEach(g => {
                const row = document.createElement("div");
                row.className = "flex items-center justify-between text-xs p-2 gap-2";
                row.style.background = "var(--snow-bg-elevated)";
                row.style.borderRadius = "var(--snow-radius-sm)";
                row.style.border = "1px solid var(--snow-border)";
                const label = g.network_name || g.peer_node_name || g.peer_node_id || g.grant_id;
                const status = g.status || "ACTIVE";
                const curTier = g.permission_tier || "files_and_clipboard";
                row.innerHTML = `
                    <div class="flex flex-col min-w-0 flex-1">
                        <strong class="truncate text-primary">${escapeHtml(label)}</strong>
                        <span class="text-muted">${escapeHtml(g.direction || "INBOUND")} • ${escapeHtml(status)}</span>
                    </div>
                    ${status === "ACTIVE" ? `
                        <select class="form-input text-xs fed-tier-select" style="width: auto; padding: 3px 6px;" title="Grant Permission Tier">
                            <option value="full_control" ${curTier === "full_control" ? "selected" : ""}>Full Control</option>
                            <option value="files_and_clipboard" ${curTier === "files_and_clipboard" ? "selected" : ""}>Files &amp; Clipboard</option>
                            <option value="files_only" ${curTier === "files_only" ? "selected" : ""}>Files Only</option>
                            <option value="clipboard_only" ${curTier === "clipboard_only" ? "selected" : ""}>Clipboard Only</option>
                            <option value="not_allowed" ${curTier === "not_allowed" ? "selected" : ""}>Not Allowed</option>
                        </select>
                        <button class="btn btn-xs btn-danger btn-revoke-grant">Revoke</button>
                    ` : `<span class="chip chip-sm chip-neutral">${escapeHtml(status)}</span>`}
                `;
                row.querySelector(".fed-tier-select")?.addEventListener("change", async (e) => {
                    const tierRes = await apiRequest("/api/federation/tier", "POST", {
                        grant_id: g.grant_id,
                        permission_tier: e.target.value,
                    });
                    if (tierRes && tierRes.success) {
                        showNotificationToast(`Updated federation tier to ${e.target.value}.`, "success");
                        refreshAllData();
                    } else {
                        showNotificationToast(tierRes?.error || "Failed updating federation tier", "error");
                    }
                });
                row.querySelector(".btn-revoke-grant")?.addEventListener("click", async () => {
                    await apiRequest("/api/federation/revoke", "POST", { grant_id: g.grant_id });
                    showNotificationToast("Federation grant revoked.", "info");
                    refreshAllData();
                });
                container.appendChild(row);
            });
        } else {
            container.innerHTML = `<span class="text-xs text-muted">No active federation grants.</span>`;
        }
    }

    // =========================================================================
    // 8. View 3: Files & Apps
    // =========================================================================

    function initFilesView() {
        const tabFiles = document.getElementById("tab-seg-files");
        const tabApps = document.getElementById("tab-seg-apps");

        if (tabFiles && tabApps) {
            tabFiles.onclick = () => focusFilesSegment("files");
            tabApps.onclick = () => focusFilesSegment("apps");
        }

        const filesDevSelect = document.getElementById("files-device-select");
        if (filesDevSelect) {
            filesDevSelect.onchange = () => selectActiveDevice(filesDevSelect.value, true);
        }

        document.getElementById("files-search-input")?.addEventListener("input", filterFileRows);
        document.getElementById("apps-search-input")?.addEventListener("input", filterAppTiles);
        document.getElementById("chk-hide-hidden")?.addEventListener("change", () => loadFiles(currentSubpath));
        document.getElementById("btn-change-transfers-folder")?.addEventListener("click", async () => {
            const pickBtn = document.getElementById("btn-change-transfers-folder");
            if (pickBtn) pickBtn.disabled = true;
            try {
                const pickRes = await apiRequest("/api/files/pick-destination", "POST", {});
                if (!pickRes || !pickRes.success) {
                    showNotificationToast(pickRes?.error || "Unable to open folder picker", "error");
                    return;
                }
                if (pickRes.cancelled || !pickRes.selected || !pickRes.path) {
                    return;
                }
                const setRes = await apiRequest("/api/files/destination", "POST", { path: pickRes.path });
                if (setRes && setRes.success && setRes.pc_transfers_dir) {
                    pcTransfersDestDir = setRes.pc_transfers_dir;
                    const destEl = document.getElementById("files-destination-path");
                    if (destEl) {
                        destEl.textContent = setRes.pc_transfers_dir;
                        destEl.title = setRes.pc_transfers_dir;
                    }
                    showNotificationToast(`Incoming folder updated to ${setRes.pc_transfers_dir}`, "success");
                } else {
                    showNotificationToast(setRes?.error || "Could not update destination folder", "error");
                }
            } finally {
                if (pickBtn) pickBtn.disabled = false;
            }
        });
        document.getElementById("btn-open-transfers-folder")?.addEventListener("click", async () => {
            const res = await apiRequest("/api/files/open-transfers-folder", "POST", {});
            if (res && res.success) {
                showNotificationToast(
                    res.opened ? `Opened ${res.path || "Transfers folder"}` : `Transfers folder: ${res.path}`,
                    "success"
                );
            } else {
                showNotificationToast(res?.error || "Unable to open transfers folder", "error");
            }
        });

        document.getElementById("btn-file-up")?.addEventListener("click", () => {
            if (currentStorageMode === "desktop_remote") {
                if (currentRemoteParent !== null && currentRemoteParent !== undefined && currentRemoteParent !== currentSubpath) {
                    loadFiles(currentRemoteParent);
                }
                return;
            }
            if (currentSubpath) {
                const parts = currentSubpath.replace(/\\/g, "/").split("/").filter(Boolean);
                parts.pop();
                currentSubpath = parts.join("/");
                loadFiles(currentSubpath);
            }
        });

        const fileInput = document.getElementById("file-upload-input");
        document.getElementById("btn-trigger-upload")?.addEventListener("click", () => fileInput?.click());

        if (fileInput) {
            fileInput.onchange = (e) => {
                if (e.target.files && e.target.files.length > 0) {
                    uploadFiles(e.target.files);
                    e.target.value = "";
                }
            };
        }

        document.getElementById("btn-share-pc-screen")?.addEventListener("click", openPcSharePicker);
        document.getElementById("btn-stop-pc-share")?.addEventListener("click", stopPcScreenShare);
        document.getElementById("btn-close-pc-share-modal")?.addEventListener("click", () => {
            document.getElementById("pc-share-targets-modal")?.classList.add("d-none");
        });
        document.getElementById("btn-pc-share-cancel")?.addEventListener("click", () => {
            document.getElementById("pc-share-targets-modal")?.classList.add("d-none");
        });
        document.getElementById("btn-pc-share-confirm")?.addEventListener("click", confirmStartPcScreenShare);
        document.getElementById("btn-stop-screen-stream")?.addEventListener("click", stopRemoteScreenStream);
        document.getElementById("btn-retry-screen-stream")?.addEventListener("click", () => {
            screenFrameErrorCount = 0;
            pollScreenStreamStatus();
        });
    }

    function focusFilesSegment(seg) {
        currentFilesSegment = (seg === "apps") ? "apps" : "files";
        document.getElementById("tab-seg-files")?.classList.toggle("active", currentFilesSegment === "files");
        document.getElementById("tab-seg-apps")?.classList.toggle("active", currentFilesSegment === "apps");

        const subFiles = document.getElementById("subpanel-files");
        const subApps = document.getElementById("subpanel-apps");
        const layout = document.querySelector(".files-v5-layout");

        if (window.innerWidth <= 1024) {
            subFiles?.classList.toggle("d-none", currentFilesSegment !== "files");
            subApps?.classList.toggle("d-none", currentFilesSegment !== "apps");
        } else {
            subFiles?.classList.remove("d-none");
            subApps?.classList.remove("d-none");
            if (currentFilesSegment === "apps") {
                subApps?.scrollIntoView({ behavior: "smooth", block: "nearest" });
            }
        }
        if (layout) layout.dataset.focus = currentFilesSegment;
    }

    function getTransferRouteBadgeInfo(devObj) {
        if (!devObj) return { text: "Wi-Fi • Zero Data", cls: "chip chip-sm chip-cyan" };
        const raw = String(
            devObj.active_transport || devObj.transport || devObj.connection_mode || devObj.remote_address || ""
        ).toLowerCase();
        if (raw.includes("usb") || raw.includes("adb") || raw.includes("127.0.0.1")) {
            return { text: "USB • Zero Data", cls: "chip chip-sm chip-emerald" };
        }
        if (raw.includes("relay") || raw.includes("remote") || raw.includes("tunnel")) {
            return { text: "Remote • Uses Data", cls: "chip chip-sm chip-amber" };
        }
        return { text: "Wi-Fi • Zero Data", cls: "chip chip-sm chip-cyan" };
    }

    function updateTransferProgressUi({
        visible,
        title = "",
        loaded = 0,
        total = 0,
        pct = 0,
        speedBps = 0,
        indeterminate = false,
        routeBadge = null,
    }) {
        const containers = [
            {
                card: document.getElementById("active-transfer-container"),
                name: document.getElementById("active-transfer-name"),
                badge: document.getElementById("active-transfer-route-badge"),
                speed: document.getElementById("active-transfer-speed"),
                bar: document.getElementById("active-transfer-progress"),
                bytes: document.getElementById("active-transfer-bytes"),
                pctEl: document.getElementById("active-transfer-percent"),
            },
            {
                card: document.getElementById("files-active-transfer-card"),
                name: document.getElementById("files-transfer-name"),
                badge: document.getElementById("files-transfer-route-badge"),
                speed: document.getElementById("files-transfer-speed"),
                bar: document.getElementById("files-transfer-progress"),
                bytes: document.getElementById("files-transfer-bytes"),
                pctEl: document.getElementById("files-transfer-percent"),
            },
        ];
        const topbarChip = document.getElementById("topbar-active-transfer-chip");
        topbarChip?.classList.toggle("d-none", !visible);

        containers.forEach(c => {
            if (!c.card) return;
            c.card.classList.toggle("d-none", !visible);
            if (!visible) {
                if (c.bar) {
                    c.bar.classList.remove("indeterminate");
                    c.bar.style.width = "0%";
                }
                return;
            }
            if (c.name && title) c.name.textContent = title;
            if (c.badge && routeBadge) {
                c.badge.textContent = routeBadge.text;
                c.badge.className = routeBadge.cls;
            }
            if (c.bar) {
                c.bar.classList.toggle("indeterminate", Boolean(indeterminate));
                if (!indeterminate) c.bar.style.width = `${Math.max(0, Math.min(100, pct))}%`;
            }
            if (c.pctEl) c.pctEl.textContent = indeterminate ? "In Progress" : `${pct}%`;
            if (c.bytes) {
                c.bytes.textContent = total > 0
                    ? `${formatBytes(loaded)} / ${formatBytes(total)}`
                    : (loaded > 0 ? formatBytes(loaded) : "Streaming over HTTPS...");
            }
            if (c.speed) {
                c.speed.textContent = speedBps > 0 ? `${formatBytes(speedBps)}/s` : (indeterminate ? "HTTPS :8766" : "0 KB/s");
            }
        });
    }

    async function cancelActiveTransfer() {
        let didCancel = false;
        if (activeUploadXhr) {
            activeUploadXhr.abort();
            activeUploadXhr = null;
            didCancel = true;
        }
        if (activeDownloadController) {
            activeDownloadController.abort();
            activeDownloadController = null;
            didCancel = true;
            apiRequest("/api/files/transfer/cancel", "POST", {}).catch(() => {});
        }
        updateTransferProgressUi({ visible: false });
        if (didCancel) {
            showNotificationToast("File transfer cancelled.", "warning");
        }
    }

    async function refreshFileDestinations() {
        const destEl = document.getElementById("files-destination-path");
        if (!destEl) return;
        const res = await apiRequest("/api/files/destinations");
        if (res && res.success && res.pc_transfers_dir) {
            pcTransfersDestDir = res.pc_transfers_dir;
            destEl.textContent = res.pc_transfers_dir;
            destEl.title = res.pc_transfers_dir;
        }
    }

    function filterFileRows() {
        const q = (document.getElementById("files-search-input")?.value || "").trim().toLowerCase();
        document.querySelectorAll("#file-table-body tr[data-filename]").forEach(tr => {
            const fname = tr.getAttribute("data-filename") || "";
            tr.style.display = (!q || fname.includes(q)) ? "" : "none";
        });
    }

    async function loadFiles(subpath = "") {
        currentSubpath = subpath;
        refreshFileDestinations();
        const breadcrumbEl = document.getElementById("file-breadcrumbs");
        const targetLabel = document.getElementById("files-transfer-target-label");
        const tbody = document.getElementById("file-table-body");
        const emptyState = document.getElementById("file-empty-state");
        const emptyMsg = document.getElementById("file-empty-message");
        const uploadBtn = document.getElementById("btn-trigger-upload");
        const upBtn = document.getElementById("btn-file-up");

        if (breadcrumbEl) breadcrumbEl.textContent = subpath ? (subpath.startsWith("/") || subpath.includes(":\\") ? subpath : `/${subpath}`) : "/";
        const devObj = getSelectedDeviceObj();
        const isLocalTarget = !devObj || isLocalNode(devObj);
        const isAndroid = Boolean(devObj && isAndroidDevice(devObj));
        const isTargetOnline = Boolean(devObj && devObj.is_connected);

        if (uploadBtn) uploadBtn.disabled = isLocalTarget || !isTargetOnline || !isAndroid;
        if (upBtn) upBtn.disabled = isLocalTarget || !isTargetOnline || (!subpath && !currentRemoteParent);

        if (targetLabel) {
            if (isLocalTarget) {
                targetLabel.textContent = "Local Windows Host active — select a connected device above to browse remote files or transfer files.";
            } else if (!isTargetOnline) {
                targetLabel.textContent = `${devObj.device_name || "Device"} is offline — reconnect to browse or transfer files over HTTPS (port 8766).`;
            } else {
                const routeInfo = getTransferRouteBadgeInfo(devObj);
                targetLabel.textContent = `Encrypted HTTPS transfer to ${devObj.device_name || "Device"} (${routeInfo.text})`;
            }
        }
        if (!tbody) return;

        if (isLocalTarget) {
            tbody.innerHTML = "";
            if (emptyMsg) {
                emptyMsg.textContent = "Local Windows PC mode: Use Quick Launch Apps on the right for desktop tools, or select a connected device above to browse remote files.";
            }
            emptyState?.classList.remove("d-none");
            return;
        }

        if (!isTargetOnline) {
            tbody.innerHTML = "";
            if (emptyMsg) {
                emptyMsg.textContent = `${devObj.device_name || "Device"} is currently offline. Reconnect to browse remote files.`;
            }
            emptyState?.classList.remove("d-none");
            return;
        }

        const targetId = devObj.device_id;
        const hideHidden = document.getElementById("chk-hide-hidden")?.checked ?? true;
        const devTypeHint = isAndroid ? "android" : "windows";
        tbody.innerHTML = `<tr><td colspan="4" class="text-muted text-center" style="padding: 20px;">Loading files...</td></tr>`;
        emptyState?.classList.add("d-none");

        const res = await apiRequest(
            `/api/files?subpath=${encodeURIComponent(subpath)}&hide_hidden=${hideHidden}&device_id=${encodeURIComponent(targetId)}&device_type=${encodeURIComponent(devTypeHint)}`
        );
        const items = res?.items || res?.files || res?.data?.items || [];
        currentStorageMode = res?.storage_mode || (isAndroid ? "saf_tree" : "desktop_remote");
        currentRemoteParent = res?.parent || "";
        if (res?.destination_dir) {
            pcTransfersDestDir = res.destination_dir;
            const destEl = document.getElementById("files-destination-path");
            if (destEl) destEl.textContent = res.destination_dir;
        }
        if (currentStorageMode === "desktop_remote" && res?.directory && breadcrumbEl) {
            breadcrumbEl.textContent = res.directory;
        }
        if (upBtn) {
            upBtn.disabled = isLocalTarget || !isTargetOnline || (currentStorageMode === "desktop_remote" ? !currentRemoteParent : !subpath);
        }

        if (!res || !res.success) {
            tbody.innerHTML = "";
            if (emptyMsg) emptyMsg.textContent = res?.error || "Unable to browse files on selected device.";
            emptyState?.classList.remove("d-none");
            return;
        }

        tbody.innerHTML = "";
        if (!Array.isArray(items) || items.length === 0) {
            if (emptyMsg) emptyMsg.textContent = "Empty directory";
            emptyState?.classList.remove("d-none");
            return;
        }

        items.forEach(f => {
            const rawType = String(f.type || "").toLowerCase();
            const isDir = Boolean(f.is_dir || f.is_directory || rawType === "directory" || rawType === "dir");
            const rawSize = f.size_bytes ?? f.size ?? f.bytes;
            const rawMod = f.last_modified ?? f.modified_at ?? f.modified ?? f.modified_time;
            const modTime = formatTimestamp(rawMod) || "--";
            const row = document.createElement("tr");
            row.setAttribute("data-filename", String(f.name || "").toLowerCase());

            row.innerHTML = `
                <td>
                    <div class="flex items-center gap-2 cursor-pointer file-row-open">
                        <svg class="svg-icon svg-icon-sm ${isDir ? "text-cyan" : "text-muted"}" viewBox="0 0 24 24">
                            ${isDir ? '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>' : '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>'}
                        </svg>
                        <span class="${isDir ? "text-primary font-semibold" : "text-secondary"}">${escapeHtml(f.name)}</span>
                    </div>
                </td>
                <td class="text-xs text-muted mono">${isDir ? "--" : (f.size_formatted || formatBytes(rawSize))}</td>
                <td class="text-xs text-muted">${escapeHtml(modTime)}</td>
                <td style="text-align: right;">
                    ${isDir ? `<button class="btn btn-xs btn-tonal btn-open-dir">Open</button>` : `<button class="btn btn-xs btn-primary btn-dl-file">Download</button>`}
                </td>
            `;

            if (isDir) {
                const enterDir = () => {
                    const nextTarget = currentStorageMode === "desktop_remote"
                        ? (f.path || (subpath ? `${subpath}/${f.name}` : f.name))
                        : (subpath ? `${subpath}/${f.name}` : f.name);
                    loadFiles(nextTarget);
                };
                row.querySelector(".btn-open-dir").onclick = enterDir;
                row.querySelector(".file-row-open").onclick = enterDir;
            } else {
                row.querySelector(".btn-dl-file").onclick = async () => {
                    const routeBadge = getTransferRouteBadgeInfo(devObj);
                    if (activeDownloadController) activeDownloadController.abort();
                    activeDownloadController = new AbortController();
                    updateTransferProgressUi({
                        visible: true,
                        title: `Downloading ${f.name}`,
                        total: Number(rawSize || 0),
                        indeterminate: true,
                        routeBadge,
                    });
                    showNotificationToast(`Downloading ${f.name} to PC transfers...`, "info");
                    try {
                        const headers = { "Content-Type": "application/json" };
                        if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
                        const resp = await fetch("/api/files/download", {
                            method: "POST",
                            headers,
                            signal: activeDownloadController.signal,
                            body: JSON.stringify({
                                file_name: f.name,
                                subpath: currentSubpath,
                                device_id: targetId,
                            }),
                        });
                        const dlRes = await resp.json().catch(() => ({}));
                        if (resp.ok && dlRes && dlRes.success) {
                            const savedDir = dlRes.destination_dir || pcTransfersDestDir || "PC Transfers";
                            updateTransferProgressUi({
                                visible: true,
                                title: `Downloaded ${f.name}`,
                                loaded: Number(rawSize || 0),
                                total: Number(rawSize || 0),
                                pct: 100,
                                indeterminate: false,
                                routeBadge,
                            });
                            setTimeout(() => updateTransferProgressUi({ visible: false }), 1800);
                            showNotificationToast(`Downloaded ${f.name} to ${savedDir}`, "success");
                        } else {
                            updateTransferProgressUi({ visible: false });
                            showNotificationToast(dlRes?.error || "Download failed", "error");
                        }
                    } catch (err) {
                        updateTransferProgressUi({ visible: false });
                        if (err && err.name !== "AbortError") {
                            showNotificationToast(err.message || "Download failed", "error");
                        }
                    } finally {
                        activeDownloadController = null;
                    }
                };
            }
            tbody.appendChild(row);
        });
        filterFileRows();
    }

    function uploadFiles(files) {
        if (!files || files.length === 0) return;
        const targetId = resolveTargetDeviceId();
        if (!targetId) {
            showNotificationToast("Connect or select an Android phone to send files.", "warning");
            return;
        }
        const devObj = registeredDevices.find(d => d.device_id === targetId) || getSelectedDeviceObj();
        const routeBadge = getTransferRouteBadgeInfo(devObj);

        let idx = 0;
        function sendNext() {
            if (idx >= files.length) {
                activeUploadXhr = null;
                updateTransferProgressUi({ visible: false });
                loadFiles(currentSubpath);
                return;
            }

            const file = files[idx];
            const formData = new FormData();
            formData.append("device_id", targetId);
            formData.append("file", file);

            updateTransferProgressUi({
                visible: true,
                title: `Sending ${file.name}`,
                loaded: 0,
                total: file.size || 0,
                pct: 0,
                speedBps: 0,
                indeterminate: false,
                routeBadge,
            });

            const startTime = performance.now();
            const xhr = new XMLHttpRequest();
            activeUploadXhr = xhr;
            xhr.open("POST", "/api/files/upload", true);
            if (csrfToken) xhr.setRequestHeader("X-CSRF-Token", csrfToken);

            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const pct = Math.round((e.loaded / e.total) * 100);
                    const elapsedSec = Math.max(0.1, (performance.now() - startTime) / 1000);
                    const bps = e.loaded / elapsedSec;
                    updateTransferProgressUi({
                        visible: true,
                        title: `Sending ${file.name}`,
                        loaded: e.loaded,
                        total: e.total,
                        pct,
                        speedBps: bps,
                        indeterminate: false,
                        routeBadge,
                    });
                }
            };

            xhr.onload = () => {
                try {
                    const data = JSON.parse(xhr.responseText || "{}");
                    if (xhr.status >= 200 && xhr.status < 300 && data.success) {
                        const savedPath = data.data?.saved_path || data.saved_path;
                        showNotificationToast(
                            savedPath ? `Sent ${file.name} -> ${savedPath}` : `Sent ${file.name}!`,
                            "success"
                        );
                    } else {
                        showNotificationToast(data.error || `Failed sending ${file.name}`, "error");
                    }
                } catch (e) {
                    showNotificationToast(`Failed sending ${file.name}`, "error");
                }
                idx++;
                sendNext();
            };

            xhr.onerror = () => {
                showNotificationToast(`Network error uploading ${file.name}`, "error");
                idx++;
                sendNext();
            };

            xhr.onabort = () => {
                activeUploadXhr = null;
                updateTransferProgressUi({ visible: false });
            };

            xhr.send(formData);
        }
        sendNext();
    }

    function filterAppTiles() {
        const q = (document.getElementById("apps-search-input")?.value || "").trim().toLowerCase();
        document.querySelectorAll("#apps-grid-container .app-tile").forEach(tile => {
            const label = tile.getAttribute("data-appname") || "";
            tile.style.display = (!q || label.includes(q)) ? "flex" : "none";
        });
    }

    async function loadRemoteApps() {
        const container = document.getElementById("apps-grid-container");
        const emptyState = document.getElementById("apps-empty-state");
        const appsTitle = document.getElementById("apps-panel-title");
        const appsChip = document.getElementById("apps-panel-scope-chip");
        if (!container) return;
        container.innerHTML = "";

        const chosen = getSelectedDeviceObj();
        const isAndroid = chosen ? isAndroidDevice(chosen) : false;
        if (appsTitle) appsTitle.textContent = isAndroid ? "Remote Phone Apps" : "Quick Launch Apps (Windows)";
        if (appsChip) {
            appsChip.textContent = isAndroid ? "Android Launcher" : "Windows Allowlist";
            appsChip.className = isAndroid ? "chip chip-sm chip-cyan" : "chip chip-sm chip-emerald";
        }
        const endpoint = isAndroid
            ? `/api/apps/android?device_id=${encodeURIComponent(chosen.device_id)}`
            : "/api/apps/windows";

        const res = await apiRequest(endpoint);
        const apps = res?.apps || res?.data?.apps || [];

        if (res && res.success && Array.isArray(apps) && apps.length > 0) {
            emptyState?.classList.add("d-none");
            apps.forEach(rawApp => {
                const app = (typeof rawApp === "string") ? { name: rawApp, app_name: rawApp } : rawApp;
                const displayName = app.label || app.app_name || app.name || app.package_name || "Application";
                const tile = document.createElement("div");
                tile.className = "app-tile";
                tile.setAttribute("data-appname", displayName.toLowerCase());
                tile.innerHTML = `
                    <div class="island-icon-box" style="width:28px;height:28px;">
                        <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><rect height="18" rx="2" ry="2" width="18" x="3" y="3"></rect></svg>
                    </div>
                    <div class="flex flex-col min-w-0" style="flex:1;">
                        <span class="text-sm font-semibold text-primary truncate">${escapeHtml(displayName)}</span>
                        <span class="text-xs text-muted truncate">${escapeHtml(isAndroid ? "Android App" : "Windows Allowlist")}</span>
                    </div>
                    <button class="btn btn-xs btn-tonal btn-launch-app">Launch</button>
                `;

                tile.querySelector(".btn-launch-app").onclick = async () => {
                    showNotificationToast(`Launching ${displayName}...`, "info");
                    let launchRes;
                    if (isAndroid) {
                        launchRes = await apiRequest("/api/apps/android/launch", "POST", {
                            package_name: app.package_name || app.name,
                            device_id: chosen.device_id,
                        });
                    } else {
                        launchRes = await apiRequest("/api/apps/windows/launch", "POST", {
                            app_name: app.name || app.app_name || displayName,
                        });
                    }
                    if (launchRes && launchRes.success) {
                        showNotificationToast(`Launched ${displayName}!`, "success");
                    } else {
                        showNotificationToast(launchRes?.error || `Failed launching ${displayName}`, "error");
                    }
                };
                container.appendChild(tile);
            });
            filterAppTiles();
        } else {
            emptyState?.classList.remove("d-none");
        }
    }

    // =========================================================================
    // 9. View 4: Shared Clipboard
    // =========================================================================

    function getClipboardTargetEligibility() {
        const targetId = resolveTargetDeviceId();
        if (!targetId) {
            return { eligible: false, targetId: "", reason: "Connect a target device to send clipboard items" };
        }
        const dev = registeredDevices.find(d => d.device_id === targetId);
        if (!dev || !dev.is_connected) {
            return { eligible: false, targetId: "", reason: "Selected target device is offline" };
        }
        const prof = String(dev.permission_profile || "full_control").toLowerCase();
        if (prof === "not_allowed" || prof === "files_only") {
            return {
                eligible: false,
                targetId,
                reason: `Target permission profile (${prof.replace(/_/g, " ")}) blocks clipboard push`,
            };
        }
        return { eligible: true, targetId, reason: `Send to ${dev.device_name || targetId}` };
    }

    function initClipboardView() {
        const clipSyncToggle = document.getElementById("clipview-instant-sync-toggle");
        if (clipSyncToggle) {
            clipSyncToggle.addEventListener("change", async () => {
                const homeToggle = document.getElementById("clipboard-instant-sync-toggle");
                if (homeToggle) homeToggle.checked = clipSyncToggle.checked;
                const res = await apiRequest("/api/clipboard/sync", "POST", { direction: "both", device_id: resolveTargetDeviceId() });
                if (res && res.success) {
                    showNotificationToast("Clipboard synchronized.", "success");
                } else {
                    showNotificationToast(res?.error || "Clipboard sync unavailable", "warning");
                }
            });
        }

        document.getElementById("btn-clip-add-note")?.addEventListener("click", () => openTextModal("clipboard"));

        document.getElementById("btn-clipboard-clear-unpinned")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Clearing...", async () => {
                const res = await apiRequest("/api/clipboard/buffer/clear", "POST", { unpinned_only: true });
                if (res && res.success) {
                    showNotificationToast("Cleared unpinned clipboard entries.", "info");
                    await loadClipboardItems();
                } else {
                    showNotificationToast(res?.error || "Failed clearing clipboard entries", "error");
                }
            });
        });

        document.getElementById("clipview-search-input")?.addEventListener("input", () => loadClipboardItems());
    }

    async function loadClipboardItems() {
        const container = document.getElementById("clipview-grid-container");
        const emptyState = document.getElementById("clipview-empty-state");
        const badge = document.getElementById("clipview-count-badge");
        if (!container) return;

        const res = await apiRequest("/api/clipboard/buffer?limit=15");
        const rawItems = (res && Array.isArray(res.items)) ? res.items : (res?.data?.items || []);
        container.innerHTML = "";

        let items = rawItems;
        const q = document.getElementById("clipview-search-input")?.value?.trim().toLowerCase();
        if (q) {
            items = items.filter(it => {
                const manifestNames = Array.isArray(it.file_manifest)
                    ? it.file_manifest.map(f => `${f.name || f.file_name || ""} ${f.mime_type || ""}`).join(" ")
                    : "";
                const t = `${it.text_content || ""} ${it.text || ""} ${it.preview || ""} ${it.preview_text || ""} ${it.source_device_name || ""} ${manifestNames}`;
                return t.toLowerCase().includes(q);
            });
        }

        if (badge) badge.textContent = `${items.length} Items`;
        if (items.length === 0) {
            emptyState?.classList.remove("d-none");
            return;
        }
        emptyState?.classList.add("d-none");

        const targetElig = getClipboardTargetEligibility();

        items.forEach(it => {
            const id = it.item_id || it.id || "";
            const rawType = String(it.content_type || it.type || "text").toLowerCase();
            const type = (rawType === "image" || rawType === "file" || rawType === "file_bundle") ? rawType : "text";
            const text = it.text_content || it.text || it.preview || it.preview_text || "";
            const source = it.source_device_name || it.source_device || "Device";
            const pinned = it.is_pinned !== undefined ? Boolean(it.is_pinned) : Boolean(it.pinned);
            const manifest = Array.isArray(it.file_manifest) ? it.file_manifest : [];
            const seqLabel = (it.seq !== undefined && it.seq !== null) ? `#${it.seq}` : "";
            const sizeLabel = formatBytes(it.size_bytes);
            const isExplicitUnavailable = it.available === false || it.is_available === false || it.complete === false;
            const isIncompleteFile = (type === "file" || type === "file_bundle") && (isExplicitUnavailable || manifest.length === 0);
            const isItemActionable = Boolean(id) && !isIncompleteFile;

            const card = document.createElement("div");
            card.className = "clipboard-card";
            card.dataset.itemType = type;
            card.dataset.itemId = id;

            let typeBadgeText = "Text";
            let typeBadgeCls = "chip-cyan";
            let bodyHtml = "";

            if (type === "image") {
                typeBadgeText = "Image";
                const dimInfo = (it.width && it.height) ? `${it.width}×${it.height}` : "";
                const mimeLabel = it.mime_type || "image/png";
                bodyHtml = `
                    <div class="clipboard-image-wrap flex items-center justify-center p-2" style="background-color: var(--snow-bg-nested); border-radius: var(--snow-radius-md); overflow: hidden; min-height: 96px;">
                        <img class="clipboard-preview-img" loading="lazy" src="/api/clipboard/image/${encodeURIComponent(id)}" alt="Clipboard Image Preview" style="max-height: 150px; max-width: 100%; object-fit: contain; border-radius: var(--snow-radius-sm);" />
                    </div>
                    <div class="clipboard-meta-row">
                        <span class="mono">${escapeHtml(mimeLabel)}</span>
                        ${dimInfo ? `<span>• ${escapeHtml(dimInfo)}</span>` : ""}
                        ${sizeLabel !== "--" ? `<span>• ${escapeHtml(sizeLabel)}</span>` : ""}
                    </div>
                `;
            } else if (type === "file") {
                typeBadgeText = "File";
                typeBadgeCls = "chip-emerald";
                const f0 = manifest[0] || {};
                const fname = f0.name || f0.file_name || text || "Unnamed file";
                const fmime = f0.mime_type || it.mime_type || "application/octet-stream";
                const fsize = formatBytes(f0.size_bytes ?? it.size_bytes);
                bodyHtml = `
                    <div class="clipboard-manifest-list">
                        <div class="clipboard-file-row">
                            <div class="flex items-center gap-2 min-w-0">
                                <svg class="svg-icon svg-icon-sm text-emerald" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                                <span class="clipboard-file-name" title="${escapeHtml(fname)}">${escapeHtml(fname)}</span>
                            </div>
                            <span class="chip chip-sm ${isIncompleteFile ? "chip-rose" : "chip-neutral"}">${isIncompleteFile ? "Unavailable" : escapeHtml(fsize)}</span>
                        </div>
                        <div class="clipboard-meta-row">
                            <span class="mono">${escapeHtml(fmime)}</span>
                            ${f0.sha256 ? `<span class="chip chip-sm chip-emerald">SHA-256 Verified</span>` : ""}
                        </div>
                    </div>
                `;
            } else if (type === "file_bundle") {
                const fileCount = Number(it.file_count || manifest.length || 0);
                typeBadgeText = `Bundle • ${fileCount} Files`;
                typeBadgeCls = isIncompleteFile ? "chip-amber" : "chip-emerald";
                const rowsHtml = manifest.slice(0, 5).map(entry => {
                    const en = entry.name || entry.file_name || "file";
                    const em = entry.mime_type || "file";
                    const es = formatBytes(entry.size_bytes);
                    return `
                        <div class="clipboard-file-row">
                            <div class="flex items-center gap-2 min-w-0">
                                <svg class="svg-icon svg-icon-sm text-cyan" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path></svg>
                                <span class="clipboard-file-name" title="${escapeHtml(en)}">${escapeHtml(en)}</span>
                            </div>
                            <span class="text-muted mono" style="flex-shrink:0;">${escapeHtml(em)} • ${escapeHtml(es)}</span>
                        </div>
                    `;
                }).join("");
                bodyHtml = `
                    <div class="clipboard-manifest-list">
                        ${rowsHtml || `<span class="text-xs text-rose">Bundle manifest unavailable or incomplete</span>`}
                        <div class="clipboard-meta-row">
                            <span>Total: ${escapeHtml(sizeLabel)}</span>
                            <span>• ${fileCount} file${fileCount === 1 ? "" : "s"}</span>
                            ${isIncompleteFile ? `<span class="chip chip-sm chip-rose">Incomplete</span>` : `<span class="chip chip-sm chip-emerald">SHA-256 Verified</span>`}
                        </div>
                    </div>
                `;
            } else {
                bodyHtml = `
                    <p class="text-xs text-secondary mono" style="white-space: pre-wrap; word-break: break-word; max-height: 140px; overflow-y: auto;">${escapeHtml(text)}</p>
                    <div class="clipboard-meta-row">
                        <span class="mono">${escapeHtml(it.mime_type || "text/plain")}</span>
                        ${sizeLabel !== "--" ? `<span>• ${escapeHtml(sizeLabel)}</span>` : ""}
                    </div>
                `;
            }

            const applyLabel = (type === "file" || type === "file_bundle") ? "Apply to PC" : "Apply / Copy";

            card.innerHTML = `
                <div class="flex items-center justify-between gap-2">
                    <div class="flex items-center gap-2 min-w-0">
                        <span class="chip chip-sm ${typeBadgeCls}">${escapeHtml(typeBadgeText)}</span>
                        <span class="text-xs text-muted truncate">${seqLabel ? `${escapeHtml(seqLabel)} • ` : ""}${escapeHtml(source)} • ${formatTimestamp(it.timestamp)}</span>
                    </div>
                    <div class="flex items-center gap-1">
                        ${pinned ? `<span class="chip chip-sm chip-emerald">Pinned</span>` : ""}
                        <button class="icon-btn btn-pin-clip" style="width: 26px; height: 26px;" title="${pinned ? "Unpin" : "Pin"}">
                            <svg class="svg-icon svg-icon-sm ${pinned ? "text-cyan" : ""}" viewBox="0 0 24 24"><line x1="12" x2="12" y1="17" y2="22"></line><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"></path></svg>
                        </button>
                        <button class="icon-btn btn-del-clip text-rose" style="width: 26px; height: 26px;" title="Delete">
                            <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                        </button>
                    </div>
                </div>
                ${bodyHtml}
                <div class="flex items-center justify-between gap-2 pt-2" style="border-top: 1px solid var(--snow-border);">
                    <button class="btn btn-xs btn-primary btn-radius-md btn-copy-act" ${isItemActionable ? "" : "disabled"}>${applyLabel}</button>
                    <button class="btn btn-xs btn-tonal btn-radius-md btn-share-act" ${(isItemActionable && targetElig.eligible) ? "" : "disabled"} title="${escapeHtml(targetElig.reason)}">Send to Target</button>
                </div>
            `;
            const previewImg = card.querySelector("img.clipboard-preview-img");
            if (previewImg) {
                previewImg.addEventListener("error", () => {
                    const wrap = card.querySelector(".clipboard-image-wrap");
                    if (wrap) {
                        wrap.innerHTML = `<div class="flex items-center gap-2 text-xs text-muted" style="padding: 12px;"><svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg><span>Image preview unavailable</span></div>`;
                    }
                }, { once: true });
            }

            card.querySelector(".btn-copy-act").onclick = async (e) => {
                if (!isItemActionable) return;
                await withButtonLoading(e.currentTarget, "Applying...", async () => {
                    const applyRes = await apiRequest("/api/clipboard/buffer/apply", "POST", { item_id: id, target: "pc" });
                    if (applyRes && applyRes.success) {
                        if (type === "text" && navigator.clipboard && text) {
                            navigator.clipboard.writeText(text).catch(() => {});
                        }
                        showNotificationToast(
                            type === "file" || type === "file_bundle"
                                ? "Files committed and copied to PC clipboard!"
                                : "Applied to PC clipboard!",
                            "success"
                        );
                    } else {
                        showNotificationToast(applyRes?.error || "Failed applying item to PC", "error");
                    }
                });
            };
            card.querySelector(".btn-share-act").onclick = async (e) => {
                const elig = getClipboardTargetEligibility();
                if (!elig.eligible) {
                    showNotificationToast(elig.reason, "warning");
                    return;
                }
                await withButtonLoading(e.currentTarget, "Sending...", async () => {
                    const pushRes = await apiRequest("/api/clipboard/buffer/apply", "POST", { item_id: id, target: elig.targetId });
                    if (pushRes && pushRes.success) {
                        showNotificationToast("Delivered clipboard entry to target device!", "success");
                    } else {
                        showNotificationToast(pushRes?.error || "Failed sending clipboard entry to target", "error");
                    }
                });
            };
            card.querySelector(".btn-pin-clip").onclick = async (e) => {
                await withButtonLoading(e.currentTarget, "", async () => {
                    const action = pinned ? "/api/clipboard/buffer/unpin" : "/api/clipboard/buffer/pin";
                    const pRes = await apiRequest(action, "POST", { item_id: id });
                    if (pRes && pRes.success) {
                        await loadClipboardItems();
                    } else {
                        showNotificationToast(pRes?.error || "Unable to update pin state", "error");
                    }
                });
            };
            card.querySelector(".btn-del-clip").onclick = async (e) => {
                await withButtonLoading(e.currentTarget, "", async () => {
                    const dRes = await apiRequest("/api/clipboard/buffer/delete", "POST", { item_id: id });
                    if (dRes && dRes.success) {
                        await loadClipboardItems();
                    } else {
                        showNotificationToast(dRes?.error || "Unable to delete clipboard item", "error");
                    }
                });
            };

            container.appendChild(card);
        });
    }

    // =========================================================================
    // 10. View 5: AI & Settings
    // =========================================================================

    function initAiSettingsView() {
        document.getElementById("btn-mcp-test-local")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Testing...", async () => {
                const res = await apiRequest("/api/mcp/test-local", "POST", {});
                if (res && res.success) {
                    showNotificationToast(`All ${res.tools_count || 54} FastMCP tools verified! (${res.latency_ms?.toFixed(1) || "OK"} ms)`, "success");
                } else {
                    showNotificationToast(res?.error || "MCP self-test failed", "error");
                }
            });
        });

        const hostMappings = [
            { id: "btn-setup-claude", host: "claude" },
            { id: "btn-setup-chatgpt", host: "chatgpt" },
            { id: "btn-setup-gemini", host: "gemini" },
            { id: "btn-setup-antigravity", host: "antigravity" },
            { id: "btn-setup-cursor", host: "cursor" },
        ];
        hostMappings.forEach(({ id, host }) => {
            document.getElementById(id)?.addEventListener("click", async (e) => {
                await withButtonLoading(e.currentTarget, "Configuring...", async () => {
                    const res = await apiRequest("/api/mcp/setup", "POST", { host });
                    if (res && res.success) {
                        showNotificationToast(`Configured ${host} successfully!`, "success");
                    } else {
                        showNotificationToast(res?.error || `Failed configuring ${host}.`, "error");
                    }
                    await loadAiHostStatus();
                });
            });
        });

        // Remote AI Link Start / Stop / Copy Link / Show QR
        document.getElementById("btn-mcp-tunnel-start")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Starting...", async () => {
                const provider = document.getElementById("mcp-tunnel-provider")?.value || "render";
                const domain = document.getElementById("mcp-tunnel-permanent-input")?.value.trim() || undefined;
                const payload = { provider };
                if (domain) payload.custom_url = domain;
                const res = await apiRequest("/api/mcp/tunnel/start", "POST", payload, { timeoutMs: 15000 });
                if (res && res.success) {
                    showNotificationToast("Remote AI Link online!", "success");
                } else {
                    showNotificationToast(res?.error || "Failed starting Remote AI Link", "error");
                }
                await loadAiTunnelStatus();
            });
        });

        document.getElementById("btn-mcp-tunnel-stop")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Stopping...", async () => {
                const res = await apiRequest("/api/mcp/tunnel/stop", "POST", {});
                if (res && res.success) {
                    showNotificationToast("Remote AI Link stopped.", "info");
                } else {
                    showNotificationToast(res?.error || "Failed stopping Remote AI Link", "error");
                }
                await loadAiTunnelStatus();
            });
        });

        document.getElementById("btn-mcp-copy-url")?.addEventListener("click", () => {
            const inp = document.getElementById("mcp-tunnel-url-display");
            const activeUrl = inp ? inp.value.trim() : "";
            if (activeUrl) {
                navigator.clipboard?.writeText(activeUrl).catch(() => {});
                showNotificationToast("Copied active Remote AI Link!", "success");
            } else {
                showNotificationToast("Start Remote AI Link first.", "warning");
            }
        });

        document.getElementById("btn-mcp-tunnel-save")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Saving...", async () => {
                const provider = document.getElementById("mcp-tunnel-provider")?.value || "render";
                const domain = document.getElementById("mcp-tunnel-permanent-input")?.value.trim() || "";
                const tokenInp = document.getElementById("mcp-tunnel-token-input");
                const rawToken = tokenInp ? tokenInp.value.trim() : "";

                if (provider === "render") {
                    const hubRes = await apiRequest("/api/settings/hub", "POST", { default_hub_url: domain });
                    if (!hubRes || !hubRes.success) {
                        showNotificationToast(hubRes?.error || "Invalid Hub URL", "error");
                        return;
                    }
                }

                const payload = {
                    provider,
                    mcp_public_url: provider === "render" ? null : (domain || null),
                    default_hub_url: provider === "render" ? (domain || null) : undefined,
                };
                if (rawToken && !rawToken.includes("***") && rawToken !== "[REDACTED]") {
                    if (provider === "render") {
                        payload.relay_ticket = rawToken;
                    } else {
                        payload.mcp_cloudflare_token = rawToken;
                    }
                }
                const res = await apiRequest("/api/mcp/tunnel/config", "POST", payload);
                if (res && res.success) {
                    if (tokenInp) tokenInp.value = "";
                    showNotificationToast("Saved tunnel override configuration.", "success");
                    await loadAiTunnelStatus();
                } else {
                    showNotificationToast(res?.error || "Failed saving tunnel configuration", "error");
                }
            });
        });

        document.getElementById("btn-mcp-tunnel-token-clear")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Clearing...", async () => {
                const res = await apiRequest("/api/mcp/tunnel/config", "POST", {
                    mcp_cloudflare_token: null,
                    cloudflare_token: null,
                    relay_ticket: null,
                });
                if (res && res.success) {
                    const tokenInp = document.getElementById("mcp-tunnel-token-input");
                    if (tokenInp) tokenInp.value = "";
                    showNotificationToast("Cleared persisted tunnel token.", "info");
                    await loadAiTunnelStatus();
                } else {
                    showNotificationToast(res?.error || "Failed clearing tunnel token", "error");
                }
            });
        });

        const qrModal = document.getElementById("mcp-qr-modal");
        document.getElementById("btn-mcp-tunnel-show-qr")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Loading...", async () => {
                const res = await apiRequest("/api/mcp/tunnel/qr");
                const container = document.getElementById("mcp-qr-svg-container");
                if (res && res.success && res.active && res.svg && qrModal) {
                    if (container) {
                        container.classList.add("qr-active");
                        container.innerHTML = res.svg;
                    }
                    document.getElementById("mcp-qr-link-input").value = res.url || "";
                    qrModal.classList.remove("d-none");
                } else {
                    if (container) {
                        container.classList.remove("qr-active");
                        container.innerHTML = `<span class="text-xs text-muted text-center">No active QR</span>`;
                    }
                    showNotificationToast("Start Remote AI Link to display active QR.", "warning");
                }
            });
        });
        document.getElementById("btn-close-mcp-qr")?.addEventListener("click", () => qrModal?.classList.add("d-none"));
        document.getElementById("btn-mcp-modal-copy")?.addEventListener("click", () => {
            const inp = document.getElementById("mcp-qr-link-input");
            if (inp && inp.value) {
                navigator.clipboard?.writeText(inp.value).catch(() => {});
                showNotificationToast("Copied MCP link!", "success");
            }
        });

        // Diagnostics & Owner IPC Secret
        document.getElementById("btn-copy-diag-snow-id")?.addEventListener("click", () => {
            const val = document.getElementById("diag-my-snow-id")?.textContent?.trim() || "";
            if (val && val !== "--") {
                navigator.clipboard?.writeText(val).catch(() => {});
                showNotificationToast("Copied My SNOW ID!", "success");
            }
        });
        document.getElementById("btn-copy-diag-network-id")?.addEventListener("click", () => {
            const val = document.getElementById("diag-my-network-id")?.textContent?.trim() || "";
            if (val && val !== "--") {
                navigator.clipboard?.writeText(val).catch(() => {});
                showNotificationToast("Copied My Network ID!", "success");
            }
        });
        document.getElementById("btn-copy-diag-ai-url")?.addEventListener("click", () => {
            const val = document.getElementById("diag-remote-ai-url")?.textContent?.trim() || "";
            if (val && val !== "--") {
                navigator.clipboard?.writeText(val).catch(() => {});
                showNotificationToast("Copied Remote AI Link URL!", "success");
            }
        });

        document.getElementById("btn-ipc-secret-toggle")?.addEventListener("click", async () => {
            const inp = document.getElementById("diag-ipc-secret-value");
            const btn = document.getElementById("btn-ipc-secret-toggle");
            if (revealedIpcSecret) {
                clearRevealedIpcSecret();
                return;
            }
            if (btn) btn.disabled = true;
            try {
                const res = await apiRequest("/api/system/ipc-secret");
                if (res && res.success && res.ipc_secret) {
                    revealedIpcSecret = res.ipc_secret;
                    if (inp) {
                        inp.type = "text";
                        inp.value = revealedIpcSecret;
                    }
                    if (btn) btn.textContent = "Hide";
                } else {
                    showNotificationToast(res?.error || "Unable to fetch IPC secret", "error");
                }
            } finally {
                if (btn) btn.disabled = false;
            }
        });
        document.getElementById("btn-ipc-secret-copy")?.addEventListener("click", async () => {
            let secretToCopy = revealedIpcSecret;
            if (!secretToCopy) {
                const res = await apiRequest("/api/system/ipc-secret");
                if (res && res.success && res.ipc_secret) {
                    secretToCopy = res.ipc_secret;
                } else {
                    showNotificationToast(res?.error || "Unable to fetch IPC secret", "error");
                    return;
                }
            }
            if (navigator.clipboard && secretToCopy) {
                navigator.clipboard.writeText(secretToCopy).catch(() => {});
                showNotificationToast("Copied IPC Secret to clipboard!", "success");
            }
            secretToCopy = "";
        });
        window.addEventListener("beforeunload", clearRevealedIpcSecret);

        document.getElementById("btn-diag-update-check")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Checking...", async () => {
                const banner = document.getElementById("update-status-banner");
                const applyBtn = document.getElementById("btn-diag-update-apply");
                const res = await apiRequest("/api/system/update-check");
                if (res && res.success && (res.available || res.update_available)) {
                    pendingUpdateMeta = res;
                    if (banner) {
                        banner.textContent = `Update v${res.latest_version} available (${res.update_type})`;
                        banner.classList.remove("d-none");
                    }
                    applyBtn?.classList.remove("d-none");
                    showNotificationToast(`Update v${res.latest_version} available!`, "success");
                } else {
                    pendingUpdateMeta = null;
                    applyBtn?.classList.add("d-none");
                    if (banner) {
                        banner.textContent = res && res.success
                            ? `Current version ${res?.current_version || "7.0.0"} is up to date.`
                            : (res?.error || "Update check failed.");
                        banner.classList.remove("d-none");
                    }
                    showNotificationToast(res && res.success ? "SNOW is up to date." : (res?.error || "Update check failed"), res && res.success ? "info" : "error");
                }
            });
        });
        document.getElementById("btn-diag-update-apply")?.addEventListener("click", async (e) => {
            if (!pendingUpdateMeta) return;
            await withButtonLoading(e.currentTarget, "Applying...", async () => {
                const res = await apiRequest("/api/system/update-apply", "POST", {
                    update_type: pendingUpdateMeta.update_type,
                    url: pendingUpdateMeta.url,
                    sha256: pendingUpdateMeta.sha256,
                });
                if (res && res.success) {
                    showNotificationToast(res.message || "Update applied!", "success");
                    setTimeout(() => window.location.reload(), 1200);
                } else {
                    showNotificationToast(res?.error || "Update failed", "error");
                }
            });
        });
        document.getElementById("btn-diag-reset-override")?.addEventListener("click", async (e) => {
            await withButtonLoading(e.currentTarget, "Resetting...", async () => {
                const res = await apiRequest("/api/web-ui/reset-override", "POST", {});
                if (res && res.success) {
                    showNotificationToast("Reset to bundled Web UI. Reloading...", "info");
                    setTimeout(() => window.location.reload(), 900);
                } else {
                    showNotificationToast(res?.error || "Reset failed", "error");
                }
            });
        });
    }

    async function loadAiSettingsView() {
        await Promise.all([
            loadAiHostStatus(),
            loadAiTunnelStatus(),
            loadRelayTunnelStatus(),
            loadApprovals(),
            loadActivityTimeline(),
        ]);
    }

    async function loadAiHostStatus() {
        const res = await apiRequest("/api/mcp-gateway/status");
        if (res && res.success && res.data && Array.isArray(res.data.ai_hosts)) {
            res.data.ai_hosts.forEach(h => {
                const badge = document.getElementById(`badge-status-${h.host}`);
                if (badge) {
                    badge.textContent = h.is_configured ? "Configured" : "Ready";
                    badge.className = h.is_configured ? "chip chip-sm chip-emerald" : "chip chip-sm chip-neutral";
                }
            });
        }
    }

    async function loadAiTunnelStatus() {
        const [statusRes, cfgRes, hubRes] = await Promise.all([
            apiRequest("/api/mcp/tunnel/status"),
            apiRequest("/api/mcp/tunnel/config"),
            apiRequest("/api/settings/hub"),
        ]);
        const statusBadge = document.getElementById("mcp-tunnel-status");
        const btnStart = document.getElementById("btn-mcp-tunnel-start");
        const btnStop = document.getElementById("btn-mcp-tunnel-stop");
        const btnCopy = document.getElementById("btn-mcp-copy-url");
        const btnShowQr = document.getElementById("btn-mcp-tunnel-show-qr");
        const urlInput = document.getElementById("mcp-tunnel-url-display");
        const providerSel = document.getElementById("mcp-tunnel-provider");
        const permUrlInput = document.getElementById("mcp-tunnel-permanent-input");
        const tokenStatusBadge = document.getElementById("mcp-tunnel-token-status");
        const netBadge = document.getElementById("diag-network-key-id");

        const cfg = cfgRes?.config || {};
        const selectedProvider = cfg.provider || "render";
        if (providerSel) providerSel.value = selectedProvider;
        if (netBadge && hubRes?.network_id) netBadge.textContent = hubRes.network_id;
        const diagSnowEl = document.getElementById("diag-my-snow-id");
        const diagNetEl = document.getElementById("diag-my-network-id");
        const diagAiEl = document.getElementById("diag-remote-ai-url");
        if (diagSnowEl) diagSnowEl.textContent = canonicalSnowId || "--";
        if (diagNetEl && hubRes?.network_id) diagNetEl.textContent = hubRes.network_id;
        const activeEndpointPreview = (statusRes && statusRes.active && (statusRes.mcp_endpoint || statusRes.public_url))
            ? (statusRes.mcp_endpoint || `${statusRes.public_url.replace(/\/$/, "")}/mcp`)
            : "";
        if (diagAiEl) {
            diagAiEl.textContent = activeEndpointPreview || statusRes?.configured_render_url || hubRes?.permanent_mcp_url || "--";
        }
        if (permUrlInput && document.activeElement !== permUrlInput) {
            permUrlInput.value = cfg.default_hub_url || cfg.mcp_public_url || cfg.public_url || "";
        }
        if (tokenStatusBadge) {
            const maskedToken = cfg.mcp_cloudflare_token || cfg.cloudflare_token || cfg.relay_ticket || "";
            if (maskedToken) {
                tokenStatusBadge.textContent = `Configured: ${maskedToken}`;
                tokenStatusBadge.className = "chip chip-sm chip-emerald mono";
            } else {
                tokenStatusBadge.textContent = "No Token Saved";
                tokenStatusBadge.className = "chip chip-sm chip-neutral";
            }
        }

        const configuredRenderRoute = statusRes?.configured_render_url || hubRes?.permanent_mcp_url || "";
        const isPrefEnabled = statusRes?.enabled !== false;
        const isActive = Boolean(statusRes && statusRes.active && (statusRes.mcp_endpoint || statusRes.public_url));

        if (isActive) {
            const activeEndpoint = statusRes.mcp_endpoint || `${statusRes.public_url.replace(/\/$/, "")}/mcp`;
            if (statusBadge) {
                statusBadge.textContent = "Active • 54 Tools Ready";
                statusBadge.className = "chip chip-emerald";
            }
            if (btnStart) btnStart.disabled = true;
            if (btnStop) btnStop.disabled = false;
            if (btnCopy) btnCopy.disabled = false;
            if (btnShowQr) btnShowQr.disabled = false;
            if (urlInput) {
                urlInput.value = activeEndpoint;
                urlInput.placeholder = configuredRenderRoute || activeEndpoint;
            }
        } else if (isPrefEnabled) {
            const transientErr = statusRes?.last_error ? "Enabled • Reconnecting to Render Hub" : "Starting Remote AI Link...";
            if (statusBadge) {
                statusBadge.textContent = transientErr;
                statusBadge.className = "chip chip-amber";
            }
            if (btnStart) btnStart.disabled = false;
            if (btnStop) btnStop.disabled = false;
            if (btnCopy) btnCopy.disabled = !configuredRenderRoute;
            if (btnShowQr) btnShowQr.disabled = true;
            if (urlInput) {
                urlInput.value = "";
                urlInput.placeholder = configuredRenderRoute || "Connecting Remote AI Link to Render Hub...";
            }
        } else {
            if (statusBadge) {
                statusBadge.textContent = "Stopped";
                statusBadge.className = "chip chip-neutral";
            }
            if (btnStart) btnStart.disabled = false;
            if (btnStop) btnStop.disabled = true;
            if (btnCopy) btnCopy.disabled = true;
            if (btnShowQr) btnShowQr.disabled = true;
            if (urlInput) {
                urlInput.value = "";
                urlInput.placeholder = configuredRenderRoute || "Start Remote AI Link to activate your Render Hub endpoint";
            }
        }
    }

    async function loadApprovals() {
        const container = document.getElementById("approvals-list-container");
        const emptyState = document.getElementById("approvals-empty-state");
        const badge = document.getElementById("approvals-count-badge");
        const topbarBadge = document.getElementById("topbar-approvals-badge");

        const [capRes, oauthRes] = await Promise.all([
            apiRequest("/api/approvals"),
            apiRequest("/api/mcp/oauth/pending"),
        ]);

        const capApprovals = capRes?.requests || capRes?.approvals || capRes?.pending || [];
        const oauthPending = (oauthRes && Array.isArray(oauthRes.pending)) ? oauthRes.pending : [];
        const total = capApprovals.length + oauthPending.length;

        if (badge) badge.textContent = `${total} Pending`;
        if (topbarBadge) {
            topbarBadge.textContent = String(total);
            topbarBadge.classList.toggle("d-none", total === 0);
        }

        if (!container) return;
        container.innerHTML = "";
        if (total === 0) {
            emptyState?.classList.remove("d-none");
            return;
        }
        emptyState?.classList.add("d-none");

        // Render Capability Approvals
        capApprovals.forEach(appr => {
            const reqId = appr.request_id || appr.id;
            const remSec = appr.time_remaining_seconds !== undefined ? Math.max(0, Math.round(Number(appr.time_remaining_seconds))) : null;
            const card = document.createElement("div");
            card.className = "notif-card";
            card.innerHTML = `
                <div class="flex items-center justify-between gap-2">
                    <span class="text-xs font-bold text-primary truncate">${escapeHtml(appr.principal || appr.client_name || "AI Assistant")}</span>
                    <span class="chip chip-sm chip-amber">${escapeHtml(appr.risk_level || "CONFIRM")}${remSec !== null ? ` • ${remSec}s` : ""}</span>
                </div>
                <span class="text-xs text-secondary">${escapeHtml(appr.action || appr.tool_name || "Execute capability")} • ${escapeHtml(appr.target_device || "Device")}</span>
                <div class="flex gap-2 mt-1">
                    <button class="btn btn-xs btn-primary btn-appr-accept w-full">Approve</button>
                    <button class="btn btn-xs btn-danger btn-appr-deny w-full">Deny</button>
                </div>
            `;
            card.querySelector(".btn-appr-accept").onclick = async () => {
                await apiRequest("/api/approvals/resolve", "POST", { request_id: reqId, decision: "approve", status: "APPROVED" });
                showNotificationToast("Capability approved.", "success");
                loadApprovals();
            };
            card.querySelector(".btn-appr-deny").onclick = async () => {
                await apiRequest("/api/approvals/resolve", "POST", { request_id: reqId, decision: "deny", status: "REJECTED" });
                showNotificationToast("Capability denied.", "warning");
                loadApprovals();
            };
            container.appendChild(card);
        });

        // Render OAuth 2.1 Approvals
        oauthPending.forEach(oa => {
            const card = document.createElement("div");
            card.className = "notif-card";
            card.innerHTML = `
                <div class="flex items-center justify-between gap-2">
                    <span class="text-xs font-bold text-primary truncate">${escapeHtml(oa.client_name || oa.client_id || "Remote AI Client")}</span>
                    <span class="chip chip-sm chip-cyan">OAuth 2.1</span>
                </div>
                <span class="text-xs text-secondary">Requested scope: ${escapeHtml(oa.scope || "snow:mcp")}</span>
                <div class="flex gap-2 mt-1">
                    <button class="btn btn-xs btn-primary btn-oa-approve w-full">Approve</button>
                    <button class="btn btn-xs btn-danger btn-oa-reject w-full">Reject</button>
                </div>
            `;
            card.querySelector(".btn-oa-approve").onclick = async () => {
                await apiRequest("/api/mcp/oauth/approve", "POST", { request_id: oa.request_id });
                showNotificationToast("OAuth client authorized.", "success");
                loadApprovals();
            };
            card.querySelector(".btn-oa-reject").onclick = async () => {
                await apiRequest("/api/mcp/oauth/reject", "POST", { request_id: oa.request_id });
                showNotificationToast("OAuth client rejected.", "warning");
                loadApprovals();
            };
            container.appendChild(card);
        });
    }

    function formatActivityEvent(ev) {
        const rawAction = String(ev.capability || ev.action || ev.event_type || "activity").trim();
        const key = rawAction.toLowerCase().replace(/^snow_/, "");
        const actionLabels = {
            "desktop_status": "Checked Windows PC status and telemetry",
            "windows_system_info": "Checked Windows PC system information",
            "windows_battery": "Checked Windows battery status",
            "windows_launch_app": "Launched allowlisted Windows application",
            "desktop_app_launch": "Launched Windows application",
            "windows_file_list": "Listed authorized Windows folder",
            "desktop_file_list": "Listed authorized Windows folder",
            "windows_file_read": "Read file from authorized Windows directory",
            "windows_file_write": "Wrote file to authorized Windows directory",
            "windows_terminal_exec": "Executed Windows terminal command",
            "desktop_exec": "Executed Windows terminal command",
            "windows_clipboard_get": "Read Windows clipboard",
            "windows_clipboard_set": "Updated Windows clipboard",
            "desktop_clipboard_set": "Updated Windows clipboard",
            "clipboard_buffer_add": "Saved item to shared clipboard buffer",
            "clipboard_buffer_pin": "Pinned shared clipboard item",
            "clipboard_buffer_unpin": "Unpinned shared clipboard item",
            "clipboard_buffer_delete": "Deleted shared clipboard item",
            "clipboard_buffer_clear": "Cleared shared clipboard buffer",
            "clipboard_buffer_apply": "Applied shared clipboard item to device",
            "media_control": "Adjusted media playback or volume",
            "windows_media_control": "Adjusted Windows media playback or volume",
            "share_link": "Shared link or note to device",
            "windows_share_link": "Opened shared link on Windows",
            "youtube_play": "Opened YouTube playback or search",
            "web_open": "Opened URL in browser",
            "windows_list_windows": "Listed open Windows desktop windows",
            "windows_focus_window": "Focused a Windows desktop window",
            "system_volume_set": "Set system audio volume",
            "federation_peers": "Listed federation peers and grants",
            "android_screenshot": "Captured Android screen",
            "android_camera_capture": "Captured Android camera photo",
            "android_ring": "Triggered Find My Phone ringer",
            "android_file_list": "Listed Android device files",
            "android_file_send": "Sent file to Android device",
            "android_file_receive": "Downloaded file from Android device",
            "android_apps_launch": "Launched Android application",
            "pair_success": "Paired trusted device",
            "auth_success": "Authenticated device session",
            "auth_failed": "Blocked invalid authentication attempt",
            "system_pause": "Paused SNOW background automation",
            "system_resume": "Resumed SNOW background automation",
        };
        const title = actionLabels[key] || rawAction.replace(/[._-]+/g, " ").replace(/\b\w/g, c => c.toUpperCase());

        const rawPrincipal = String(ev.principal || ev.actor || "").toUpperCase();
        const principalLabel = rawPrincipal.includes("OWNER")
            ? "Owner"
            : (rawPrincipal.includes("AI") || rawPrincipal.includes("MCP") ? "AI Assistant" : (ev.principal || "System"));

        const rawOutcome = String(ev.outcome || ev.status || "OK").toUpperCase();
        const outcomeLabel = (rawOutcome === "OK" || rawOutcome === "SUCCESS" || rawOutcome === "ALLOWED")
            ? "Completed"
            : (rawOutcome.includes("DENIED") || rawOutcome.includes("BLOCK") || rawOutcome.includes("REJECT") ? "Blocked" : rawOutcome);

        const targetPart = ev.target_device ? ` on ${ev.target_device}` : "";
        return {
            title,
            subtitle: `${principalLabel}${targetPart} • ${outcomeLabel}`,
        };
    }

    async function loadActivityTimeline() {
        const container = document.getElementById("activity-timeline-container");
        const res = await apiRequest("/api/activity?limit=25");
        const events = res?.events || res?.records || res?.activities || [];

        if (!container) return;
        container.innerHTML = "";
        if (!res || !res.success) {
            container.innerHTML = `<span class="text-xs text-muted">Activity history unavailable while Core is offline.</span>`;
            return;
        }
        if (events.length === 0) {
            container.innerHTML = `<span class="text-xs text-muted">No recorded audit events yet.</span>`;
            return;
        }

        events.slice(0, 15).forEach(ev => {
            const fmt = formatActivityEvent(ev);
            const row = document.createElement("div");
            row.className = "flex items-center justify-between gap-2 text-xs p-2";
            row.style.background = "var(--snow-bg-elevated)";
            row.style.borderRadius = "var(--snow-radius-sm)";
            row.innerHTML = `
                <div class="flex flex-col min-w-0">
                    <span class="font-medium text-primary truncate">${escapeHtml(fmt.title)}</span>
                    <span class="text-muted truncate">${escapeHtml(fmt.subtitle)}</span>
                </div>
                <span class="text-muted mono" style="flex-shrink:0;">${escapeHtml(formatTimestamp(ev.timestamp))}</span>
            `;
            container.appendChild(row);
        });
    }

    // =========================================================================
    // 11. Command Palette (Ctrl+K)
    // =========================================================================

    function initCommandPalette() {
        const overlay = document.getElementById("command-palette-overlay");
        const trigger = document.getElementById("btn-topbar-command-palette");
        const input = document.getElementById("command-palette-input");
        const results = document.getElementById("command-palette-results");

        function openPalette() {
            if (overlay && input) {
                overlay.classList.remove("d-none");
                input.value = "";
                filterResults("");
                input.focus();
            }
        }
        function closePalette() {
            overlay?.classList.add("d-none");
        }

        if (trigger) trigger.onclick = openPalette;

        window.addEventListener("keydown", (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
                const tag = document.activeElement ? document.activeElement.tagName.toLowerCase() : "";
                if (tag !== "input" && tag !== "textarea") {
                    e.preventDefault();
                    openPalette();
                }
            } else if (e.key === "Escape") {
                closePalette();
                document.getElementById("connect-modal")?.classList.add("d-none");
                document.getElementById("poweroff-modal")?.classList.add("d-none");
                document.getElementById("media-preview-modal")?.classList.add("d-none");
                document.getElementById("notif-reply-modal")?.classList.add("d-none");
                document.getElementById("share-link-modal")?.classList.add("d-none");
                document.getElementById("mcp-qr-modal")?.classList.add("d-none");
                document.getElementById("killswitch-modal")?.classList.add("d-none");
                document.getElementById("device-island-container")?.classList.add("d-none");
            }
        });

        overlay?.addEventListener("click", (e) => {
            if (e.target === overlay) closePalette();
        });

        function filterResults(q) {
            results?.querySelectorAll(".palette-item").forEach(it => {
                it.style.display = (!q || it.textContent.toLowerCase().includes(q)) ? "flex" : "none";
            });
        }

        input?.addEventListener("input", () => filterResults(input.value.trim().toLowerCase()));

        results?.querySelectorAll(".palette-item").forEach(it => {
            it.onclick = async () => {
                const action = it.getAttribute("data-action");
                closePalette();
                if (action === "nav-overview") switchTab("overview");
                else if (action === "nav-devices") switchTab("devices");
                else if (action === "nav-files") switchTab("files");
                else if (action === "nav-clipboard") switchTab("clipboard");
                else if (action === "nav-settings") switchTab("settings");
                else if (action === "act-ring") triggerRingPhone();
                else if (action === "act-capture-phone") triggerScreenCapture();
                else if (action === "act-capture-workflow") {
                    showNotificationToast("Running capture_pc_to_phone workflow...", "info");
                    await apiRequest("/api/workflows/run", "POST", { workflow_id: "capture_pc_to_phone" });
                } else if (action === "act-sync-clip") {
                    await apiRequest("/api/clipboard/sync", "POST", { direction: "both", device_id: resolveTargetDeviceId() });
                    showNotificationToast("Clipboard synchronized.", "success");
                }
            };
        });
    }

    // =========================================================================
    // 12. Global Modals (Connect, Peer Host, Share/Add Note, Media, Reply)
    // =========================================================================

    function initModals() {
        const connectModal = document.getElementById("connect-modal");
        document.getElementById("btn-close-connect-modal")?.addEventListener("click", () => connectModal?.classList.add("d-none"));

        document.getElementById("btn-copy-modal-netid")?.addEventListener("click", () => {
            const val = document.getElementById("modal-network-id")?.textContent || canonicalSnowId;
            navigator.clipboard?.writeText(val).catch(() => {});
            showNotificationToast(`Copied ${val}`, "success");
        });

        document.getElementById("btn-modal-connect-submit")?.addEventListener("click", async () => {
            const val = document.getElementById("modal-connect-input")?.value.trim();
            if (!val) return;
            connectModal?.classList.add("d-none");
            await handleUnifiedConnectInput(val);
        });

        document.getElementById("btn-connect-peer-submit")?.addEventListener("click", async () => {
            const host = document.getElementById("connect-peer-host")?.value.trim();
            const port = parseInt(document.getElementById("connect-peer-port")?.value || "8765", 10);
            const pin = document.getElementById("connect-peer-pin")?.value.trim() || "";
            const fp = document.getElementById("connect-peer-fp")?.value.trim() || "";
            if (!host) {
                showNotificationToast("Enter peer host IP address.", "warning");
                return;
            }
            showNotificationToast(`Connecting to ${host}:${port}...`, "info");
            const res = await apiRequest("/api/devices/connect-peer", "POST", {
                host,
                port,
                pin,
                expected_fingerprint: fp,
            });
            if (res && res.success) {
                showNotificationToast("Connected to peer host!", "success");
                connectModal?.classList.add("d-none");
                refreshAllData();
            } else {
                showNotificationToast(res?.error || "Peer host connection failed", "error");
            }
        });

        document.getElementById("btn-close-media-preview")?.addEventListener("click", closeMediaPreview);
        document.getElementById("btn-lightbox-close")?.addEventListener("click", closeMediaPreview);
        document.getElementById("btn-lightbox-stop-stream")?.addEventListener("click", async () => {
            await stopRemoteScreenStream();
            document.getElementById("btn-lightbox-stop-stream")?.classList.add("d-none");
            document.getElementById("media-preview-stream-badge")?.classList.add("d-none");
        });
        document.getElementById("media-preview-modal")?.addEventListener("click", (e) => {
            if (e.target && e.target.id === "media-preview-modal") {
                closeMediaPreview();
            }
        });
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") {
                const mediaModal = document.getElementById("media-preview-modal");
                if (mediaModal && !mediaModal.classList.contains("d-none")) {
                    closeMediaPreview();
                }
            }
        });

        // Share Link / Add Clipboard Note Modal
        const shareModal = document.getElementById("share-link-modal");
        const closeShare = () => shareModal?.classList.add("d-none");
        document.getElementById("btn-close-share-modal")?.addEventListener("click", closeShare);
        document.getElementById("btn-share-modal-cancel")?.addEventListener("click", closeShare);
        document.getElementById("btn-share-modal-submit")?.addEventListener("click", async () => {
            const txt = document.getElementById("share-modal-input")?.value.trim() || "";
            if (!txt) {
                showNotificationToast("Please enter text or URL.", "warning");
                return;
            }
            closeShare();
            if (modalPurposeMode === "clipboard") {
                const res = await apiRequest("/api/clipboard/buffer/add", "POST", { text: txt, is_pinned: false });
                if (res && res.success) {
                    showNotificationToast("Added note to shared clipboard!", "success");
                    loadClipboardItems();
                    loadHomeWidgets();
                } else {
                    showNotificationToast(res?.error || "Failed adding clipboard item", "error");
                }
            } else {
                const isUrl = txt.startsWith("http://") || txt.startsWith("https://");
                const targetId = resolveTargetDeviceId();
                const res = await apiRequest("/api/share", "POST", {
                    target: targetId ? "phone" : "windows",
                    device_id: targetId,
                    url: isUrl ? txt : "",
                    text: isUrl ? "" : txt,
                });
                if (res && res.success) showNotificationToast("Shared successfully!", "success");
                else showNotificationToast(res?.error || "Failed sharing content", "error");
            }
        });
    }

    function openConnectModal() {
        const modal = document.getElementById("connect-modal");
        if (modal) {
            modal.classList.remove("d-none");
            refreshPairingState();
        }
    }

    function openTextModal(mode) {
        modalPurposeMode = mode;
        const modal = document.getElementById("share-link-modal");
        const title = document.getElementById("share-modal-title");
        const inp = document.getElementById("share-modal-input");
        if (title) title.textContent = mode === "clipboard" ? "Add Clipboard Note" : "Share Link or Note";
        if (inp) {
            inp.value = "";
            setTimeout(() => inp.focus(), 50);
        }
        modal?.classList.remove("d-none");
    }

    function closeMediaPreview() {
        const modal = document.getElementById("media-preview-modal");
        modal?.classList.add("d-none");
        if (lastFocusedBeforeLightbox && typeof lastFocusedBeforeLightbox.focus === "function") {
            try { lastFocusedBeforeLightbox.focus(); } catch (e) {}
            lastFocusedBeforeLightbox = null;
        }
    }

    function openMediaPreview(src, title = "Media Preview", isLiveStream = false) {
        const modal = document.getElementById("media-preview-modal");
        const img = document.getElementById("media-preview-img");
        const titleEl = document.getElementById("media-preview-title");
        const dlBtn = document.getElementById("btn-download-preview");
        const streamBadge = document.getElementById("media-preview-stream-badge");
        const stopStreamBtn = document.getElementById("btn-lightbox-stop-stream");
        if (modal && img) {
            if (!lastFocusedBeforeLightbox) {
                lastFocusedBeforeLightbox = document.activeElement;
            }
            img.src = src;
            if (titleEl) titleEl.textContent = title;
            if (dlBtn) dlBtn.href = src;
            streamBadge?.classList.toggle("d-none", !isLiveStream);
            stopStreamBtn?.classList.toggle("d-none", !isLiveStream);
            modal.classList.remove("d-none");
            document.getElementById("btn-close-media-preview")?.focus();
        }
    }

    // =========================================================================
    // 13. Background Polling & Non-Overwriting State Synchronization
    // =========================================================================

    async function pollStateUpdates() {
        if (isPollStateInFlight) return;
        isPollStateInFlight = true;
        const myPollSeq = ++pollStateSeq;
        try {
            // 1. System status & Core health
            const [statusRes, sysStatus, fedRes] = await Promise.all([
                apiRequest("/api/status"),
                apiRequest("/api/system/status"),
                apiRequest("/api/federation/grants"),
            ]);
            if (myPollSeq !== pollStateSeq) return;

            if (statusRes && statusRes.success) {
                lastStatusSnapshot = statusRes;
                isCoreOnline = Boolean(statusRes.daemon_online ?? true);
                if (statusRes.snow_id) canonicalSnowId = statusRes.snow_id;
                if (statusRes.device_id) localHostDeviceId = statusRes.device_id;
                if (statusRes.device_name) localHostIdentity = statusRes.device_name;
                if (statusRes.telemetry && Object.keys(statusRes.telemetry).length > 0) {
                    localHostTelemetry = statusRes.telemetry;
                }
                const coreIdEl = document.getElementById("core-canonical-id");
                if (coreIdEl) coreIdEl.textContent = canonicalSnowId;
                const diagSnowEl = document.getElementById("diag-my-snow-id");
                if (diagSnowEl && canonicalSnowId && canonicalSnowId !== "SNW-LOCAL") {
                    diagSnowEl.textContent = canonicalSnowId;
                }
            } else {
                isCoreOnline = false;
            }

            if (sysStatus && sysStatus.success) {
                isCorePaused = Boolean(sysStatus.is_paused ?? sysStatus.data?.is_paused);
            }
            updateCoreStatusBadge();

            if (fedRes && Array.isArray(fedRes.grants)) {
                federationGrants = fedRes.grants;
            }

            // 2. Registered & Connected Devices (preserve non-empty telemetry across transient misses)
            const devRes = await apiRequest("/api/devices");
            if (devRes && Array.isArray(devRes.devices)) {
                const prevById = new Map(registeredDevices.map(d => [d.device_id, d]));
                const normalized = [];
                const seenIds = new Set();
                let seenLocal = false;

                devRes.devices.forEach(rawDev => {
                    const isLocal = isLocalNode(rawDev);
                    if (isLocal) {
                        if (seenLocal) return;
                        seenLocal = true;
                    } else if (rawDev.device_id) {
                        if (seenIds.has(rawDev.device_id)) return;
                        seenIds.add(rawDev.device_id);
                    }
                    const prev = prevById.get(rawDev.device_id);
                    const hasNewTel = rawDev.telemetry && Object.keys(rawDev.telemetry).length > 0;
                    const mergedTel = hasNewTel ? rawDev.telemetry : (rawDev.is_connected && prev?.telemetry ? prev.telemetry : rawDev.telemetry);
                    normalized.push({ ...rawDev, is_local: isLocal, telemetry: mergedTel });
                });

                registeredDevices = normalized;
                const connectedRemotes = registeredDevices.filter(d => !isLocalNode(d) && d.is_connected);

                if (!hasUserSelectedDevice && !activeDeviceId) {
                    activeDeviceId = connectedRemotes.length > 0 ? connectedRemotes[0].device_id : "local";
                } else if (activeDeviceId && activeDeviceId !== "local") {
                    const stillExists = registeredDevices.some(d => d.device_id === activeDeviceId && !isLocalNode(d));
                    if (!stillExists) {
                        activeDeviceId = "local";
                    }
                }
            }

            const currentDev = getSelectedDeviceObj();
            updateTopbarCapsule(currentDev);
            renderDeviceIsland();

            if (currentTab === "overview") {
                updateHeroCard(currentDev);
                if (!isHomeWidgetsInFlight) {
                    loadHomeWidgets();
                }
            }

            // 3. Global pending approvals counter & live screen stream status
            await Promise.all([loadApprovals(), pollScreenStreamStatus()]);
        } finally {
            isPollStateInFlight = false;
        }
    }

    async function refreshAllData() {
        await pollStateUpdates();
        if (currentTab === "devices") renderDevicesView();
        else if (currentTab === "files") {
            loadFiles(currentSubpath);
            loadRemoteApps();
        } else if (currentTab === "clipboard") loadClipboardItems();
        else if (currentTab === "settings") loadAiSettingsView();
    }

    // Bootstrap entrypoint
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initSession);
    } else {
        initSession();
    }
})();
