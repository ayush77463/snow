/**
 * SNOW V3 — Vanilla Web Dashboard Client
 * 
 * Secure, zero-dependency local dashboard interface for SNOW Core.
 * Communicates with http://127.0.0.1:8769 over authenticated REST endpoints.
 */

(function () {
    "use strict";

    function escapeHtml(str) {
        if (str === null || str === undefined) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Application State
    let csrfToken = "";
    let currentTab = "overview";
    let activeDeviceId = "";
    let currentSubpath = "";
    let mediaTarget = "windows";
    let pollInterval = null;
    let selectedPairingTier = "owner";
    let activeLanIp = "127.0.0.1:8765";
    let pairingStateTimer = null;

    // DOM Elements
    const authOverlay = document.getElementById("auth-overlay");
    const authStatusText = document.getElementById("auth-status-text");
    const navItems = document.querySelectorAll(".nav-item");
    const tabPanes = document.querySelectorAll(".tab-pane");
    const activeTabTitle = document.getElementById("active-tab-title");
    const coreStatusDot = document.getElementById("core-status-dot");
    const coreStatusText = document.getElementById("core-status-text");
    const btnThemeToggle = document.getElementById("btn-theme-toggle");
    const btnGlobalRefresh = document.getElementById("btn-global-refresh");

    // =========================================================================
    // 1. Authentication & Session Initialization
    // =========================================================================

    async function initSession() {
        // Check URL hash for single-use bootstrap token (#token=...)
        const hash = window.location.hash.substring(1);
        const params = new URLSearchParams(hash);
        const bootstrapToken = params.get("token");

        // Immediately purge token from URL fragment to protect history and referrer
        if (bootstrapToken) {
            history.replaceState(null, "", window.location.pathname);
        }

        try {
            if (bootstrapToken) {
                authStatusText.textContent = "Verifying single-use bootstrap token...";
                const res = await fetch("/api/auth/session", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ token: bootstrapToken }),
                });
                const data = await res.json();
                if (data.success && data.csrf_token) {
                    csrfToken = data.csrf_token;
                    authOverlay.classList.add("hidden");
                    startDashboard();
                    return;
                }
            }

            // Attempt session check if cookie already exists
            const checkRes = await fetch("/api/status");
            if (checkRes.ok) {
                const statusData = await checkRes.json();
                if (statusData && statusData.csrf_token) {
                    csrfToken = statusData.csrf_token;
                }
                authOverlay.classList.add("hidden");
                startDashboard();
            } else {
                authStatusText.textContent = "Authentication required. Please launch with 'snow web' from terminal.";
            }
        } catch (err) {
            authStatusText.textContent = "Failed to connect to SNOW Web Server: " + err.message;
        }
    }

    // =========================================================================
    // 2. HTTP Helper with Security Headers & Safe CSRF
    // =========================================================================

    async function apiRequest(endpoint, method = "GET", body = null) {
        const headers = {};
        if (body) {
            headers["Content-Type"] = "application/json";
        }
        if (csrfToken && (method === "POST" || method === "PUT" || method === "DELETE")) {
            headers["X-CSRF-Token"] = csrfToken;
        }

        const options = {
            method: method,
            headers: headers,
        };
        if (body) {
            options.body = JSON.stringify(body);
        }

        try {
            const res = await fetch(endpoint, options);
            if (res.status === 401 || res.status === 403) {
                console.warn("API request unauthorized or CSRF invalid:", endpoint);
                // Attempt to refresh CSRF token from /api/status if session cookie is alive
                try {
                    const st = await fetch("/api/status");
                    if (st.ok) {
                        const stData = await st.json();
                        if (stData && stData.csrf_token) csrfToken = stData.csrf_token;
                    }
                } catch (_) { }
            }
            return await res.json();
        } catch (err) {
            console.error("Network request failed:", endpoint, err);
            return { success: false, error: err.message };
        }
    }

    // =========================================================================
    // 3. Navigation & Tab Switching
    // =========================================================================

    function switchTab(tabName) {
        currentTab = tabName;
        navItems.forEach(item => {
            if (item.getAttribute("data-tab") === tabName) {
                item.classList.add("active");
            } else {
                item.classList.remove("active");
            }
        });

        tabPanes.forEach(pane => {
            if (pane.id === "section-" + tabName) {
                pane.classList.add("active");
            } else {
                pane.classList.remove("active");
            }
        });

        // Update Title
        const titleMap = {
            overview: "Overview",
            devices: "Devices & Mesh",
            files: "Phone Storage (SAF)",
            notifications: "Android Notifications",
            media: "Multimedia Controls",
            share: "Share Link / Note",
            approvals: "Security Approvals",
            activity: "Activity Audit",
            federation: "Federation & Sharing",
            settings: "Settings & Diagnostics",
            clipboard: "Clipboard History",
            apps: "Android Applications",
        };
        activeTabTitle.textContent = titleMap[tabName] || "Dashboard";

        // Stop screen streaming poll when leaving overview
        if (tabName !== "overview") {
            stopScreenPoll();
        }

        // Load Tab Data
        refreshActiveTab();
    }

    function setupNavigation() {
        navItems.forEach(item => {
            item.addEventListener("click", () => {
                const tab = item.getAttribute("data-tab");
                if (tab) switchTab(tab);
            });
        });

        // Quick action buttons on Overview
        document.querySelectorAll("[data-quick]").forEach(btn => {
            btn.addEventListener("click", () => {
                const action = btn.getAttribute("data-quick");
                if (action === "qr") {
                    switchTab("devices");
                    showPairingQr();
                } else if (action === "files") {
                    switchTab("files");
                } else if (action === "notifs") {
                    switchTab("notifications");
                } else if (action === "share") {
                    switchTab("share");
                }
            });
        });

        if (btnGlobalRefresh) {
            btnGlobalRefresh.addEventListener("click", () => {
                refreshActiveTab();
            });
        }
    }

    let isRefreshing = false;

    async function refreshActiveTab() {
        if (isRefreshing) return;
        isRefreshing = true;

        const originalText = btnGlobalRefresh ? btnGlobalRefresh.innerHTML : "";
        if (btnGlobalRefresh) {
            btnGlobalRefresh.disabled = true;
            btnGlobalRefresh.innerHTML = "⏳ Refreshing...";
        }

        try {
            await Promise.allSettled([
                loadSystemStatus(),
                loadApprovalsCount()
            ]);

            const savedDeviceId = activeDeviceId;

            if (currentTab === "overview") {
                await loadOverview();
            } else if (currentTab === "devices") {
                await loadDevices();
            } else if (currentTab === "files") {
                await loadSafFiles();
            } else if (currentTab === "notifications") {
                await loadNotifications();
            } else if (currentTab === "approvals") {
                await loadApprovalsList();
            } else if (currentTab === "activity") {
                await loadActivityHistory();
            } else if (currentTab === "clipboard") {
                await loadClipboardBuffer();
            } else if (currentTab === "apps") {
                await loadAndroidApps();
            } else if (currentTab === "federation") {
                await loadFederationData();
            } else if (currentTab === "settings") {
                await Promise.allSettled([
                    loadRelayStatus(),
                    loadMcpGatewayStatus(),
                    loadNetworkIdentity()
                ]);
            }

            if (savedDeviceId && lastKnownPeerDevices.some(d => d.device_id === savedDeviceId)) {
                activeDeviceId = savedDeviceId;
                const globalSelect = document.getElementById("global-target-select");
                if (globalSelect) globalSelect.value = savedDeviceId;
                const fileDevSelect = document.getElementById("files-device-select");
                if (fileDevSelect) fileDevSelect.value = savedDeviceId;
            }
        } catch (err) {
            console.error("Dashboard refresh error:", err);
            showNotificationToast("Refresh encountered error: " + (err.message || "Unknown error"), "error");
        } finally {
            if (btnGlobalRefresh) {
                btnGlobalRefresh.disabled = false;
                btnGlobalRefresh.innerHTML = originalText || "🔄 Refresh";
            }
            isRefreshing = false;
        }
    }

    // =========================================================================
    // 4. Data Loaders & View Renderers
    // =========================================================================

    async function loadSystemStatus() {
        const data = await apiRequest("/api/status");
        if (data && data.success) {
            coreStatusDot.className = "status-dot " + (data.daemon_online ? "dot-online" : "dot-offline");
            coreStatusText.textContent = data.daemon_online ? "Core Online" : "Core Offline";
            const sysStat = document.getElementById("stat-sys-status");
            const sysDet = document.getElementById("stat-sys-details");
            if (sysStat) sysStat.textContent = data.daemon_online ? "Healthy" : "Offline";
            if (sysDet) sysDet.textContent = data.daemon_online ? "IPC Loopback Active" : "Run 'snow daemon start'";
            if (data.csrf_token && !csrfToken) {
                csrfToken = data.csrf_token;
            }
            if (Array.isArray(data.lan_ips) && data.lan_ips.length > 0) {
                const port = data.wss_port || 8765;
                activeLanIp = `${data.lan_ips[0]}:${port}`;
                const ovLan = document.getElementById("overview-lan-ip");
                const devLan = document.getElementById("devices-lan-ip");
                if (ovLan) ovLan.textContent = activeLanIp;
                if (devLan) devLan.textContent = activeLanIp;
            }
        }
    }

    let approvalsCountdownTimer = null;

    async function loadApprovalsCount() {
        const data = await apiRequest("/api/approvals");
        const approvals = (data && Array.isArray(data.requests)) ? data.requests : ((data && Array.isArray(data.approvals)) ? data.approvals : ((data && data.data && Array.isArray(data.data.requests)) ? data.data.requests : []));
        const count = (data && data.success) ? approvals.length : 0;
        const badge = document.getElementById("badge-approvals");
        const statApprovals = document.getElementById("stat-pending-approvals");
        if (badge) {
            if (count > 0) {
                badge.textContent = count.toString();
                badge.style.display = "";
            } else {
                badge.style.display = "none";
            }
        }
        if (statApprovals) statApprovals.textContent = count.toString();

        const banner = document.getElementById("pending-approval-banner");
        const bannerText = document.getElementById("pending-approval-banner-text");
        if (banner) {
            if (count > 0) {
                banner.classList.remove("d-none");
                if (bannerText) {
                    bannerText.textContent = `${count} pending AI request${count > 1 ? "s" : ""} require${count === 1 ? "s" : ""} your approval`;
                }
            } else {
                banner.classList.add("d-none");
            }
        }
    }

    function isLocalNode(dev) {
        return dev.transport === "local" || dev.is_local === true || dev.platform === "windows" || dev.device_id === "local" || dev.device_id === "desktop-core";
    }

    function formatTransportLabel(tr) {
        if (!tr) return "Unknown";
        if (tr === "wifi_lan" || tr === "Wi-Fi LAN") return "🟢 Wi-Fi LAN";
        if (tr === "usb_adb" || tr === "USB ADB") return "🔌 USB ADB";
        if (tr === "loopback" || tr === "Loopback") return "🔁 Loopback";
        if (tr === "peer_link" || tr === "mesh_peer" || tr === "Peer Link") return "🔗 Peer Link";
        if (tr === "remote_relay" || tr === "Remote Relay" || tr === "relay") return "🌐 Remote Relay";
        return tr;
    }

    function getTransportChipClass(tr) {
        if (!tr) return "chip-neutral";
        if (tr === "wifi_lan" || tr === "Wi-Fi LAN") return "chip-wifi";
        if (tr === "usb_adb" || tr === "USB ADB") return "chip-usb";
        if (tr === "loopback" || tr === "Loopback") return "chip-loopback";
        if (tr === "peer_link" || tr === "mesh_peer" || tr === "Peer Link") return "chip-peer";
        if (tr === "remote_relay" || tr === "Remote Relay" || tr === "relay") return "chip-relay";
        return "chip-neutral";
    }

    let lastKnownPeerDevices = [];

    function populateGlobalTargetSelector(peerDevices) {
        lastKnownPeerDevices = Array.isArray(peerDevices) ? peerDevices : [];
        const peers = lastKnownPeerDevices.filter(d => !isLocalNode(d));
        const globalSelect = document.getElementById("global-target-select");
        const transportChip = document.getElementById("global-target-transport-chip");
        const fileDevSelect = document.getElementById("files-device-select");

        // Maintain selection if the device is still known
        if (activeDeviceId && !peers.some(d => d.device_id === activeDeviceId)) {
            // Do not silently switch to another device if explicit target disconnected
        } else if (!activeDeviceId && peers.length > 0) {
            const firstConnected = peers.find(d => d.is_connected);
            if (firstConnected) {
                activeDeviceId = firstConnected.device_id;
            } else if (peers.length > 0) {
                activeDeviceId = peers[0].device_id;
            }
        }

        if (globalSelect) {
            globalSelect.innerHTML = "";
            if (peers.length === 0) {
                const opt = document.createElement("option");
                opt.value = "";
                opt.textContent = "No Connected Peer";
                globalSelect.appendChild(opt);
            } else {
                peers.forEach(dev => {
                    const opt = document.createElement("option");
                    opt.value = dev.device_id;
                    const statusText = dev.is_connected ? formatTransportLabel(dev.transport) : "Offline";
                    opt.textContent = `${dev.device_name || dev.device_id} (${statusText})`;
                    if (dev.device_id === activeDeviceId) {
                        opt.selected = true;
                    }
                    globalSelect.appendChild(opt);
                });
            }
            if (activeDeviceId) {
                globalSelect.value = activeDeviceId;
            }
        }

        if (fileDevSelect) {
            fileDevSelect.innerHTML = "";
            const placeholder = document.createElement("option");
            placeholder.value = "";
            placeholder.textContent = "Select target Android device...";
            fileDevSelect.appendChild(placeholder);
            peers.forEach(dev => {
                const opt = document.createElement("option");
                opt.value = dev.device_id;
                const statusText = dev.is_connected ? formatTransportLabel(dev.transport) : "Offline";
                opt.textContent = `${dev.device_name || dev.device_id} (${statusText})`;
                if (dev.device_id === activeDeviceId) {
                    opt.selected = true;
                }
                fileDevSelect.appendChild(opt);
            });
            if (activeDeviceId) {
                fileDevSelect.value = activeDeviceId;
            }
        }

        // Update transport chip for the active device
        if (transportChip) {
            const activeDev = peers.find(d => d.device_id === activeDeviceId);
            if (activeDev && activeDev.is_connected) {
                transportChip.textContent = formatTransportLabel(activeDev.transport);
                transportChip.className = "chip " + getTransportChipClass(activeDev.transport);
            } else {
                transportChip.textContent = "Offline";
                transportChip.className = "chip chip-neutral";
            }
        }
    }

    // 4A. Overview
    async function loadOverview() {
        const devRes = await apiRequest("/api/devices");
        const devCountEl = document.getElementById("stat-connected-devices");
        const transportChip = document.getElementById("stat-transport-chip");

        let activeCount = 0;
        let primaryTransport = "No Active Session";
        let chipClass = "chip-neutral";

        const devList = (devRes && Array.isArray(devRes.devices)) ? devRes.devices : ((devRes && devRes.data && Array.isArray(devRes.data.devices)) ? devRes.data.devices : []);
        if (devRes && devRes.success && devList.length > 0) {
            const peerDevices = devList.filter(d => !isLocalNode(d));
            populateGlobalTargetSelector(peerDevices);
            const connected = peerDevices.filter(d => d.is_connected);
            activeCount = connected.length;
            if (activeCount > 0) {
                const tr = connected[0].transport || "unknown";
                primaryTransport = formatTransportLabel(tr);
                chipClass = getTransportChipClass(tr);
            }
        } else {
            populateGlobalTargetSelector([]);
        }

        if (devCountEl) devCountEl.textContent = activeCount.toString();
        if (transportChip) {
            transportChip.textContent = primaryTransport;
            transportChip.className = "chip " + chipClass;
        }

        // Recent Activity for Overview
        const actRes = await apiRequest("/api/activity?limit=5");
        const feed = document.getElementById("overview-activity-list");
        if (feed) {
            feed.innerHTML = "";
            const events = (actRes && Array.isArray(actRes.events)) ? actRes.events : ((actRes && Array.isArray(actRes.records)) ? actRes.records : ((actRes && actRes.data && Array.isArray(actRes.data.events)) ? actRes.data.events : []));
            if (actRes && actRes.success && events.length > 0) {
                events.forEach(rec => {
                    const item = document.createElement("div");
                    item.className = "activity-item";

                    const timeSpan = document.createElement("span");
                    timeSpan.className = "activity-time";
                    timeSpan.textContent = formatTimestamp(rec.timestamp);

                    const descSpan = document.createElement("span");
                    descSpan.className = "activity-desc";
                    const cap = rec.capability || rec.event_type || "OPERATION";
                    const target = rec.target_device || rec.device_id || "Core";
                    const outcome = rec.outcome || rec.summary || (rec.details ? JSON.stringify(rec.details) : "completed");
                    descSpan.textContent = `[${rec.principal || 'SYSTEM'}] ${cap} (${target}) → ${outcome}`;

                    item.appendChild(timeSpan);
                    item.appendChild(descSpan);
                    feed.appendChild(item);
                });
            } else {
                const empty = document.createElement("div");
                empty.className = "empty-state";
                empty.textContent = "No recent operations recorded.";
                feed.appendChild(empty);
            }
        }

        // Live screen sharing & camera photo polling on overview tab
        startScreenPoll();
        loadLatestCameraPhoto();
        loadClipboardBuffer();
    }

    // =========================================================================
    // 4A.1 Live Screen Sharing & Camera Delivery (Phase 26A)
    // =========================================================================

    let screenPollTimer = null;
    let screenPollActive = false;

    async function pollScreenFrame() {
        if (!screenPollActive) return;

        const statusRes = await apiRequest("/api/screen/status");
        const statusBadge = document.getElementById("screen-status-badge");
        const idleMsg = document.getElementById("screen-idle-message");
        const frameImg = document.getElementById("screen-frame-img");
        const statsBar = document.getElementById("screen-stats-bar");
        const stopBtn = document.getElementById("btn-stop-screen-share");

        if (statusRes && statusRes.state === "STREAMING") {
            if (idleMsg) idleMsg.classList.add("d-none");
            if (frameImg) frameImg.classList.remove("d-none");
            if (statsBar) statsBar.classList.remove("d-none");
            if (stopBtn) stopBtn.classList.remove("d-none");
            if (statusBadge) {
                statusBadge.textContent = "STREAMING";
                statusBadge.className = "badge badge-success";
            }

            try {
                const frameRes = await fetch("/api/screen/frame");
                if (frameRes.ok && frameRes.status === 200) {
                    const blob = await frameRes.blob();
                    if (blob.size > 0) {
                        const oldSrc = frameImg.src;
                        frameImg.src = URL.createObjectURL(blob);
                        if (oldSrc && oldSrc.startsWith("blob:")) URL.revokeObjectURL(oldSrc);

                        const fpsEl = document.getElementById("screen-stat-fps");
                        const resEl = document.getElementById("screen-stat-resolution");
                        const bwEl = document.getElementById("screen-stat-bandwidth");
                        const lastEl = document.getElementById("screen-stat-last-update");

                        if (fpsEl && statusRes.fps) fpsEl.textContent = `FPS: ${Number(statusRes.fps).toFixed(1)}`;
                        if (resEl && statusRes.frame_width && statusRes.frame_height) {
                            resEl.textContent = `${statusRes.frame_width}×${statusRes.frame_height}`;
                        }
                        if (bwEl) bwEl.textContent = `${(blob.size / 1024).toFixed(1)} KiB/frame`;
                        if (lastEl) lastEl.textContent = `Last: ${new Date().toLocaleTimeString()}`;
                    }
                }
            } catch (e) {
                console.debug("Screen frame fetch error:", e);
            }
        } else {
            if (idleMsg) idleMsg.classList.remove("d-none");
            if (frameImg) frameImg.classList.add("d-none");
            if (statsBar) statsBar.classList.add("d-none");
            if (stopBtn) stopBtn.classList.add("d-none");
            if (statusBadge) {
                const state = (statusRes && statusRes.state) || "IDLE";
                statusBadge.textContent = state;
                statusBadge.className = "badge " + (state === "STOPPED" ? "badge-muted" : state === "REVOKED" ? "badge-danger" : "badge-muted");
            }
        }

        if (screenPollActive) {
            const delay = document.hidden ? 2500 : 500;
            screenPollTimer = setTimeout(pollScreenFrame, delay);
        }
    }

    function startScreenPoll() {
        if (screenPollActive) return;
        screenPollActive = true;
        pollScreenFrame();
    }

    function stopScreenPoll() {
        screenPollActive = false;
        if (screenPollTimer) {
            clearTimeout(screenPollTimer);
            screenPollTimer = null;
        }
    }

    async function loadLatestCameraPhoto() {
        const container = document.getElementById("camera-preview-container");
        const idleMsg = document.getElementById("camera-idle-message");
        const img = document.getElementById("camera-latest-img");
        const info = document.getElementById("camera-delivery-info");

        try {
            const res = await fetch("/api/camera/latest");
            if (res.ok && res.status === 200) {
                const blob = await res.blob();
                if (blob.size > 0) {
                    if (container) container.classList.remove("d-none");
                    if (idleMsg) idleMsg.classList.add("d-none");
                    if (img) {
                        const oldSrc = img.src;
                        img.src = URL.createObjectURL(blob);
                        if (oldSrc && oldSrc.startsWith("blob:")) URL.revokeObjectURL(oldSrc);
                    }
                    const filename = res.headers.get("X-Snow-Filename") || "Camera photo";
                    if (info) info.textContent = `Delivered: ${filename} (${(blob.size / 1024).toFixed(1)} KiB) at ${new Date().toLocaleTimeString()}`;
                }
            }
        } catch (e) {
            console.debug("Camera photo fetch error:", e);
        }
    }

    // =========================================================================
    // 4A.2 Shared Clipboard Ring Buffer & Remote Apps (Phase 26B)
    // =========================================================================

    async function loadClipboardBuffer() {
        const overviewTimeline = document.getElementById("hub-overview-timeline");
        const fullTimeline = document.getElementById("clipboard-full-timeline");
        const countBadge = document.getElementById("hub-buffer-count-badge");
        const detailCount = document.getElementById("clipboard-detail-count");

        const res = await apiRequest("/api/clipboard/buffer");
        const items = (res && res.data && Array.isArray(res.data.items)) ? res.data.items :
            (res && Array.isArray(res.items)) ? res.items : [];
        const count = items.length;
        const pinnedCount = items.filter(it => it.is_pinned).length;

        if (countBadge) countBadge.textContent = `${count} item${count === 1 ? '' : 's'}`;
        if (detailCount) detailCount.textContent = `${count} / 10 items (${pinnedCount} pinned)`;

        const renderTimeline = (container, isOverview = false) => {
            if (!container) return;
            container.innerHTML = "";
            if (items.length === 0) {
                const empty = document.createElement("div");
                empty.className = "empty-state";
                empty.textContent = "No items in clipboard buffer yet.";
                container.appendChild(empty);
                return;
            }

            const displayItems = isOverview ? items.slice(0, 5) : items;
            displayItems.forEach(item => {
                const card = document.createElement("div");
                card.className = "clipboard-card" + (item.is_pinned ? " pinned" : "");

                // Header
                const hdr = document.createElement("div");
                hdr.className = "clip-header";

                const metaLeft = document.createElement("div");
                metaLeft.className = "clip-meta-left";
                const chip = document.createElement("span");
                chip.className = "clip-device-chip";
                const dev = (item.source_device || "pc").toLowerCase();
                chip.textContent = (dev === "pc" || dev === "windows" || dev === "desktop") ? "💻 PC" : "📱 Phone";
                metaLeft.appendChild(chip);

                const typeSpan = document.createElement("span");
                typeSpan.className = "text-muted";
                typeSpan.textContent = item.type === "image" ? "📷 Image" : "📝 Text";
                metaLeft.appendChild(typeSpan);

                const metaRight = document.createElement("div");
                metaRight.className = "clip-meta-right";
                if (item.is_pinned) {
                    const pin = document.createElement("span");
                    pin.className = "clip-pin-badge";
                    pin.textContent = "📌 Pinned";
                    metaRight.appendChild(pin);
                }
                const timeSpan = document.createElement("span");
                timeSpan.textContent = formatTimestamp(item.timestamp);
                metaRight.appendChild(timeSpan);

                hdr.appendChild(metaLeft);
                hdr.appendChild(metaRight);
                card.appendChild(hdr);

                // Body
                const body = document.createElement("div");
                body.className = "clip-body";
                if (item.type === "image") {
                    const img = document.createElement("img");
                    img.className = "clip-thumb";
                    img.src = `/api/clipboard/image/${item.item_id}`;
                    img.alt = "Clipboard Image";
                    body.appendChild(img);
                } else {
                    const txt = document.createElement("div");
                    txt.className = "clip-text";
                    txt.textContent = item.preview_text || item.text_content || "";
                    body.appendChild(txt);
                }
                card.appendChild(body);

                // Footer & Actions
                const footer = document.createElement("div");
                footer.className = "clip-footer";

                const info = document.createElement("div");
                info.className = "clip-info";
                const sz = item.size_bytes || 0;
                info.textContent = sz > 1024 ? `${(sz / 1024).toFixed(1)} KiB` : `${sz} B`;
                footer.appendChild(info);

                const actions = document.createElement("div");
                actions.className = "clip-actions";

                const btnApplyPc = document.createElement("button");
                btnApplyPc.className = "btn-xs btn-primary";
                btnApplyPc.textContent = "⚡ Apply PC";
                btnApplyPc.title = "Copy to Windows clipboard";
                btnApplyPc.addEventListener("click", async () => {
                    btnApplyPc.disabled = true;
                    btnApplyPc.textContent = "Applying...";
                    await apiRequest("/api/clipboard/buffer/apply", "POST", { item_id: item.item_id, target: "pc" });
                    btnApplyPc.textContent = "Applied!";
                    setTimeout(() => { btnApplyPc.textContent = "⚡ Apply PC"; btnApplyPc.disabled = false; }, 1500);
                });
                actions.appendChild(btnApplyPc);

                const btnSendPhone = document.createElement("button");
                btnSendPhone.className = "btn-xs btn-secondary";
                btnSendPhone.textContent = "📲 Send Phone";
                btnSendPhone.title = "Push to connected Android phone";
                btnSendPhone.addEventListener("click", async () => {
                    btnSendPhone.disabled = true;
                    btnSendPhone.textContent = "Sending...";
                    await apiRequest("/api/clipboard/buffer/apply", "POST", { item_id: item.item_id, target: "android" });
                    btnSendPhone.textContent = "Sent!";
                    setTimeout(() => { btnSendPhone.textContent = "📲 Send Phone"; btnSendPhone.disabled = false; }, 1500);
                });
                actions.appendChild(btnSendPhone);

                const btnPin = document.createElement("button");
                btnPin.className = "btn-xs btn-secondary";
                btnPin.textContent = item.is_pinned ? "Unpin" : "📌 Pin";
                btnPin.addEventListener("click", async () => {
                    const ep = item.is_pinned ? "/api/clipboard/buffer/unpin" : "/api/clipboard/buffer/pin";
                    await apiRequest(ep, "POST", { item_id: item.item_id });
                    loadClipboardBuffer();
                });
                actions.appendChild(btnPin);

                const btnDel = document.createElement("button");
                btnDel.className = "btn-xs btn-danger";
                btnDel.textContent = "✕";
                btnDel.title = "Delete item";
                btnDel.addEventListener("click", async () => {
                    await apiRequest("/api/clipboard/buffer/delete", "POST", { item_id: item.item_id });
                    loadClipboardBuffer();
                });
                actions.appendChild(btnDel);

                footer.appendChild(actions);
                card.appendChild(footer);

                container.appendChild(card);
            });
        };

        renderTimeline(overviewTimeline, true);
        renderTimeline(fullTimeline, false);
    }

    async function loadAndroidApps() {
        const container = document.getElementById("android-apps-container");
        const statusEl = document.getElementById("android-app-status");
        if (!container) return;

        // Resolve target Android device
        const devData = await apiRequest("/api/devices");
        const devList = (devData && Array.isArray(devData.devices)) ? devData.devices :
            ((devData && devData.data && Array.isArray(devData.data.devices)) ? devData.data.devices : []);
        const androidDevs = devList.filter(d => !isLocalNode(d) && d.is_connected && (d.platform === "android" || !d.platform));

        let targetId = activeDeviceId;
        if (targetId) {
            const devExists = androidDevs.find(d => d.device_id === targetId);
            if (!devExists) {
                targetId = "";
            }
        }

        if (!targetId) {
            if (androidDevs.length === 1) {
                targetId = androidDevs[0].device_id;
                activeDeviceId = targetId;
            } else if (androidDevs.length === 0) {
                container.innerHTML = '<div class="empty-state">No connected Android device found. Connect or pair an Android device first.</div>';
                return;
            } else {
                container.innerHTML = '<div class="empty-state">Multiple Android devices connected. Please select an active target device.</div>';
                return;
            }
        }

        container.innerHTML = '<div class="empty-state"><div class="spinner"></div> Fetching installed Android apps...</div>';
        const res = await apiRequest(`/api/apps/android?device_id=${encodeURIComponent(targetId)}`);
        container.innerHTML = "";

        const apps = (res && res.data && Array.isArray(res.data.apps)) ? res.data.apps :
            (res && Array.isArray(res.apps)) ? res.apps : [];

        if (apps.length === 0) {
            const empty = document.createElement("div");
            empty.className = "empty-state";
            empty.textContent = res && res.error ? `Failed to load apps: ${res.error}` : "No applications found or Android device is not connected.";
            container.appendChild(empty);
            return;
        }

        const filterInput = document.getElementById("android-app-filter");
        const renderFiltered = (filterText = "") => {
            container.innerHTML = "";
            const lowerFilter = filterText.toLowerCase();
            const filtered = apps.filter(app => {
                const name = (app.label || app.app_name || app.name || "").toLowerCase();
                const pkg = (app.package_name || app.package || "").toLowerCase();
                return name.includes(lowerFilter) || pkg.includes(lowerFilter);
            });

            if (filtered.length === 0) {
                const empty = document.createElement("div");
                empty.className = "empty-state";
                empty.textContent = "No matching apps.";
                container.appendChild(empty);
                return;
            }

            filtered.forEach(app => {
                const row = document.createElement("div");
                row.className = "app-row";

                const info = document.createElement("div");
                info.className = "app-info";
                const nameSpan = document.createElement("span");
                nameSpan.className = "app-name";
                nameSpan.textContent = app.label || app.app_name || app.name || app.package_name || "Unknown App";
                const pkgSpan = document.createElement("span");
                pkgSpan.className = "app-pkg";
                pkgSpan.textContent = app.package_name || app.package || "";
                info.appendChild(nameSpan);
                info.appendChild(pkgSpan);
                row.appendChild(info);

                const btnLaunch = document.createElement("button");
                btnLaunch.className = "btn-xs btn-primary";
                btnLaunch.textContent = "🚀 Launch";
                btnLaunch.addEventListener("click", async () => {
                    btnLaunch.disabled = true;
                    btnLaunch.textContent = "Launching...";
                    const lRes = await apiRequest("/api/apps/android/launch", "POST", {
                        package_name: app.package_name || app.package,
                        device_id: targetId
                    });
                    btnLaunch.disabled = false;
                    btnLaunch.textContent = "🚀 Launch";
                    if (statusEl) {
                        if (lRes && lRes.success) {
                            statusEl.textContent = `Launched ${app.app_name || app.package_name} successfully.`;
                            statusEl.className = "text-sm text-success mt-2";
                        } else {
                            statusEl.textContent = `Launch failed: ${lRes ? (lRes.error || lRes.status) : 'Unknown error'}`;
                            statusEl.className = "text-sm text-danger mt-2";
                        }
                    }
                });
                row.appendChild(btnLaunch);

                container.appendChild(row);
            });
        };

        if (filterInput) {
            filterInput.oninput = () => renderFiltered(filterInput.value);
        }
        renderFiltered();
    }

    // 4B. Devices
    async function loadDevices() {
        const data = await apiRequest("/api/devices");
        const container = document.getElementById("devices-list");
        const hostContainer = document.getElementById("local-host-card-container");
        const fileDevSelect = document.getElementById("files-device-select");
        if (!container) return;

        container.innerHTML = "";
        if (hostContainer) hostContainer.innerHTML = "";
        if (fileDevSelect) {
            fileDevSelect.innerHTML = '<option value="">Select target Android device...</option>';
        }

        const isCoreOnline = Boolean(data && data.success);
        const devices = (data && Array.isArray(data.devices)) ? data.devices : ((data && data.data && Array.isArray(data.data.devices)) ? data.data.devices : []);

        // Partition into local desktop host node vs peer mobile devices
        const localNodes = devices.filter(isLocalNode);
        const peerDevices = devices.filter(d => !isLocalNode(d));
        populateGlobalTargetSelector(peerDevices);

        // 1. Render Local Host Node
        const hostCard = document.createElement("div");
        hostCard.className = "device-card host-node-card";
        const hostHeader = document.createElement("div");
        hostHeader.className = "device-card-header";
        const hostName = document.createElement("h3");
        hostName.textContent = (localNodes[0] && localNodes[0].device_name) ? `💻 ${localNodes[0].device_name} (Host Core)` : "💻 Windows Laptop (Desktop Core)";
        const hostBadge = document.createElement("span");
        if (isCoreOnline) {
            hostBadge.className = "badge badge-success";
            hostBadge.textContent = "Core Active";
        } else {
            hostBadge.className = "badge badge-muted";
            hostBadge.textContent = "Core Offline";
        }
        hostHeader.appendChild(hostName);
        hostHeader.appendChild(hostBadge);

        const hostBody = document.createElement("div");
        hostBody.className = "device-card-body";
        hostBody.appendChild(createDetailRow("Device ID:", (localNodes[0] && localNodes[0].device_id) || "desktop-core"));
        hostBody.appendChild(createDetailRow("Platform:", "Windows 11 (Headless Core)"));
        hostBody.appendChild(createDetailRow("Trust Tier:", "Owner (Protected Host)"));

        const hostTrRow = document.createElement("div");
        hostTrRow.className = "device-detail-row";
        const hostTrLabel = document.createElement("span");
        hostTrLabel.className = "label";
        hostTrLabel.textContent = "Transport:";
        const hostTrChip = document.createElement("span");
        if (isCoreOnline) {
            hostTrChip.className = "chip chip-loopback";
            hostTrChip.textContent = "🔁 Localhost Loopback IPC (8767)";
        } else {
            hostTrChip.className = "chip chip-neutral";
            hostTrChip.textContent = "⚪ IPC Offline (Run 'snow daemon start')";
        }
        hostTrRow.appendChild(hostTrLabel);
        hostTrRow.appendChild(hostTrChip);
        hostBody.appendChild(hostTrRow);

        hostCard.appendChild(hostHeader);
        hostCard.appendChild(hostBody);

        if (hostContainer) {
            hostContainer.appendChild(hostCard);
        } else {
            container.appendChild(hostCard);
        }

        // 2. Render Peer Devices or Offline Diagnostics
        if (!isCoreOnline) {
            const empty = document.createElement("div");
            empty.className = "empty-state";
            const errMsg = (data && data.error) ? data.error : "SNOW Desktop Core is offline or unreachable.";
            empty.innerHTML = `⚠️ <strong>Desktop Core Offline</strong><br><small class="text-muted">${escapeHtml(errMsg)}<br>Please launch the core daemon in terminal with <code>python -m snow daemon start</code> or <code>snow</code>, then refresh.</small>`;
            container.appendChild(empty);
            return;
        }

        if (peerDevices.length === 0) {
            const empty = document.createElement("div");
            empty.className = "empty-state";
            empty.textContent = "No paired or connected mobile devices found. Click 'Generate Pairing QR' to onboard your phone.";
            container.appendChild(empty);
            return;
        }

        peerDevices.forEach(dev => {
            const card = document.createElement("div");
            card.className = "device-card";

            const header = document.createElement("div");
            header.className = "device-card-header";

            const name = document.createElement("h3");
            name.textContent = `📱 ${dev.device_name || dev.device_id}`;

            const badge = document.createElement("span");
            if (dev.is_connected) {
                badge.className = "badge badge-success";
                badge.textContent = "Connected";
            } else {
                badge.className = "badge badge-muted";
                badge.textContent = "Offline";
            }

            header.appendChild(name);
            header.appendChild(badge);

            const body = document.createElement("div");
            body.className = "device-card-body";

            // Device ID
            body.appendChild(createDetailRow("Device ID:", dev.device_id));

            // Trust Tier
            body.appendChild(createDetailRow("Trust Tier:", dev.trust_tier || "tier1_standard"));

            // Transport Chip
            const trRow = document.createElement("div");
            trRow.className = "device-detail-row";
            const trLabel = document.createElement("span");
            trLabel.className = "label";
            trLabel.textContent = "Transport:";
            const trChip = document.createElement("span");

            const tr = dev.transport || "unknown";
            const isRelayedOnline = dev.reachability_state === "ONLINE_RELAYED" || (dev.is_connected && (tr === "remote_relay" || tr === "relay"));
            if (isRelayedOnline) {
                trChip.className = "chip chip-relay";
                trChip.textContent = "🌐 Remote Relay";
            } else if (!dev.is_connected) {
                trChip.className = "chip chip-neutral";
                trChip.textContent = "Disconnected";
            } else if (tr === "wifi_lan") {
                trChip.className = "chip chip-wifi";
                trChip.textContent = "🟢 Wi-Fi LAN";
            } else if (tr === "usb_adb") {
                trChip.className = "chip chip-usb";
                trChip.textContent = "🔌 USB Cable (ADB)";
            } else if (tr === "loopback") {
                trChip.className = "chip chip-loopback";
                trChip.textContent = "🔁 Loopback";
            } else {
                trChip.className = "chip chip-neutral";
                trChip.textContent = "⚪ " + tr;
            }
            trRow.appendChild(trLabel);
            trRow.appendChild(trChip);
            body.appendChild(trRow);

            // Live Phone Telemetry (Stage 2A)
            if (dev.is_connected && dev.telemetry) {
                const tel = dev.telemetry;
                if (tel.level !== undefined && tel.level !== null) {
                    const chargingStr = tel.charging ? ` ⚡ Charging (${tel.power_source || 'Power'})` : "";
                    const tempStr = tel.temperature_celsius ? ` · ${tel.temperature_celsius}°C` : "";
                    body.appendChild(createDetailRow("Battery:", `${tel.level}%${chargingStr}${tempStr}`));
                }
                if (tel.ram_total_bytes && tel.ram_available_bytes) {
                    const ramTotalGB = (tel.ram_total_bytes / (1024 * 1024 * 1024)).toFixed(1);
                    const ramUsedGB = ((tel.ram_total_bytes - tel.ram_available_bytes) / (1024 * 1024 * 1024)).toFixed(1);
                    body.appendChild(createDetailRow("RAM:", `${ramUsedGB} / ${ramTotalGB} GB`));
                }
                if (tel.storage_total_bytes && tel.storage_available_bytes) {
                    const storageTotalGB = (tel.storage_total_bytes / (1024 * 1024 * 1024)).toFixed(1);
                    const storageFreeGB = (tel.storage_available_bytes / (1024 * 1024 * 1024)).toFixed(1);
                    body.appendChild(createDetailRow("Storage:", `${storageFreeGB} GB free / ${storageTotalGB} GB`));
                }
            }

            // Connection Mode Selector (Phase 28A)
            const modeRow = document.createElement("div");
            modeRow.className = "device-detail-row mt-2";
            const modeLabel = document.createElement("span");
            modeLabel.className = "label";
            modeLabel.textContent = "Mode:";
            const modeSelect = document.createElement("select");
            modeSelect.className = "device-connection-mode-select";
            modeSelect.innerHTML = `
                <option value="auto">Auto (Local First)</option>
                <option value="local_only">Local Only</option>
                <option value="remote_only">Remote Relay</option>
            `;
            modeSelect.value = dev.connection_mode || "auto";
            modeSelect.addEventListener("change", async () => {
                const newMode = modeSelect.value;
                const res = await apiRequest("/api/devices/connection-mode", "POST", {
                    device_id: dev.device_id,
                    connection_mode: newMode,
                });
                if (!res || !res.success) {
                    alert("Failed to update connection mode: " + (res?.error || "Unknown error"));
                    modeSelect.value = dev.connection_mode || "auto";
                }
            });
            modeRow.appendChild(modeLabel);
            modeRow.appendChild(modeSelect);
            body.appendChild(modeRow);

            // Permission Profile Selector (Stage 2B)
            const permRow = document.createElement("div");
            permRow.className = "device-detail-row mt-2";
            const permLabel = document.createElement("span");
            permLabel.className = "label";
            permLabel.textContent = "Profile:";
            const permSelect = document.createElement("select");
            permSelect.className = "device-permission-profile-select";
            permSelect.innerHTML = `
                <option value="full_control">🛡️ Full Control</option>
                <option value="files_and_clipboard">📁 Files & Clipboard</option>
                <option value="clipboard_only">📋 Clipboard Only</option>
            `;
            permSelect.value = dev.permission_profile || "full_control";
            permSelect.addEventListener("change", async () => {
                const newProfile = permSelect.value;
                const res = await apiRequest("/api/devices/permission-profile", "POST", {
                    device_id: dev.device_id,
                    profile: newProfile,
                });
                if (!res || !res.success) {
                    alert("Failed to update permission profile: " + (res?.error || "Unknown error"));
                    permSelect.value = dev.permission_profile || "full_control";
                }
            });
            permRow.appendChild(permLabel);
            permRow.appendChild(permSelect);
            body.appendChild(permRow);

            // Actions row
            const actionsRow = document.createElement("div");
            actionsRow.className = "device-card-actions mt-3";
            if (!dev.is_connected) {
                const btnRevoke = document.createElement("button");
                btnRevoke.className = "btn-danger btn-sm";
                btnRevoke.textContent = "🗑 Forget Device";
                btnRevoke.title = "Permanently remove this offline device";
                btnRevoke.addEventListener("click", async () => {
                    if (!confirm(`Permanently remove offline device '${dev.device_name || dev.device_id}'?`)) return;
                    btnRevoke.disabled = true;
                    btnRevoke.textContent = "Removing...";
                    const revRes = await apiRequest("/api/devices/revoke", "POST", { device_id: dev.device_id });
                    if (revRes && revRes.success) {
                        card.remove();
                        loadOverview();
                        loadDevices();
                    } else {
                        alert("Failed to revoke device: " + (revRes.error || revRes.status));
                        btnRevoke.disabled = false;
                        btnRevoke.textContent = "🗑 Forget Device";
                    }
                });
                actionsRow.appendChild(btnRevoke);
            } else {
                const activeTag = document.createElement("span");
                activeTag.className = "text-xs text-muted";
                activeTag.textContent = "✓ Active authorized session";
                actionsRow.appendChild(activeTag);
            }
            body.appendChild(actionsRow);

            card.appendChild(header);
            card.appendChild(body);
            container.appendChild(card);
        });
    }

    async function cleanOfflineGhosts() {
        const data = await apiRequest("/api/devices");
        const devices = (data && Array.isArray(data.devices)) ? data.devices : ((data && data.data && Array.isArray(data.data.devices)) ? data.data.devices : []);
        const offlinePeers = devices.filter(d => !isLocalNode(d) && !d.is_connected);

        if (offlinePeers.length === 0) {
            alert("No offline ghost devices found to clean.");
            return;
        }

        if (!confirm(`Found ${offlinePeers.length} disconnected ghost device(s). Permanently remove them?`)) {
            return;
        }

        let removedCount = 0;
        for (const dev of offlinePeers) {
            const res = await apiRequest("/api/devices/revoke", "POST", { device_id: dev.device_id });
            if (res && res.success) {
                removedCount++;
            }
        }

        alert(`Cleaned ${removedCount} offline ghost device(s).`);
        loadDevices();
        loadOverview();
    }

    async function showPairingQr(forceRefresh = true) {
        const qrCard = document.getElementById("qr-display-card");
        const svgBox = document.getElementById("qr-svg-container");
        const pinCode = document.getElementById("qr-pin-code");
        const metaText = document.getElementById("qr-meta-text");
        const countdownEl = document.getElementById("qr-countdown");

        if (!qrCard || !svgBox) return;

        qrCard.classList.remove("hidden");

        if (forceRefresh) {
            svgBox.innerHTML = '<div class="spinner"></div>';
            if (pinCode) pinCode.textContent = "------";
            if (countdownEl) countdownEl.textContent = "⏳ Generating...";

            const res = await apiRequest("/api/pair/qr", "POST", { trust_tier: selectedPairingTier });
            if (res && res.success) {
                svgBox.innerHTML = res.svg || "";
                const payload = res.data || {};
                if (pinCode) pinCode.textContent = payload.pin || "------";
                if (metaText) {
                    const ips = Array.isArray(payload.ips) ? payload.ips.join(", ") : (payload.ips || "127.0.0.1");
                    const tierLabel = (selectedPairingTier === "owner") ? "OWNER" : "PEER";
                    metaText.textContent = `Node: ${payload.node_id || payload.id || 'desktop-core'} | Port: ${payload.port || 8765} | Tier: ${tierLabel} | LAN IPs: ${ips}`;
                }
            } else {
                const errMsg = (res && res.error) ? res.error : "Failed to generate pairing QR. Ensure SNOW Desktop Core is running.";
                svgBox.innerHTML = `<div class="empty-state text-danger">${escapeHtml(errMsg)}</div>`;
            }
        }

        // Trigger polling for live PIN state and pending phone connections
        pollPairingState();
    }

    async function pollPairingState() {
        if (pairingStateTimer) {
            clearTimeout(pairingStateTimer);
            pairingStateTimer = null;
        }

        const qrCard = document.getElementById("qr-display-card");
        if (!qrCard || qrCard.classList.contains("hidden")) return;

        const res = await apiRequest("/api/pair/state");
        if (res && res.success && res.data) {
            const st = res.data;
            const pinCode = document.getElementById("qr-pin-code");
            const countdownEl = document.getElementById("qr-countdown");
            const pendingAlert = document.getElementById("pending-device-alert");
            const pendingName = document.getElementById("pending-device-name");

            if (st.is_paired) {
                // Device successfully paired! Hide pairing card and refresh
                qrCard.classList.add("hidden");
                loadDevices();
                loadOverview();
                return;
            }

            if (st.has_active_pin) {
                if (pinCode && st.pin) pinCode.textContent = st.pin;
                if (countdownEl) countdownEl.textContent = `⏳ ${st.remaining_seconds}s remaining`;
            } else {
                if (countdownEl) countdownEl.textContent = "⚠️ PIN expired";
            }

            if (st.pending_device_id) {
                if (pendingAlert) pendingAlert.classList.remove("hidden");
                if (pendingName) pendingName.textContent = st.pending_device_name || st.pending_device_id;
            } else {
                if (pendingAlert) pendingAlert.classList.add("hidden");
            }
        }

        // Schedule next poll if card is still open
        if (qrCard && !qrCard.classList.contains("hidden")) {
            pairingStateTimer = setTimeout(pollPairingState, 1500);
        }
    }

    // 4C. SAF Phone Files
    async function loadSafFiles() {
        const fileSelect = document.getElementById("files-device-select");
        const targetDev = fileSelect ? fileSelect.value : activeDeviceId;
        const tbody = document.getElementById("files-table-body");
        if (!tbody) return;

        if (!targetDev) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Select a connected Android device to browse SAF files.</td></tr>';
            return;
        }

        tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><div class="spinner"></div> Loading phone storage...</td></tr>';

        const showHidden = document.getElementById("chk-show-hidden")?.checked || false;
        const endpoint = `/api/files?device_id=${encodeURIComponent(targetDev)}&subpath=${encodeURIComponent(currentSubpath)}&show_hidden=${showHidden}`;
        const res = await apiRequest(endpoint);

        const storageBadge = document.getElementById("files-storage-badge");
        if (storageBadge) {
            const mode = (res && res.storage_mode) || (res && res.data && res.data.storage_mode);
            if (mode === "full_shared_storage") {
                storageBadge.className = "badge badge-success";
                storageBadge.textContent = "Full Internal Shared Storage";
            } else if (mode === "saf_tree") {
                storageBadge.className = "badge badge-primary";
                storageBadge.textContent = "SAF Folder";
            } else {
                storageBadge.className = "badge badge-muted";
                storageBadge.textContent = "Storage Unavailable";
            }
        }

        tbody.innerHTML = "";
        if (!res || !res.success) {
            let errorText = res ? (res.error || res.status || "Failed loading files") : "Connection failed";
            if (res && (res.status === "SAF_FOLDER_NOT_CONFIGURED" || (res.error && res.error.includes("SAF_FOLDER_NOT_CONFIGURED")))) {
                errorText = "SAF storage folder not configured on phone. Please open the SNOW app on your phone (Files tab) and select a storage folder, or grant Full Phone Storage Access in Settings.";
            } else if (res && (res.status === "SAF_PERMISSION_REVOKED" || (res.error && res.error.includes("SAF_PERMISSION_REVOKED")))) {
                errorText = "Storage permission expired or revoked on phone. Please re-select a folder or check permissions in the SNOW Android app.";
            } else if (res && res.status === "ALL_FILES_ACCESS_REQUIRED") {
                errorText = "Full Phone Storage Access is not granted. Please open SNOW Settings > Full Phone Storage Access on your phone to enable.";
            }
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state text-danger">${escapeHtml(errorText)}</td></tr>`;
            return;
        }

        const items = (res && Array.isArray(res.items)) ? res.items : ((res && res.data && Array.isArray(res.data.items)) ? res.data.items : []);
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Folder is empty.</td></tr>';
            return;
        }

        items.forEach(item => {
            const tr = document.createElement("tr");
            const isDir = item.is_directory === true || item.type === "directory";

            // Name + Icon
            const tdName = document.createElement("td");
            tdName.className = "file-name-cell";
            const icon = document.createElement("span");
            icon.className = "file-icon";
            icon.textContent = isDir ? "📁" : "📄";
            const nameSpan = document.createElement("span");
            nameSpan.textContent = item.name || "unnamed";

            tdName.appendChild(icon);
            tdName.appendChild(nameSpan);

            if (isDir) {
                tdName.classList.add("cursor-pointer");
                tdName.title = "Click to enter folder";
                tdName.addEventListener("click", () => {
                    currentSubpath = currentSubpath ? (currentSubpath + "/" + item.name) : item.name;
                    updateBreadcrumbs();
                    loadSafFiles();
                });
            }

            // Type
            const tdType = document.createElement("td");
            tdType.textContent = isDir ? "Folder" : (item.mime_type || "File");

            // Size
            const sizeVal = item.size_bytes ?? item.size ?? 0;
            const tdSize = document.createElement("td");
            tdSize.textContent = isDir ? "--" : formatBytes(sizeVal);

            // Last Modified
            const tdMod = document.createElement("td");
            tdMod.textContent = item.last_modified ? formatTimestamp(item.last_modified) : "--";

            // Action
            const tdAction = document.createElement("td");
            if (!isDir) {
                const btnDownload = document.createElement("button");
                btnDownload.className = "btn-table-action";
                btnDownload.textContent = "⬇ Download to PC";
                btnDownload.addEventListener("click", async () => {
                    btnDownload.textContent = "⏳ Downloading...";
                    btnDownload.disabled = true;
                    const dlRes = await apiRequest("/api/files/download", "POST", {
                        device_id: targetDev,
                        file_name: item.name,
                        subpath: currentSubpath,
                    });
                    if (dlRes && dlRes.success) {
                        btnDownload.textContent = "✓ Saved";
                        setTimeout(() => {
                            btnDownload.textContent = "⬇ Download to PC";
                            btnDownload.disabled = false;
                        }, 2500);
                    } else {
                        btnDownload.textContent = "✕ Failed";
                        alert("File download failed: " + (dlRes.error || dlRes.status || "Unknown error"));
                        btnDownload.disabled = false;
                    }
                });
                tdAction.appendChild(btnDownload);
            }

            tr.appendChild(tdName);
            tr.appendChild(tdType);
            tr.appendChild(tdSize);
            tr.appendChild(tdMod);
            tr.appendChild(tdAction);
            tbody.appendChild(tr);
        });
    }

    function updateBreadcrumbs() {
        const bar = document.getElementById("files-breadcrumbs");
        if (!bar) return;
        bar.innerHTML = "";

        const rootCrumb = document.createElement("span");
        rootCrumb.className = "crumb" + (currentSubpath === "" ? " active" : "");
        rootCrumb.textContent = "Root";
        rootCrumb.addEventListener("click", () => {
            currentSubpath = "";
            updateBreadcrumbs();
            loadSafFiles();
        });
        bar.appendChild(rootCrumb);

        if (currentSubpath) {
            const parts = currentSubpath.split("/");
            let accumulated = "";
            parts.forEach((part, idx) => {
                accumulated = accumulated ? (accumulated + "/" + part) : part;
                const sep = document.createElement("span");
                sep.className = "crumb-sep";
                sep.textContent = " / ";
                bar.appendChild(sep);

                const c = document.createElement("span");
                c.className = "crumb" + (idx === parts.length - 1 ? " active" : "");
                c.textContent = part;
                const pathTarget = accumulated;
                c.addEventListener("click", () => {
                    currentSubpath = pathTarget;
                    updateBreadcrumbs();
                    loadSafFiles();
                });
                bar.appendChild(c);
            });
        }
    }

    // 4D. Notifications
    async function loadNotifications() {
        const feed = document.getElementById("notifications-list");
        if (!feed) return;

        feed.innerHTML = '<div class="empty-state"><div class="spinner"></div> Fetching active phone notifications...</div>';

        const endpoint = activeDeviceId ? `/api/notifications?device_id=${encodeURIComponent(activeDeviceId)}` : "/api/notifications";
        const res = await apiRequest(endpoint);
        feed.innerHTML = "";

        if (!res || !res.success) {
            const empty = document.createElement("div");
            empty.className = "empty-state";
            if (res && res.status === "PERMISSION_NOT_GRANTED") {
                empty.textContent = "Notification Listener Permission not granted on Android. Enable it in Phone Settings > Apps > Special Access > Notification Access.";
            } else if (res && res.status === "SYNC_OPT_OUT") {
                empty.textContent = "Notification mirroring is currently disabled in Android companion app settings.";
            } else {
                empty.textContent = "Failed to load notifications: " + (res ? (res.error || res.status) : "Connection error");
            }
            feed.appendChild(empty);
            return;
        }

        const notifs = (res && Array.isArray(res.notifications)) ? res.notifications : ((res && res.data && Array.isArray(res.data.notifications)) ? res.data.notifications : []);
        if (notifs.length === 0) {
            const empty = document.createElement("div");
            empty.className = "empty-state";
            empty.textContent = "No active notifications on phone.";
            feed.appendChild(empty);
            return;
        }

        notifs.forEach(notif => {
            const card = document.createElement("div");
            card.className = "notif-card";

            const header = document.createElement("div");
            header.className = "notif-header";

            const appBadge = document.createElement("span");
            appBadge.className = "notif-app-name";
            appBadge.textContent = notif.app_name || notif.package_name || "Notification";

            const timeSpan = document.createElement("span");
            timeSpan.className = "notif-time";
            const postTime = notif.timestamp || notif.post_time || notif.postTime;
            timeSpan.textContent = formatTimestamp(postTime);

            header.appendChild(appBadge);
            header.appendChild(timeSpan);

            const title = document.createElement("h4");
            title.className = "notif-title";
            title.textContent = notif.title || "(No Title)";

            const body = document.createElement("p");
            body.className = "notif-body";
            body.textContent = notif.text || notif.body || "";

            const actions = document.createElement("div");
            actions.className = "notif-actions";

            // Dismiss Button
            const btnDismiss = document.createElement("button");
            btnDismiss.className = "btn-secondary btn-sm";
            btnDismiss.textContent = "Dismiss";
            btnDismiss.addEventListener("click", async () => {
                btnDismiss.disabled = true;
                btnDismiss.textContent = "Dismissing...";
                const dRes = await apiRequest("/api/notifications/dismiss", "POST", {
                    key: notif.key,
                    device_id: activeDeviceId,
                });
                if (dRes && dRes.success) {
                    card.remove();
                } else {
                    alert("Failed to dismiss notification: " + (dRes.error || dRes.status));
                    btnDismiss.disabled = false;
                    btnDismiss.textContent = "Dismiss";
                }
            });
            actions.appendChild(btnDismiss);

            // Quick Reply if supported
            if (notif.can_reply) {
                const replyBox = document.createElement("div");
                replyBox.className = "notif-reply-box";

                const replyInput = document.createElement("input");
                replyInput.type = "text";
                replyInput.className = "form-input form-input-sm";
                replyInput.placeholder = "Type quick reply...";

                const btnReply = document.createElement("button");
                btnReply.className = "btn-primary btn-sm";
                btnReply.textContent = "Send Reply";
                btnReply.addEventListener("click", async () => {
                    const text = replyInput.value.trim();
                    if (!text) return;
                    btnReply.disabled = true;
                    btnReply.textContent = "Sending...";
                    const rRes = await apiRequest("/api/notifications/reply", "POST", {
                        key: notif.key,
                        text: text,
                        device_id: activeDeviceId,
                    });
                    if (rRes && rRes.success) {
                        btnReply.textContent = "Sent!";
                        replyInput.value = "";
                        setTimeout(() => card.remove(), 1200);
                    } else {
                        alert("Quick reply failed: " + (rRes.error || rRes.status));
                        btnReply.disabled = false;
                        btnReply.textContent = "Send Reply";
                    }
                });

                replyBox.appendChild(replyInput);
                replyBox.appendChild(btnReply);
                actions.appendChild(replyBox);
            }

            card.appendChild(header);
            card.appendChild(title);
            card.appendChild(body);
            card.appendChild(actions);
            feed.appendChild(card);
        });
    }

    // 4E. Media Controls
    function setupMediaControls() {
        const toggleButtons = document.querySelectorAll(".media-target-selector .btn-toggle");
        toggleButtons.forEach(btn => {
            btn.addEventListener("click", () => {
                toggleButtons.forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                mediaTarget = btn.getAttribute("data-target") || "windows";
            });
        });

        const feedbackEl = document.getElementById("media-feedback");
        document.querySelectorAll(".btn-media").forEach(btn => {
            btn.addEventListener("click", async () => {
                const action = btn.getAttribute("data-action");
                if (!action) return;

                if (feedbackEl) {
                    feedbackEl.textContent = `Dispatching '${action}' to ${mediaTarget}...`;
                    feedbackEl.className = "feedback-msg";
                }

                const res = await apiRequest("/api/media", "POST", {
                    action: action,
                    target: mediaTarget,
                    device_id: activeDeviceId,
                });

                if (feedbackEl) {
                    if (res && res.success) {
                        feedbackEl.textContent = `✓ '${action}' sent to ${mediaTarget} successfully.`;
                        feedbackEl.className = "feedback-msg success";
                    } else {
                        feedbackEl.textContent = `✕ Failed: ${res.error || res.status}`;
                        feedbackEl.className = "feedback-msg error";
                    }
                }
            });
        });
    }

    // 4F. Share Link / Text
    function setupShare() {
        const btnSend = document.getElementById("btn-send-share");
        const urlInput = document.getElementById("share-url-input");
        const textInput = document.getElementById("share-text-input");
        const targetSelect = document.getElementById("share-target-select");
        const statusMsg = document.getElementById("share-status-msg");

        if (!btnSend) return;

        btnSend.addEventListener("click", async () => {
            const url = urlInput ? urlInput.value.trim() : "";
            const text = textInput ? textInput.value.trim() : "";
            const target = targetSelect ? targetSelect.value : "phone";

            if (!url && !text) {
                if (statusMsg) {
                    statusMsg.textContent = "Please provide a URL link or a text note to share.";
                    statusMsg.className = "feedback-msg error";
                }
                return;
            }

            if (url) {
                if (!url.startsWith("http://") && !url.startsWith("https://")) {
                    if (statusMsg) {
                        statusMsg.textContent = "Only http:// and https:// URLs are permitted.";
                        statusMsg.className = "feedback-msg error";
                    }
                    return;
                }
            }

            if (statusMsg) {
                statusMsg.textContent = `Sharing with ${target}...`;
                statusMsg.className = "feedback-msg";
            }

            btnSend.disabled = true;
            const res = await apiRequest("/api/share", "POST", {
                url: url,
                text: text,
                target: target,
                device_id: activeDeviceId,
            });

            btnSend.disabled = false;

            if (statusMsg) {
                if (res && res.success) {
                    statusMsg.textContent = `✓ Successfully dispatched to ${target}.`;
                    statusMsg.className = "feedback-msg success";
                    if (urlInput) urlInput.value = "";
                    if (textInput) textInput.value = "";
                } else {
                    statusMsg.textContent = `✕ Share failed: ${res.error || res.status}`;
                    statusMsg.className = "feedback-msg error";
                }
            }
        });
    }

    // 4G. Approvals
    async function loadApprovalsList() {
        const feed = document.getElementById("approvals-list");
        if (!feed) return;

        if (approvalsCountdownTimer) {
            clearInterval(approvalsCountdownTimer);
            approvalsCountdownTimer = null;
        }

        feed.innerHTML = '<div class="empty-state"><div class="spinner"></div> Querying authorization queue...</div>';
        const res = await apiRequest("/api/approvals");
        feed.innerHTML = "";

        const requests = (res && Array.isArray(res.requests)) ? res.requests : ((res && Array.isArray(res.approvals)) ? res.approvals : ((res && res.data && Array.isArray(res.data.requests)) ? res.data.requests : []));
        if (!res || !res.success || requests.length === 0) {
            const empty = document.createElement("div");
            empty.className = "empty-state";
            empty.textContent = "No pending approval requests. System is secure.";
            feed.appendChild(empty);
            loadApprovalsCount();
            return;
        }

        requests.forEach(req => {
            const card = document.createElement("div");
            card.className = "approval-card";
            card.id = `approval-card-${req.request_id}`;

            const header = document.createElement("div");
            header.className = "approval-header";

            const titleRow = document.createElement("div");
            titleRow.className = "d-flex align-items-center gap-2";

            const opName = document.createElement("h4");
            opName.textContent = req.capability || req.action || req.operation || "Sensitive Operation";

            const riskLevel = (req.risk_level || "MEDIUM").toUpperCase();
            const riskBadge = document.createElement("span");
            riskBadge.className = `badge ${getRiskBadgeClass(riskLevel)}`;
            riskBadge.textContent = riskLevel;

            titleRow.appendChild(opName);
            titleRow.appendChild(riskBadge);

            const reqId = document.createElement("span");
            reqId.className = "text-xs text-muted";
            reqId.textContent = req.request_id;

            header.appendChild(titleRow);
            header.appendChild(reqId);

            const details = document.createElement("div");
            details.className = "approval-details";
            details.appendChild(createDetailRow("Principal:", req.principal || "AI Assistant"));
            details.appendChild(createDetailRow("Target Device:", req.target_device || "Windows Host"));
            details.appendChild(createDetailRow("Requested At:", formatTimestamp(req.created_at)));

            // Live TTL Countdown
            const ttlRow = document.createElement("div");
            ttlRow.className = "device-detail-row";
            const ttlLabel = document.createElement("span");
            ttlLabel.className = "label";
            ttlLabel.textContent = "Time-to-Live:";
            const ttlSpan = document.createElement("span");
            ttlSpan.className = "ttl-countdown";
            const initialRemaining = Math.max(0, Math.round(Number(req.time_remaining_seconds != null ? req.time_remaining_seconds : (req.expires_at || 0))));
            const deadlineMs = Date.now() + (initialRemaining * 1000);
            ttlSpan.setAttribute("data-deadline", deadlineMs.toString());
            ttlSpan.textContent = initialRemaining > 0 ? `⏳ ${initialRemaining}s remaining` : "⛔ Expired";
            ttlRow.appendChild(ttlLabel);
            ttlRow.appendChild(ttlSpan);
            details.appendChild(ttlRow);

            if (req.reason) {
                details.appendChild(createDetailRow("Reason:", req.reason));
            }

            // Secret-redacted parameter preview
            const paramsBox = document.createElement("div");
            paramsBox.className = "mt-2";
            const paramsLabel = document.createElement("span");
            paramsLabel.className = "label text-xs font-semibold text-muted";
            paramsLabel.textContent = "Sanitized Parameters (Preview):";
            const paramsPre = document.createElement("div");
            paramsPre.className = "sanitized-params-pre";
            const safeParams = req.sanitized_params || req.params || {};
            paramsPre.textContent = JSON.stringify(safeParams, null, 2);
            paramsBox.appendChild(paramsLabel);
            paramsBox.appendChild(paramsPre);
            details.appendChild(paramsBox);

            const actions = document.createElement("div");
            actions.className = "approval-actions mt-3";

            const btnApprove = document.createElement("button");
            btnApprove.className = "btn-success";
            btnApprove.textContent = "✓ Approve Operation";
            if (initialRemaining <= 0) btnApprove.disabled = true;

            btnApprove.addEventListener("click", async () => {
                const nowMs = Date.now();
                const deadline = Number(ttlSpan.getAttribute("data-deadline") || 0);
                if (deadline > 0 && (deadline - nowMs) <= 0) {
                    btnApprove.disabled = true;
                    alert("This approval request has expired and cannot be approved.");
                    return;
                }
                btnApprove.disabled = true;
                btnApprove.textContent = "Approving...";
                const r = await apiRequest(`/api/approvals/${encodeURIComponent(req.request_id)}/resolve`, "POST", {
                    request_id: req.request_id,
                    decision: "approve",
                });
                if (r && r.success) {
                    card.style.opacity = "0.4";
                    setTimeout(() => {
                        card.remove();
                        loadApprovalsCount();
                        if (feed.querySelectorAll(".approval-card").length === 0) {
                            feed.innerHTML = '<div class="empty-state">No pending approval requests. System is secure.</div>';
                        }
                    }, 200);
                } else {
                    alert("Approval failed: " + (r.error || r.status || "Unknown error"));
                    btnApprove.disabled = false;
                    btnApprove.textContent = "✓ Approve Operation";
                }
            });

            const btnDeny = document.createElement("button");
            btnDeny.className = "btn-danger";
            btnDeny.textContent = "✕ Deny";
            btnDeny.addEventListener("click", async () => {
                btnDeny.disabled = true;
                btnDeny.textContent = "Denying...";
                const r = await apiRequest(`/api/approvals/${encodeURIComponent(req.request_id)}/resolve`, "POST", {
                    request_id: req.request_id,
                    decision: "deny",
                });
                if (r && r.success) {
                    card.style.opacity = "0.4";
                    setTimeout(() => {
                        card.remove();
                        loadApprovalsCount();
                        if (feed.querySelectorAll(".approval-card").length === 0) {
                            feed.innerHTML = '<div class="empty-state">No pending approval requests. System is secure.</div>';
                        }
                    }, 200);
                } else {
                    alert("Denial failed: " + (r.error || r.status || "Unknown error"));
                    btnDeny.disabled = false;
                    btnDeny.textContent = "✕ Deny";
                }
            });

            actions.appendChild(btnApprove);
            actions.appendChild(btnDeny);

            card.appendChild(header);
            card.appendChild(details);
            card.appendChild(actions);
            feed.appendChild(card);
        });

        // Start live 1-second countdown ticker
        approvalsCountdownTimer = setInterval(() => {
            const countdowns = feed.querySelectorAll(".ttl-countdown");
            if (countdowns.length === 0) {
                clearInterval(approvalsCountdownTimer);
                approvalsCountdownTimer = null;
                return;
            }
            const nowMs = Date.now();
            countdowns.forEach(span => {
                const deadline = Number(span.getAttribute("data-deadline") || 0);
                const left = Math.max(0, Math.round((deadline - nowMs) / 1000));
                if (left > 0) {
                    span.textContent = `⏳ ${left}s remaining`;
                } else {
                    span.textContent = "⛔ Expired";
                    const card = span.closest(".approval-card");
                    if (card) {
                        const appBtn = card.querySelector(".btn-success");
                        if (appBtn) appBtn.disabled = true;
                    }
                }
            });
        }, 1000);
    }

    // 4H. Activity Audit
    async function loadActivityHistory() {
        const tbody = document.getElementById("activity-table-body");
        if (!tbody) return;

        tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><div class="spinner"></div> Reading audit records...</td></tr>';

        const res = await apiRequest("/api/activity?limit=50");
        tbody.innerHTML = "";

        const events = (res && Array.isArray(res.events)) ? res.events : ((res && Array.isArray(res.records)) ? res.records : ((res && res.data && Array.isArray(res.data.events)) ? res.data.events : []));
        if (!res || !res.success || events.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No audit events recorded.</td></tr>';
            return;
        }

        events.forEach(rec => {
            const tr = document.createElement("tr");

            const tdTime = document.createElement("td");
            tdTime.textContent = formatTimestamp(rec.timestamp);

            const tdType = document.createElement("td");
            tdType.textContent = rec.capability || rec.event_type || "--";

            const tdPrinc = document.createElement("td");
            tdPrinc.textContent = rec.principal || "--";

            const tdDev = document.createElement("td");
            tdDev.textContent = rec.target_device || rec.device_id || "--";

            const tdDetails = document.createElement("td");
            tdDetails.textContent = rec.outcome || rec.summary || JSON.stringify(rec.details || {});

            tr.appendChild(tdTime);
            tr.appendChild(tdType);
            tr.appendChild(tdPrinc);
            tr.appendChild(tdDev);
            tr.appendChild(tdDetails);
            tbody.appendChild(tr);
        });
    }

    // =========================================================================
    // 5. Theme & Settings
    // =========================================================================

    function initTheme() {
        const savedTheme = localStorage.getItem("snow_theme") || "light";
        applyTheme(savedTheme);

        if (btnThemeToggle) {
            btnThemeToggle.addEventListener("click", () => {
                const current = document.body.classList.contains("theme-dark") ? "dark" : "light";
                const next = current === "dark" ? "light" : "dark";
                applyTheme(next);
            });
        }

        const themeRadios = document.querySelectorAll('input[name="theme-choice"]');
        themeRadios.forEach(radio => {
            if (radio.value === savedTheme) radio.checked = true;
            radio.addEventListener("change", () => {
                applyTheme(radio.value);
            });
        });
    }

    function applyTheme(theme) {
        if (theme === "dark") {
            document.body.className = "theme-dark";
        } else {
            document.body.className = "theme-light";
        }
        localStorage.setItem("snow_theme", theme);

        const radios = document.querySelectorAll('input[name="theme-choice"]');
        radios.forEach(r => {
            r.checked = (r.value === theme);
        });
    }

    // =========================================================================
    // 6. Utility Functions
    // =========================================================================

    function getRiskBadgeClass(riskLevel) {
        const lvl = (riskLevel || "").toUpperCase();
        if (lvl === "CRITICAL") return "badge-risk-critical";
        if (lvl === "HIGH") return "badge-risk-high";
        if (lvl === "MEDIUM") return "badge-risk-medium";
        return "badge-risk-low";
    }

    function createDetailRow(label, value) {
        const row = document.createElement("div");
        row.className = "device-detail-row";
        const l = document.createElement("span");
        l.className = "label";
        l.textContent = label;
        const v = document.createElement("span");
        v.className = "val";
        v.textContent = value;
        row.appendChild(l);
        row.appendChild(v);
        return row;
    }

    function formatTimestamp(ts) {
        if (!ts) return "--";
        try {
            const date = new Date(typeof ts === "number" ? (ts < 1e11 ? ts * 1000 : ts) : ts);
            return date.toLocaleTimeString() + " " + date.toLocaleDateString();
        } catch (_) {
            return String(ts);
        }
    }

    function formatBytes(bytes) {
        if (bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
    }

    async function loadRelayStatus() {
        const valEl = document.getElementById("relay-status-val");
        const clientValEl = document.getElementById("relay-client-status-val");
        const epEl = document.getElementById("relay-endpoint-val");
        const frameEl = document.getElementById("relay-max-frame-val");
        const resBox = document.getElementById("relay-test-result");
        const toggleEl = document.getElementById("relay-enable-toggle");
        const urlInput = document.getElementById("relay-url-input");
        const groupInput = document.getElementById("relay-group-input");

        const res = await apiRequest("/api/relay/status");
        if (res && res.success && res.data) {
            const d = res.data;
            if (valEl) {
                valEl.innerHTML = d.enabled
                    ? `<span class="badge badge-success">Service Active</span>`
                    : `<span class="badge badge-muted">Service Standby</span>`;
            }
            if (epEl) epEl.textContent = d.endpoint || "Not Configured";
            if (frameEl) frameEl.textContent = `${d.max_frame_size_mib || 25} MiB (${d.quota_mib_hr || 100} MiB/hr quota)`;
        } else {
            if (valEl) valEl.innerHTML = `<span class="badge badge-danger">Unavailable</span>`;
        }

        const cfgRes = await apiRequest("/api/relay/config");
        if (cfgRes && cfgRes.success && cfgRes.data) {
            const cd = cfgRes.data;
            if (toggleEl && !toggleEl.dataset.userEdited) toggleEl.checked = !!cd.enabled;
            if (urlInput && !urlInput.dataset.userEdited) urlInput.value = cd.relay_url || "";
            if (groupInput && !groupInput.dataset.userEdited) groupInput.value = cd.group_id || "";
            if (clientValEl) {
                if (cd.connected) {
                    clientValEl.innerHTML = `<span class="badge badge-success">Connected</span>`;
                } else if (cd.enabled) {
                    clientValEl.innerHTML = `<span class="badge badge-warning">Connecting...</span>`;
                } else {
                    clientValEl.innerHTML = `<span class="badge badge-muted">Disabled</span>`;
                }
            }
            if (resBox) {
                resBox.textContent = cd.connected
                    ? `Connected to ${cd.relay_url} (group: ${cd.group_id}). Active tunnels: ${(cd.active_tunnels || []).length}.`
                    : (cd.enabled ? "Relay client enabled, connecting..." : "Relay client disabled (operating in local-first zero-trust mode).");
            }
        }
    }

    async function loadMcpGatewayStatus() {
        const statusEl = document.getElementById("mcp-gateway-status");
        const epEl = document.getElementById("mcp-endpoint-val");
        const hostsEl = document.getElementById("mcp-hosts-val");
        const resBox = document.getElementById("mcp-test-result");

        if (resBox) resBox.textContent = "Checking Remote MCP Gateway status...";

        const res = await apiRequest("/api/mcp-gateway/status");
        if (res && res.success && res.data) {
            const d = res.data;
            const st = d.gateway_status;
            if (statusEl) {
                if (st === "online") {
                    statusEl.innerHTML = `<span class="badge badge-success">Online (8771)</span>`;
                } else if (st === "offline") {
                    statusEl.innerHTML = `<span class="badge badge-muted">Offline (Not Started)</span>`;
                } else if (st === "timeout") {
                    statusEl.innerHTML = `<span class="badge badge-warning">Probe Timed Out</span>`;
                } else {
                    statusEl.innerHTML = `<span class="badge badge-warning">Unhealthy</span>`;
                }
            }
            if (epEl && d.endpoint) epEl.textContent = d.endpoint;

            const publicEpRow = document.getElementById("row-public-mcp-endpoint");
            const publicEpEl = document.getElementById("mcp-public-endpoint-val");
            const btnCopyPublicMcp = document.getElementById("btn-copy-public-mcp-url");
            const capCountEl = document.getElementById("mcp-capabilities-count");

            if (capCountEl && d.capabilities_count) {
                capCountEl.textContent = String(d.capabilities_count);
            }

            if (d.public_endpoint && typeof d.public_endpoint === "string" && d.public_endpoint.startsWith("http")) {
                if (publicEpEl) publicEpEl.textContent = d.public_endpoint;
                if (publicEpRow) publicEpRow.style.display = "flex";
                if (btnCopyPublicMcp) btnCopyPublicMcp.style.display = "inline-block";
            } else {
                if (publicEpEl) publicEpEl.textContent = "Not Configured";
                if (publicEpRow) publicEpRow.style.display = "none";
                if (btnCopyPublicMcp) btnCopyPublicMcp.style.display = "none";
            }

            if (hostsEl && Array.isArray(d.ai_hosts)) {
                hostsEl.textContent = "";
                if (d.ai_hosts.length === 0) {
                    const emptySpan = document.createElement("span");
                    emptySpan.className = "text-muted";
                    emptySpan.textContent = "None";
                    hostsEl.appendChild(emptySpan);
                } else {
                    d.ai_hosts.forEach(h => {
                        const badge = document.createElement("span");
                        const cls = h.is_configured ? "badge-success" : "badge-muted";
                        badge.className = `badge ${cls}`;
                        badge.style.marginRight = "4px";
                        badge.textContent = h.display_name || h.host || "Host";
                        hostsEl.appendChild(badge);
                    });
                }
            }

            if (resBox) {
                if (st === "online") {
                    resBox.innerHTML = `<span class="text-success">✓ Gateway Online at ${d.endpoint} (OAuth 2.1 Protected)</span>`;
                } else if (st === "offline") {
                    resBox.innerHTML = `<span class="text-muted">Gateway is offline. Start in terminal with: <code>python -m snow mcp-gateway</code></span>`;
                } else {
                    resBox.innerHTML = `<span class="text-warning">Gateway responding with status: ${st}</span>`;
                }
            }
        } else {
            if (statusEl) statusEl.innerHTML = `<span class="badge badge-danger">Error</span>`;
            if (resBox) resBox.innerHTML = `<span class="text-danger">${escapeHtml((res && res.error) ? res.error : "Failed querying MCP gateway status")}</span>`;
        }
    }

    async function loadNetworkIdentity() {
        const res = await apiRequest("/api/network/identity");
        if (res && res.success && res.identity) {
            const input = document.getElementById("input-network-name");
            if (input && document.activeElement !== input) {
                input.value = res.identity.network_name || "";
            }
        }
    }

    // =========================================================================
    // 6B. Workflows & Visual Capture (Phase 24)
    // =========================================================================

    function setupWorkflows() {
        const btnCapturePc = document.getElementById("btn-wf-capture-pc");
        const btnCapturePhone = document.getElementById("btn-wf-capture-phone");
        const btnHealth = document.getElementById("btn-wf-health");
        const btnPcToPhone = document.getElementById("btn-wf-pc-to-phone");
        const btnClipboard = document.getElementById("btn-wf-clipboard");

        if (btnCapturePc) {
            btnCapturePc.addEventListener("click", () => runWorkflow("pc_screenshot", "🖥️ Capture PC Screen"));
        }
        if (btnCapturePhone) {
            btnCapturePhone.addEventListener("click", () => capturePhoneScreen());
        }
        if (btnHealth) {
            btnHealth.addEventListener("click", () => runWorkflow("device_health_snapshot", "🩺 Device Health Snapshot"));
        }
        if (btnPcToPhone) {
            btnPcToPhone.addEventListener("click", () => runWorkflow("capture_pc_to_phone", "📲 Capture PC → Phone"));
        }
        if (btnClipboard) {
            btnClipboard.addEventListener("click", () => runWorkflow("share_clipboard_and_notify", "📋 Sync Clipboard & Notify"));
        }
    }

    async function capturePhoneScreen() {
        const targetDev = activeDeviceId;
        if (!targetDev) {
            showNotificationToast("Please select a connected Android device first.", "warning");
            return;
        }

        const btnCapture = document.getElementById("btn-wf-capture-phone");
        if (btnCapture) btnCapture.disabled = true;

        const runBox = document.getElementById("workflow-run-box");
        const nameDisplay = document.getElementById("workflow-name-display");
        const statusBadge = document.getElementById("workflow-status-badge");
        const stepsList = document.getElementById("workflow-steps-list");
        const previewBox = document.getElementById("capture-preview-box");
        const previewImg = document.getElementById("capture-preview-img");
        const summaryCard = document.getElementById("workflow-summary-card");
        const captureSummaryBanner = document.getElementById("capture-summary-banner");
        const captureErrorBox = document.getElementById("capture-error-box");

        try {
            if (runBox) runBox.classList.remove("d-none");
            if (summaryCard) {
                summaryCard.classList.add("d-none");
                summaryCard.innerHTML = "";
            }
            if (captureSummaryBanner) captureSummaryBanner.textContent = "";
            if (captureErrorBox) captureErrorBox.classList.add("d-none");
            if (nameDisplay) nameDisplay.textContent = "📱 One-Time Phone Screen Capture";
            if (statusBadge) {
                statusBadge.className = "badge badge-info";
                statusBadge.textContent = "REQUESTING CONSENT...";
            }
            if (stepsList) {
                stepsList.innerHTML = '<div class="spinner"></div> Requesting screen capture consent on Android device. Please check phone screen...';
            }
            if (previewBox) previewBox.classList.add("d-none");

            let res = await apiRequest("/api/screen/capture-phone", "POST", { device_id: targetDev });

            // Automatic bounded retry polling if consent was prompted on phone (Android 14+)
            if (res && !res.success && (res.status === "SCREEN_CAPTURE_CONSENT_REQUIRED" || (res.error && res.error.toLowerCase().includes("consent")))) {
                if (statusBadge) {
                    statusBadge.className = "badge badge-warning";
                    statusBadge.textContent = "WAITING FOR CONSENT";
                }
                if (stepsList) {
                    stepsList.innerHTML = '<div class="spinner"></div> <strong>Check your phone and tap Start now to allow screen capture.</strong> (Waiting up to 30s)...';
                }
                const startTime = Date.now();
                while (Date.now() - startTime < 30000) {
                    await new Promise(r => setTimeout(r, 2000));
                    const pollRes = await apiRequest("/api/screen/capture-phone", "POST", { device_id: targetDev });
                    if (pollRes && pollRes.success) {
                        res = pollRes;
                        break;
                    } else if (pollRes && pollRes.status !== "SCREEN_CAPTURE_CONSENT_REQUIRED" && (!pollRes.error || !pollRes.error.toLowerCase().includes("consent"))) {
                        res = pollRes;
                        break;
                    }
                }
            }

            if (stepsList) stepsList.innerHTML = "";

            if (!res || !res.success) {
                if (statusBadge) {
                    statusBadge.className = "badge badge-warning";
                    statusBadge.textContent = res ? (res.status || "CONSENT REQUIRED") : "FAILED";
                }
                if (stepsList) {
                    const errDiv = document.createElement("div");
                    errDiv.className = "empty-state text-warning";
                    const hint = res && res.remediation_hint ? ` Hint: ${res.remediation_hint}` : "";
                    errDiv.textContent = `Screen capture request: ${res ? (res.error || res.status) : "Failed"}.${hint}`;
                    stepsList.appendChild(errDiv);
                }
                return;
            }

            if (statusBadge) {
                statusBadge.className = "badge badge-success";
                statusBadge.textContent = "COMPLETED";
            }

            const data = res.data || res;
            const fileName = data.file_name;

            if (stepsList) {
                const okDiv = document.createElement("div");
                okDiv.className = "empty-state text-success";
                okDiv.textContent = `Phone screen captured and uploaded successfully (${fileName || "image"}).`;
                stepsList.appendChild(okDiv);
            }

            if (fileName && previewBox && previewImg) {
                previewBox.classList.remove("d-none");
                previewImg.classList.remove("d-none");
                if (captureErrorBox) captureErrorBox.classList.add("d-none");
                previewImg.src = `/api/captures/${encodeURIComponent(fileName)}`;
                previewImg.alt = `Phone Screenshot: ${fileName}`;
                previewImg.onerror = () => {
                    previewImg.classList.add("d-none");
                    if (captureErrorBox) {
                        captureErrorBox.classList.remove("d-none");
                        captureErrorBox.textContent = `Failed loading preview for: ${fileName}`;
                    }
                };
                previewImg.onload = () => {
                    previewImg.classList.remove("d-none");
                    if (captureErrorBox) captureErrorBox.classList.add("d-none");
                };
            }
        } finally {
            if (btnCapture) btnCapture.disabled = false;
        }
    }

    async function runWorkflow(workflowId, displayName) {
        const runBox = document.getElementById("workflow-run-box");
        const nameDisplay = document.getElementById("workflow-name-display");
        const statusBadge = document.getElementById("workflow-status-badge");
        const stepsList = document.getElementById("workflow-steps-list");
        const outputBox = document.getElementById("workflow-output-box");
        const outputPre = document.getElementById("workflow-output-pre");
        const previewBox = document.getElementById("capture-preview-box");
        const previewImg = document.getElementById("capture-preview-img");
        const summaryCard = document.getElementById("workflow-summary-card");
        const captureSummaryBanner = document.getElementById("capture-summary-banner");
        const captureErrorBox = document.getElementById("capture-error-box");

        if (!runBox) return;

        runBox.classList.remove("d-none");
        if (summaryCard) {
            summaryCard.classList.add("d-none");
            summaryCard.innerHTML = "";
        }
        if (captureSummaryBanner) captureSummaryBanner.textContent = "";
        if (captureErrorBox) captureErrorBox.classList.add("d-none");
        if (nameDisplay) nameDisplay.textContent = displayName || workflowId;
        if (statusBadge) {
            statusBadge.className = "badge badge-info";
            statusBadge.textContent = "RUNNING...";
        }
        if (stepsList) stepsList.innerHTML = '<div class="spinner"></div> Executing workflow steps through CapabilityEngine...';
        if (outputBox) outputBox.classList.add("d-none");
        if (previewBox) previewBox.classList.add("d-none");

        const res = await apiRequest("/api/workflows/run", "POST", { workflow_id: workflowId });

        if (stepsList) stepsList.innerHTML = "";

        if (!res || !res.success) {
            if (statusBadge) {
                statusBadge.className = "badge badge-danger";
                statusBadge.textContent = "FAILED";
            }
            if (stepsList) {
                const errDiv = document.createElement("div");
                errDiv.className = "empty-state text-danger";
                errDiv.textContent = `Execution failed: ${res.error || res.status || 'Unknown error'}`;
                stepsList.appendChild(errDiv);
            }
            return;
        }

        const report = res.data || res;
        const status = report.status || "COMPLETED";

        if (statusBadge) {
            if (status === "COMPLETED") {
                statusBadge.className = "badge badge-success";
                statusBadge.textContent = "COMPLETED";
            } else if (status === "PARTIAL") {
                statusBadge.className = "badge badge-warning";
                statusBadge.textContent = "PARTIAL";
            } else if (status === "PENDING_APPROVAL") {
                statusBadge.className = "badge badge-warning";
                statusBadge.textContent = "PAUSED (APPROVAL REQUIRED)";
            } else {
                statusBadge.className = "badge badge-danger";
                statusBadge.textContent = status;
            }
        }

        // Render Consumer-Friendly Summary Card
        renderConsumerSummaryCard(workflowId, report, summaryCard, captureSummaryBanner, captureErrorBox);

        const steps = Array.isArray(report.step_results) ? report.step_results : [];
        let capturedFileName = null;

        steps.forEach((step, idx) => {
            const item = document.createElement("div");
            item.className = "workflow-step-item";

            const header = document.createElement("div");
            header.className = "workflow-step-header";

            const nameEl = document.createElement("span");
            nameEl.className = "workflow-step-name";
            nameEl.textContent = `${idx + 1}. ${step.name || step.capability}`;

            const badge = document.createElement("span");
            const st = step.status || "UNKNOWN";
            if (st === "SUCCESS") {
                badge.className = "badge badge-success";
                badge.textContent = "✓ Success";
            } else if (st === "SKIPPED" || st === "PARTIAL") {
                badge.className = "badge badge-warning";
                badge.textContent = `⚠ ${st === "SKIPPED" ? "Skipped (Offline)" : "Partial"}`;
            } else if (st === "PENDING_APPROVAL") {
                badge.className = "badge badge-warning";
                badge.textContent = "⏳ Approval Needed";
            } else {
                badge.className = "badge badge-danger";
                badge.textContent = `✕ ${st}`;
            }

            header.appendChild(nameEl);
            header.appendChild(badge);
            item.appendChild(header);

            const meta = document.createElement("div");
            meta.className = "workflow-step-meta";
            meta.textContent = `Capability: ${step.capability} | Duration: ${(step.duration_seconds || 0).toFixed(2)}s`;
            item.appendChild(meta);

            if (step.data && typeof step.data === "object") {
                if (step.data.file_name) {
                    capturedFileName = step.data.file_name;
                }
            }

            if (step.error) {
                const errEl = document.createElement("div");
                errEl.className = "text-xs text-danger mt-1";
                errEl.textContent = `Error: ${step.error}`;
                item.appendChild(errEl);
            }

            stepsList.appendChild(item);
        });

        if (report.final_output && Object.keys(report.final_output).length > 0) {
            if (outputBox && outputPre) {
                outputBox.classList.remove("d-none");
                outputPre.textContent = JSON.stringify(report.final_output, null, 2);
            }
            if (report.final_output.file_name) {
                capturedFileName = report.final_output.file_name;
            }
        }

        if (capturedFileName && previewBox && previewImg) {
            previewBox.classList.remove("d-none");
            previewImg.classList.remove("d-none");
            if (captureErrorBox) captureErrorBox.classList.add("d-none");
            previewImg.src = `/api/captures/${encodeURIComponent(capturedFileName)}`;
            previewImg.alt = `Screenshot: ${capturedFileName}`;
            previewImg.onerror = () => {
                previewImg.classList.add("d-none");
                if (captureErrorBox) {
                    captureErrorBox.classList.remove("d-none");
                    captureErrorBox.textContent = `Failed loading preview for: ${capturedFileName}`;
                }
            };
            previewImg.onload = () => {
                previewImg.classList.remove("d-none");
                if (captureErrorBox) captureErrorBox.classList.add("d-none");
            };
        }

        loadApprovalsCount();
    }

    function renderConsumerSummaryCard(workflowId, report, summaryCard, captureSummaryBanner, captureErrorBox) {
        if (!report) return;
        const out = report.final_output || {};

        // 1. Device Health Snapshot
        if (workflowId === "device_health_snapshot" || out.health_summary) {
            const health = out.health_summary || {};
            const win = health.windows || {};
            const phone = health.phone || {};

            const winCpu = (win.cpu_percent !== undefined && win.cpu_percent !== null) ? `${win.cpu_percent}%` : "Unavailable";
            let winRam = "Unavailable";
            if (win.ram_used_mb && win.ram_total_mb) {
                const usedGb = (win.ram_used_mb / 1024).toFixed(1);
                const totalGb = (win.ram_total_mb / 1024).toFixed(1);
                winRam = `${usedGb} GB / ${totalGb} GB (${win.ram_percent || 0}%)`;
            } else if (win.ram_used_bytes && win.ram_total_bytes) {
                const usedGb = (win.ram_used_bytes / (1024 ** 3)).toFixed(1);
                const totalGb = (win.ram_total_bytes / (1024 ** 3)).toFixed(1);
                winRam = `${usedGb} GB / ${totalGb} GB (${win.ram_percent || 0}%)`;
            } else if (win.ram_percent !== undefined && win.ram_percent !== null) {
                winRam = `${win.ram_percent}%`;
            }
            const diskVal = (win.disk_percent !== undefined && win.disk_percent !== null) ? win.disk_percent : win.disk_c_percent;
            const winDisk = (diskVal !== undefined && diskVal !== null) ? `${diskVal}%` : "Available";
            const winHost = escapeHtml(win.hostname || "Windows Host");

            const phoneName = escapeHtml(phone.device_name || "Android Phone");
            const phoneBattery = (phone.battery_percent !== undefined && phone.battery_percent !== null) ? `${phone.battery_percent}%` : (phone.is_online ? "Unavailable" : "Offline");
            const phoneCharging = phone.charging ? "⚡ Charging" : (phone.is_online ? "🔋 Battery Power" : "Disconnected");
            const phoneTransport = escapeHtml(phone.transport || (phone.is_online ? "Wi-Fi LAN / USB ADB" : "Offline"));

            let phoneRam = "Unavailable";
            if (phone.ram_total_bytes && phone.ram_available_bytes) {
                const totalGb = (phone.ram_total_bytes / (1024 ** 3)).toFixed(1);
                const availGb = (phone.ram_available_bytes / (1024 ** 3)).toFixed(1);
                const usedGb = ((phone.ram_total_bytes - phone.ram_available_bytes) / (1024 ** 3)).toFixed(1);
                phoneRam = `${usedGb} GB / ${totalGb} GB (${availGb} GB free)`;
            }

            let phoneStorage = "Unavailable";
            if (phone.storage_total_bytes && phone.storage_available_bytes) {
                const totalGb = (phone.storage_total_bytes / (1024 ** 3)).toFixed(1);
                const availGb = (phone.storage_available_bytes / (1024 ** 3)).toFixed(1);
                phoneStorage = `${availGb} GB free / ${totalGb} GB`;
            }

            if (summaryCard) {
                summaryCard.classList.remove("d-none");
                summaryCard.innerHTML = `
                    <div class="device-health-grid">
                        <div class="device-health-box">
                            <div class="health-box-header">
                                <span>💻 Windows Laptop</span>
                                <span class="badge badge-success">Local Host</span>
                            </div>
                            <div class="health-stat-row">
                                <span class="health-stat-label">Hostname:</span>
                                <span class="health-stat-val">${winHost}</span>
                            </div>
                            <div class="health-stat-row">
                                <span class="health-stat-label">CPU Usage:</span>
                                <span class="health-stat-val">${winCpu}</span>
                            </div>
                            <div class="health-stat-row">
                                <span class="health-stat-label">RAM Usage:</span>
                                <span class="health-stat-val">${winRam}</span>
                            </div>
                            <div class="health-stat-row">
                                <span class="health-stat-label">Disk C:</span>
                                <span class="health-stat-val">${winDisk}</span>
                            </div>
                        </div>
                        <div class="device-health-box">
                            <div class="health-box-header">
                                <span>📱 Android Phone</span>
                                <span class="badge ${phone.is_online ? "badge-success" : "badge-warning"}">${phone.is_online ? "Online" : "Offline"}</span>
                            </div>
                            <div class="health-stat-row">
                                <span class="health-stat-label">Device:</span>
                                <span class="health-stat-val">${phoneName}</span>
                            </div>
                            <div class="health-stat-row">
                                <span class="health-stat-label">Battery Level:</span>
                                <span class="health-stat-val">${phoneBattery}</span>
                            </div>
                            <div class="health-stat-row">
                                <span class="health-stat-label">Power State:</span>
                                <span class="health-stat-val">${phoneCharging}</span>
                            </div>
                            <div class="health-stat-row">
                                <span class="health-stat-label">RAM (Phone):</span>
                                <span class="health-stat-val">${phoneRam}</span>
                            </div>
                            <div class="health-stat-row">
                                <span class="health-stat-label">Storage (Phone):</span>
                                <span class="health-stat-val">${phoneStorage}</span>
                            </div>
                            <div class="health-stat-row">
                                <span class="health-stat-label">Transport:</span>
                                <span class="health-stat-val">${phoneTransport}</span>
                            </div>
                        </div>
                    </div>
                `;
            }
        }

        // 2. Capture PC Screen
        if (workflowId === "pc_screenshot" || out.capture_summary) {
            const cap = out.capture_summary || {};
            const dims = escapeHtml(cap.dimensions || "1920 × 1080");
            const sizeKb = cap.file_size_bytes ? (cap.file_size_bytes / 1024).toFixed(1) : "N/A";
            if (captureSummaryBanner) {
                captureSummaryBanner.innerHTML = `<span>🖥️ <strong>Captured ${dims} · ${sizeKb} KB</strong></span>`;
            }
            if (summaryCard) {
                summaryCard.classList.remove("d-none");
                summaryCard.innerHTML = `
                    <div class="d-flex align-items-center justify-content-between">
                        <div class="clipboard-summary-banner">
                            <span>🖥️</span>
                            <span>Captured <strong>${dims}</strong> · ${sizeKb} KB</span>
                        </div>
                        <span class="badge badge-success">✓ Captured</span>
                    </div>
                `;
            }
        }

        // 3. Capture PC → Phone
        if (workflowId === "capture_pc_to_phone" || out.delivery_summary) {
            const del = out.delivery_summary || {};
            const dims = escapeHtml(del.dimensions || "1920 × 1080");
            const sizeKb = del.file_size_bytes ? (del.file_size_bytes / 1024).toFixed(1) : "N/A";
            const dest = escapeHtml(del.destination_device || "realme RMX5110");
            const durationTxt = del.duration_seconds ? ` · took ${del.duration_seconds.toFixed(2)}s` : "";
            if (captureSummaryBanner) {
                captureSummaryBanner.innerHTML = `<span>📲 <strong>Captured ${dims} · ${sizeKb} KB · Delivered to ${dest}${durationTxt}</strong></span>`;
            }
            if (summaryCard) {
                summaryCard.classList.remove("d-none");
                summaryCard.innerHTML = `
                    <div class="d-flex align-items-center justify-content-between">
                        <div class="clipboard-summary-banner">
                            <span>📲</span>
                            <span>Captured ${dims} (${sizeKb} KB) · Delivered to <strong>${dest}</strong>${durationTxt}</span>
                        </div>
                        <span class="badge badge-success">✓ Transferred</span>
                    </div>
                `;
            }
        }

        // 4. Sync Clipboard & Notify
        if (workflowId === "share_clipboard_and_notify" || out.sync_summary) {
            const sync = out.sync_summary || {};
            const dest = escapeHtml(sync.device_name || "realme RMX5110");
            if (summaryCard) {
                summaryCard.classList.remove("d-none");
                if (sync.is_empty) {
                    summaryCard.innerHTML = `
                        <div class="clipboard-summary-banner text-muted">
                            <span>📋</span>
                            <span>Clipboard is empty</span>
                        </div>
                    `;
                } else if (sync.status === "SUCCESS") {
                    summaryCard.innerHTML = `
                        <div class="d-flex align-items-center justify-content-between">
                            <div class="clipboard-summary-banner text-success">
                                <span>📋</span>
                                <span>Synced <strong>${sync.synced_chars}</strong> characters to <strong>${dest}</strong></span>
                            </div>
                            <span class="badge badge-success">✓ Synchronized</span>
                        </div>
                    `;
                } else {
                    summaryCard.innerHTML = `
                        <div class="clipboard-summary-banner text-warning">
                            <span>⚠️</span>
                            <span>Clipboard synchronization partial: Android peer offline</span>
                        </div>
                    `;
                }
            }
        }
    }

    // =========================================================================
    // Federation & Sharing (Phase 30)
    // =========================================================================

    let fedCountdownInterval = null;

    async function updateSessionIndicator() {
        const indicator = document.getElementById("topbar-session-indicator");
        const statusText = document.getElementById("topbar-session-text");
        if (!indicator) return;

        try {
            const data = await apiRequest("/api/federation/grants");
            if (data && data.success && Array.isArray(data.grants)) {
                const activeGrants = data.grants.filter(g => g.status === "ACTIVE");
                if (activeGrants.length > 0) {
                    indicator.style.display = "flex";
                    if (statusText) {
                        statusText.textContent = `${activeGrants.length} Active Federated Grant${activeGrants.length > 1 ? "s" : ""}`;
                    }
                    return;
                }
            }
            indicator.style.display = "none";
        } catch (e) {
            indicator.style.display = "none";
        }
    }

    async function loadFederationData() {
        const netIdEl = document.getElementById("fed-local-net-id");
        const netNameEl = document.getElementById("fed-local-net-name");
        const tbody = document.getElementById("fed-grants-tbody");
        if (!tbody) return;

        try {
            const res = await apiRequest("/api/federation/grants");
            if (res && res.success) {
                if (netIdEl) netIdEl.textContent = res.local_network_id || "Unknown";
                if (netNameEl) netNameEl.textContent = res.local_network_name || "My SNOW Network";

                const grants = Array.isArray(res.grants) ? res.grants : [];
                if (grants.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-state text-muted">No cross-network federation grants active.</td></tr>';
                    return;
                }

                tbody.innerHTML = "";
                grants.forEach(g => {
                    const tr = document.createElement("tr");

                    // 1. Network / Node
                    const tdNode = document.createElement("td");
                    const nameDiv = document.createElement("div");
                    nameDiv.style.fontWeight = "600";
                    nameDiv.textContent = g.network_name || "Remote Network";
                    const idDiv = document.createElement("div");
                    idDiv.className = "text-muted text-xs";
                    idDiv.textContent = `${g.peer_node_name || 'Coordinator'} (${(g.peer_node_id || '').substring(0, 8)}...)`;
                    tdNode.appendChild(nameDiv);
                    tdNode.appendChild(idDiv);
                    tr.appendChild(tdNode);

                    // 2. Direction
                    const tdDir = document.createElement("td");
                    const dirChip = document.createElement("span");
                    dirChip.className = "chip chip-xs " + (g.direction === "INBOUND" ? "chip-primary" : "chip-neutral");
                    dirChip.textContent = g.direction;
                    tdDir.appendChild(dirChip);
                    tr.appendChild(tdDir);

                    // 3. Status
                    const tdStat = document.createElement("td");
                    const statChip = document.createElement("span");
                    statChip.className = "chip chip-xs " + (g.status === "ACTIVE" ? "chip-success" : (g.status === "REVOKED" ? "chip-danger" : "chip-neutral"));
                    statChip.textContent = g.status;
                    tdStat.appendChild(statChip);
                    tr.appendChild(tdStat);

                    // 4. Capabilities
                    const tdCaps = document.createElement("td");
                    const caps = Array.isArray(g.allowed_capabilities) ? g.allowed_capabilities : [];
                    if (caps.length === 0) {
                        tdCaps.textContent = "None";
                    } else {
                        const capsDiv = document.createElement("div");
                        capsDiv.style.display = "flex";
                        capsDiv.style.flexWrap = "wrap";
                        capsDiv.style.gap = "0.2rem";
                        caps.forEach(c => {
                            const badge = document.createElement("span");
                            badge.className = "chip chip-xs";
                            badge.textContent = c;
                            capsDiv.appendChild(badge);
                        });
                        tdCaps.appendChild(capsDiv);
                    }
                    tr.appendChild(tdCaps);

                    // 5. Expiry
                    const tdExp = document.createElement("td");
                    tdExp.className = "text-xs text-muted";
                    tdExp.textContent = g.expires_timestamp ? new Date(g.expires_timestamp).toLocaleDateString() : "Never";
                    tr.appendChild(tdExp);

                    // 6. Action
                    const tdAct = document.createElement("td");
                    if (g.status === "ACTIVE") {
                        const btnRevoke = document.createElement("button");
                        btnRevoke.className = "btn btn-danger btn-xs";
                        btnRevoke.textContent = "Revoke";
                        btnRevoke.addEventListener("click", async () => {
                            if (confirm(`Revoke federation grant for network '${g.network_name}'?`)) {
                                const revRes = await apiRequest("/api/federation/revoke", "POST", { grant_id: g.grant_id });
                                if (revRes && revRes.success) {
                                    loadFederationData();
                                } else {
                                    alert("Failed to revoke grant: " + ((revRes && revRes.error) ? revRes.error : "Unknown error"));
                                }
                            }
                        });
                        tdAct.appendChild(btnRevoke);
                    } else {
                        tdAct.textContent = "—";
                    }
                    tr.appendChild(tdAct);

                    tbody.appendChild(tr);
                });
            }
        } catch (err) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-state text-danger">${escapeHtml(err.message)}</td></tr>`;
        }
        updateSessionIndicator();
    }

    function setupFederation() {
        const btnCreateInvite = document.getElementById("btn-fed-create-invite");
        if (btnCreateInvite) {
            btnCreateInvite.addEventListener("click", async () => {
                const ttlSelect = document.getElementById("fed-grant-ttl");
                const grantTtl = ttlSelect ? parseInt(ttlSelect.value, 10) : 86400;

                const capCheckboxes = document.querySelectorAll(".fed-cap-checkbox:checked");
                const caps = Array.from(capCheckboxes).map(cb => cb.value);

                btnCreateInvite.disabled = true;
                btnCreateInvite.textContent = "Generating...";

                const res = await apiRequest("/api/federation/invite", "POST", {
                    allowed_capabilities: caps,
                    grant_ttl_seconds: grantTtl,
                });

                btnCreateInvite.disabled = false;
                btnCreateInvite.textContent = "Generate 9-Digit Code";

                if (res && res.success && res.code) {
                    const resultBox = document.getElementById("fed-invite-result-box");
                    const codeDisplay = document.getElementById("fed-display-code");
                    const timerDisplay = document.getElementById("fed-invite-timer");

                    if (resultBox) resultBox.style.display = "block";
                    if (codeDisplay) codeDisplay.textContent = res.code;

                    // Start 10-minute countdown
                    if (fedCountdownInterval) clearInterval(fedCountdownInterval);
                    let remaining = res.ttl_seconds || 600;
                    fedCountdownInterval = setInterval(() => {
                        remaining--;
                        if (remaining <= 0) {
                            clearInterval(fedCountdownInterval);
                            if (timerDisplay) timerDisplay.textContent = "Code expired.";
                            if (codeDisplay) codeDisplay.style.color = "var(--text-muted)";
                        } else {
                            const mins = Math.floor(remaining / 60);
                            const secs = remaining % 60;
                            if (timerDisplay) {
                                timerDisplay.textContent = `Expires in: ${mins}:${secs < 10 ? '0' : ''}${secs}`;
                            }
                        }
                    }, 1000);
                } else {
                    alert("Failed generating invitation: " + ((res && res.error) ? res.error : "Unknown error"));
                }
            });
        }

        const btnCopyCode = document.getElementById("btn-fed-copy-code");
        if (btnCopyCode) {
            btnCopyCode.addEventListener("click", () => {
                const codeEl = document.getElementById("fed-display-code");
                if (codeEl) {
                    navigator.clipboard.writeText(codeEl.textContent.trim()).then(() => {
                        btnCopyCode.textContent = "Copied!";
                        setTimeout(() => { btnCopyCode.textContent = "📋 Copy Code"; }, 2000);
                    });
                }
            });
        }

        const btnAcceptCode = document.getElementById("btn-fed-accept-code");
        if (btnAcceptCode) {
            btnAcceptCode.addEventListener("click", async () => {
                const codeInput = document.getElementById("fed-input-code");
                const nameInput = document.getElementById("fed-peer-net-name");
                const statusDiv = document.getElementById("fed-accept-status");

                const code = (codeInput ? codeInput.value : "").trim();
                const netName = (nameInput ? nameInput.value : "").trim() || "Peer SNOW Network";

                if (!code) {
                    if (statusDiv) {
                        statusDiv.className = "mt-2 text-xs text-danger";
                        statusDiv.textContent = "Please enter a 9-digit code.";
                    }
                    return;
                }

                btnAcceptCode.disabled = true;
                btnAcceptCode.textContent = "Verifying...";
                if (statusDiv) statusDiv.textContent = "";

                const res = await apiRequest("/api/federation/accept", "POST", {
                    code: code,
                    peer_network_name: netName,
                });

                btnAcceptCode.disabled = false;
                btnAcceptCode.textContent = "Verify & Establish Federation";

                if (res && res.success) {
                    if (statusDiv) {
                        statusDiv.className = "mt-2 text-xs text-success";
                        statusDiv.textContent = `✓ Federation established with '${netName}'!`;
                    }
                    if (codeInput) codeInput.value = "";
                    loadFederationData();
                } else {
                    if (statusDiv) {
                        statusDiv.className = "mt-2 text-xs text-danger";
                        statusDiv.textContent = "Verification failed: " + ((res && res.error) ? res.error : "Invalid code");
                    }
                }
            });
        }

        const btnRefreshGrants = document.getElementById("btn-fed-refresh-grants");
        if (btnRefreshGrants) {
            btnRefreshGrants.addEventListener("click", loadFederationData);
        }

        const handleKillSwitch = async () => {
            if (confirm("🚨 EMERGENCY GLOBAL KILL SWITCH\n\nAre you sure you want to revoke ALL federation grants and terminate all remote access immediately?")) {
                const res = await apiRequest("/api/federation/kill-switch", "POST", {
                    reason: "Owner manual kill switch from Dashboard",
                });
                if (res && res.success) {
                    alert(`Global Kill Switch Activated!\n\nRevoked ${res.revoked_grants_count} grants and ${res.revoked_invites_count} pending invites.`);
                    loadFederationData();
                    refreshActiveTab();
                } else {
                    alert("Kill switch failed: " + ((res && res.error) ? res.error : "Unknown error"));
                }
            }
        };

        const btnNuclearKillSwitch = document.getElementById("btn-fed-nuclear-kill-switch");
        if (btnNuclearKillSwitch) {
            btnNuclearKillSwitch.addEventListener("click", handleKillSwitch);
        }

        const btnTopbarKillSwitch = document.getElementById("btn-topbar-kill-switch");
        if (btnTopbarKillSwitch) {
            btnTopbarKillSwitch.addEventListener("click", handleKillSwitch);
        }
    }

    // =========================================================================
    // 7. Dashboard Lifecycle Start
    // =========================================================================

    function startDashboard() {
        setupNavigation();
        setupMediaControls();
        setupShare();
        initTheme();

        // Specific Button Bindings
        const btnDevicePair = document.getElementById("btn-device-pair-qr");
        if (btnDevicePair) btnDevicePair.addEventListener("click", () => showPairingQr(true));

        const btnTierOwner = document.getElementById("btn-tier-owner");
        const btnTierPeer = document.getElementById("btn-tier-peer");
        if (btnTierOwner && btnTierPeer) {
            btnTierOwner.addEventListener("click", () => {
                selectedPairingTier = "owner";
                btnTierOwner.classList.add("active");
                btnTierPeer.classList.remove("active");
                showPairingQr(true);
            });
            btnTierPeer.addEventListener("click", () => {
                selectedPairingTier = "peer";
                btnTierPeer.classList.add("active");
                btnTierOwner.classList.remove("active");
                showPairingQr(true);
            });
        }

        const btnRegenPin = document.getElementById("btn-regenerate-pin");
        if (btnRegenPin) {
            btnRegenPin.addEventListener("click", () => showPairingQr(true));
        }

        // Copy LAN IP buttons
        document.querySelectorAll(".btn-copy-lan-ip").forEach(btn => {
            btn.addEventListener("click", () => {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(activeLanIp).then(() => {
                        const orig = btn.textContent;
                        btn.textContent = "✓ Copied!";
                        setTimeout(() => { btn.textContent = orig; }, 2000);
                    }).catch(() => {
                        prompt("Copy Desktop LAN Address:", activeLanIp);
                    });
                } else {
                    prompt("Copy Desktop LAN Address:", activeLanIp);
                }
            });
        });

        const btnCleanGhosts = document.getElementById("btn-clean-ghosts");
        if (btnCleanGhosts) btnCleanGhosts.addEventListener("click", cleanOfflineGhosts);

        const btnCloseQr = document.getElementById("btn-close-qr");
        if (btnCloseQr) {
            btnCloseQr.addEventListener("click", () => {
                const c = document.getElementById("qr-display-card");
                if (c) c.classList.add("hidden");
                if (pairingStateTimer) {
                    clearTimeout(pairingStateTimer);
                    pairingStateTimer = null;
                }
            });
        }

        const btnRefreshFiles = document.getElementById("btn-refresh-files");
        if (btnRefreshFiles) btnRefreshFiles.addEventListener("click", loadSafFiles);

        const chkShowHidden = document.getElementById("chk-show-hidden");
        if (chkShowHidden) {
            chkShowHidden.addEventListener("change", loadSafFiles);
        }

        document.querySelectorAll("#quick-nav-chips .chip-btn").forEach(chipBtn => {
            chipBtn.addEventListener("click", () => {
                currentSubpath = chipBtn.getAttribute("data-chip") || "";
                updateBreadcrumbs();
                loadSafFiles();
            });
        });

        const globalTargetSelect = document.getElementById("global-target-select");
        if (globalTargetSelect) {
            globalTargetSelect.addEventListener("change", () => {
                activeDeviceId = globalTargetSelect.value;
                const fileSelect = document.getElementById("files-device-select");
                if (fileSelect) fileSelect.value = activeDeviceId;
                populateGlobalTargetSelector(lastKnownPeerDevices);
                if (currentTab === "files") {
                    currentSubpath = "";
                    updateBreadcrumbs();
                    loadSafFiles();
                } else if (currentTab === "notifications") {
                    loadNotifications();
                } else if (currentTab === "apps") {
                    loadAndroidApps();
                }
            });
        }

        const fileSelect = document.getElementById("files-device-select");
        if (fileSelect) {
            fileSelect.addEventListener("change", () => {
                activeDeviceId = fileSelect.value;
                const globalSelect = document.getElementById("global-target-select");
                if (globalSelect) globalSelect.value = activeDeviceId;
                populateGlobalTargetSelector(lastKnownPeerDevices);
                currentSubpath = "";
                updateBreadcrumbs();
                loadSafFiles();
            });
        }

        const btnSaveNetName = document.getElementById("btn-save-network-name");
        if (btnSaveNetName) {
            btnSaveNetName.addEventListener("click", async () => {
                const input = document.getElementById("input-network-name");
                const statusEl = document.getElementById("network-name-status");
                const newName = (input ? input.value : "").trim();
                if (!newName) {
                    if (statusEl) {
                        statusEl.textContent = "Network name cannot be empty.";
                        statusEl.className = "text-xs text-danger mt-1 d-block";
                    }
                    return;
                }
                if (newName.length > 64) {
                    if (statusEl) {
                        statusEl.textContent = "Network name cannot exceed 64 characters.";
                        statusEl.className = "text-xs text-danger mt-1 d-block";
                    }
                    return;
                }
                btnSaveNetName.disabled = true;
                const res = await apiRequest("/api/network/identity", "POST", { network_name: newName });
                btnSaveNetName.disabled = false;
                if (res && res.success) {
                    if (statusEl) {
                        statusEl.textContent = "Network name saved!";
                        statusEl.className = "text-xs text-success mt-1 d-block";
                        setTimeout(() => { if (statusEl) statusEl.textContent = ""; }, 2500);
                    }
                    loadOverview();
                } else {
                    if (statusEl) {
                        statusEl.textContent = `Error: ${res ? (res.error || res.status) : 'Failed to save'}`;
                        statusEl.className = "text-xs text-danger mt-1 d-block";
                    }
                }
            });
        }

        const btnRefreshNotifs = document.getElementById("btn-refresh-notifs");
        if (btnRefreshNotifs) btnRefreshNotifs.addEventListener("click", loadNotifications);

        const btnRefreshApprovals = document.getElementById("btn-refresh-approvals");
        if (btnRefreshApprovals) btnRefreshApprovals.addEventListener("click", loadApprovalsList);

        const btnRefreshActivity = document.getElementById("btn-refresh-activity");
        if (btnRefreshActivity) btnRefreshActivity.addEventListener("click", loadActivityHistory);

        // Phase 23 & 28B Remote MCP Gateway Card Bindings
        const btnCopyMcp = document.getElementById("btn-copy-mcp-url");
        if (btnCopyMcp) {
            btnCopyMcp.addEventListener("click", () => {
                const epVal = document.getElementById("mcp-endpoint-val");
                const url = (epVal && epVal.textContent) ? epVal.textContent.trim() : "http://127.0.0.1:8771/mcp";
                if (url && url.startsWith("http")) {
                    navigator.clipboard.writeText(url).then(() => {
                        btnCopyMcp.textContent = "Copied!";
                        setTimeout(() => { btnCopyMcp.textContent = "Copy Local Endpoint"; }, 2000);
                    });
                }
            });
        }

        const btnCopyPublicMcp = document.getElementById("btn-copy-public-mcp-url");
        if (btnCopyPublicMcp) {
            btnCopyPublicMcp.addEventListener("click", () => {
                const epVal = document.getElementById("mcp-public-endpoint-val");
                const url = (epVal && epVal.textContent && epVal.textContent !== "Not Configured") ? epVal.textContent.trim() : "";
                if (url && url.startsWith("https://")) {
                    navigator.clipboard.writeText(url).then(() => {
                        btnCopyPublicMcp.textContent = "Copied!";
                        setTimeout(() => { btnCopyPublicMcp.textContent = "Copy Public Endpoint"; }, 2000);
                    });
                }
            });
        }

        const btnTestMcp = document.getElementById("btn-test-mcp-health");
        if (btnTestMcp) {
            btnTestMcp.addEventListener("click", () => loadMcpGatewayStatus());
        }

        const btnRefreshRelay = document.getElementById("btn-refresh-relay-status");
        if (btnRefreshRelay) {
            btnRefreshRelay.addEventListener("click", () => loadRelayStatus());
        }

        const relayInputs = [
            document.getElementById("relay-enable-toggle"),
            document.getElementById("relay-url-input"),
            document.getElementById("relay-group-input"),
            document.getElementById("relay-ticket-input"),
        ];
        relayInputs.forEach(el => {
            if (el) {
                el.addEventListener("input", () => { el.dataset.userEdited = "true"; });
                el.addEventListener("change", () => { el.dataset.userEdited = "true"; });
            }
        });

        const btnSaveRelay = document.getElementById("btn-save-relay-config");
        if (btnSaveRelay) {
            btnSaveRelay.addEventListener("click", async () => {
                const toggleEl = document.getElementById("relay-enable-toggle");
                const urlInput = document.getElementById("relay-url-input");
                const groupInput = document.getElementById("relay-group-input");
                const ticketInput = document.getElementById("relay-ticket-input");

                btnSaveRelay.disabled = true;
                btnSaveRelay.textContent = "Saving...";

                const payload = {
                    enabled: toggleEl ? toggleEl.checked : false,
                    relay_url: urlInput ? urlInput.value.trim() : "",
                    group_id: groupInput ? groupInput.value.trim() : "",
                    ticket: ticketInput ? ticketInput.value.trim() : "",
                };

                const res = await apiRequest("/api/relay/config", "POST", payload);
                btnSaveRelay.disabled = false;
                btnSaveRelay.textContent = "Save & Apply";

                if (res && res.success) {
                    alert("Relay configuration updated successfully.");
                    if (ticketInput) ticketInput.value = "";
                    if (toggleEl) delete toggleEl.dataset.userEdited;
                    if (urlInput) delete urlInput.dataset.userEdited;
                    if (groupInput) delete groupInput.dataset.userEdited;
                    loadRelayStatus();
                } else {
                    alert("Failed to update relay config: " + (res?.error || "Unknown error"));
                }
            });
        }

        const btnConnectPeer = document.getElementById("btn-connect-peer-submit");
        if (btnConnectPeer) {
            btnConnectPeer.addEventListener("click", async () => {
                const hostEl = document.getElementById("connect-peer-host");
                const portEl = document.getElementById("connect-peer-port");
                const pinEl = document.getElementById("connect-peer-pin");
                const fpEl = document.getElementById("connect-peer-fp");
                const statusEl = document.getElementById("connect-peer-status");

                const host = hostEl ? hostEl.value.trim() : "";
                const port = portEl ? parseInt(portEl.value.trim() || "8765", 10) : 8765;
                const pin = pinEl ? pinEl.value.trim() : "";
                const fingerprint = fpEl ? fpEl.value.trim() : "";

                if (!host) {
                    if (statusEl) {
                        statusEl.textContent = "Host is required.";
                        statusEl.className = "text-xs text-danger mt-1";
                    }
                    return;
                }

                btnConnectPeer.disabled = true;
                btnConnectPeer.textContent = "Connecting...";
                if (statusEl) {
                    statusEl.textContent = `Connecting to ${host}:${port}...`;
                    statusEl.className = "text-xs text-muted mt-1";
                }

                try {
                    const res = await apiRequest("/api/devices/connect-peer", "POST", {
                        host: host,
                        port: port,
                        pin: pin,
                        expected_fingerprint: fingerprint,
                    });
                    if (res && res.success) {
                        if (statusEl) {
                            statusEl.textContent = `Connected successfully! Peer ID: ${res.data?.remote_device_id || 'peer'}`;
                            statusEl.className = "text-xs text-success mt-1";
                        }
                        if (pinEl) pinEl.value = "";
                        loadDevices();
                    } else {
                        if (statusEl) {
                            statusEl.textContent = `Connection failed: ${res?.error || res?.status || 'Unknown error'}`;
                            statusEl.className = "text-xs text-danger mt-1";
                        }
                    }
                } catch (err) {
                    if (statusEl) {
                        statusEl.textContent = `Connection error: ${err}`;
                        statusEl.className = "text-xs text-danger mt-1";
                    }
                } finally {
                    btnConnectPeer.disabled = false;
                    btnConnectPeer.textContent = "Connect to Peer";
                }
            });
        }

        const btnJumpApprovals = document.getElementById("btn-jump-approvals");
        if (btnJumpApprovals) {
            btnJumpApprovals.addEventListener("click", () => switchTab("approvals"));
        }

        // Live screen sharing stop button
        const btnStopScreen = document.getElementById("btn-stop-screen-share");
        if (btnStopScreen) {
            btnStopScreen.addEventListener("click", async () => {
                btnStopScreen.disabled = true;
                btnStopScreen.textContent = "Stopping...";
                await apiRequest("/api/screen/stop", "POST");
                btnStopScreen.disabled = false;
                btnStopScreen.textContent = "Stop Sharing";
                pollScreenFrame();
            });
        }

        // Document visibility handling for frame polling
        document.addEventListener("visibilitychange", () => {
            if (!document.hidden && currentTab === "overview" && !screenPollActive) {
                startScreenPoll();
            }
        });

        // =====================================================================
        // Phase 26B: Clipboard Hub & Remote Apps Bindings
        // =====================================================================

        const bindHubAction = (btnId, handler) => {
            const btn = document.getElementById(btnId);
            if (btn) btn.addEventListener("click", handler);
        };

        const handleCapPcClip = async () => {
            const statusEl = document.getElementById("hub-overview-status");
            if (statusEl) statusEl.textContent = "Capturing Windows clipboard...";
            const res = await apiRequest("/api/clipboard/buffer/capture_pc", "POST");
            if (statusEl) {
                if (res && res.success) {
                    statusEl.textContent = "Captured Windows clipboard to shared buffer!";
                    statusEl.className = "hub-status-text text-sm text-success mt-2";
                } else {
                    statusEl.textContent = `Capture failed: ${res ? (res.error || res.status) : 'Empty or unavailable'}`;
                    statusEl.className = "hub-status-text text-sm text-danger mt-2";
                }
            }
            loadClipboardBuffer();
        };

        const handlePullPhone = async () => {
            const statusEl = document.getElementById("hub-overview-status");
            if (statusEl) statusEl.textContent = "Pulling clipboard from phone...";
            const res = await apiRequest("/api/clipboard/buffer/pull_phone", "POST");
            if (statusEl) {
                if (res && res.success) {
                    statusEl.textContent = "Pulled clipboard from Android phone!";
                    statusEl.className = "hub-status-text text-sm text-success mt-2";
                } else {
                    statusEl.textContent = `Pull failed: ${res ? (res.error || res.status) : 'Phone offline or foreground required'}`;
                    statusEl.className = "hub-status-text text-sm text-danger mt-2";
                }
            }
            loadClipboardBuffer();
        };

        const handleApplyLatestPc = async () => {
            const statusEl = document.getElementById("hub-overview-status");
            if (statusEl) statusEl.textContent = "Applying latest buffer item to PC...";
            const res = await apiRequest("/api/clipboard/buffer/apply", "POST", { target: "pc" });
            if (statusEl) {
                if (res && res.success) {
                    statusEl.textContent = "Applied latest item to Windows clipboard!";
                    statusEl.className = "hub-status-text text-sm text-success mt-2";
                } else {
                    statusEl.textContent = `Apply failed: ${res ? (res.error || res.status) : 'Buffer empty'}`;
                    statusEl.className = "hub-status-text text-sm text-danger mt-2";
                }
            }
        };

        const handleClearUnpinned = async () => {
            await apiRequest("/api/clipboard/buffer/clear", "POST");
            loadClipboardBuffer();
        };

        bindHubAction("btn-hub-cap-pc-clip", handleCapPcClip);
        bindHubAction("btn-hub-tab-cap-pc", handleCapPcClip);
        bindHubAction("btn-hub-pull-phone", handlePullPhone);
        bindHubAction("btn-hub-tab-pull-phone", handlePullPhone);
        bindHubAction("btn-hub-apply-pc", handleApplyLatestPc);
        bindHubAction("btn-hub-tab-apply-pc", handleApplyLatestPc);
        bindHubAction("btn-hub-clear-unpinned", handleClearUnpinned);
        bindHubAction("btn-clipboard-clear-unpinned", handleClearUnpinned);
        bindHubAction("btn-clipboard-refresh", () => loadClipboardBuffer());

        bindHubAction("btn-hub-cap-screen", async () => {
            const res = await apiRequest("/api/workflows/run", "POST", { workflow_id: "capture_pc_to_phone" });
            loadClipboardBuffer();
        });
        bindHubAction("btn-hub-tab-cap-screen", async () => {
            const res = await apiRequest("/api/workflows/run", "POST", { workflow_id: "capture_pc_to_phone" });
            loadClipboardBuffer();
        });

        // Add custom text to buffer
        bindHubAction("btn-clipboard-add-text", async () => {
            const txtArea = document.getElementById("input-clipboard-text");
            const pinChk = document.getElementById("check-clipboard-pin");
            const statusEl = document.getElementById("clipboard-add-status");
            const text = (txtArea ? txtArea.value : "").trim();
            if (!text) return;
            const isPinned = pinChk ? pinChk.checked : false;

            const res = await apiRequest("/api/clipboard/buffer/add", "POST", { text: text, is_pinned: isPinned });
            if (res && res.success) {
                if (txtArea) txtArea.value = "";
                if (pinChk) pinChk.checked = false;
                if (statusEl) {
                    statusEl.textContent = "Added to shared buffer!";
                    statusEl.className = "text-sm text-success mt-2";
                    setTimeout(() => { statusEl.textContent = ""; }, 2500);
                }
                loadClipboardBuffer();
            } else {
                if (statusEl) {
                    statusEl.textContent = `Failed: ${res ? (res.error || res.status) : 'Unknown error'}`;
                    statusEl.className = "text-sm text-danger mt-2";
                }
            }
        });

        // Windows Apps launcher buttons
        document.querySelectorAll("[data-win-app]").forEach(btn => {
            btn.addEventListener("click", async () => {
                const appName = btn.getAttribute("data-win-app");
                const statusEl = document.getElementById("windows-app-status");
                if (statusEl) statusEl.textContent = `Launching ${appName}...`;
                const res = await apiRequest("/api/apps/windows/launch", "POST", { app_name: appName });
                if (statusEl) {
                    if (res && res.success) {
                        statusEl.textContent = `Launched ${appName} successfully.`;
                        statusEl.className = "text-sm text-success mt-2";
                    } else {
                        statusEl.textContent = `Launch failed: ${res ? (res.error || res.status) : 'Unknown error'}`;
                        statusEl.className = "text-sm text-danger mt-2";
                    }
                }
            });
        });

        bindHubAction("btn-apps-refresh-android", () => loadAndroidApps());

        // Guided Consumer Onboarding Wizard (Phase 29)
        let wizardStep = 1;

        async function checkOnboardingStatus() {
            try {
                const data = await apiRequest("/api/onboarding/status");
                if (data && data.success && !data.completed) {
                    openOnboardingWizard(data.network_name || "My SNOW Network");
                }
            } catch (e) {
                console.debug("Failed checking onboarding status:", e);
            }
        }

        function setWizardStep(step) {
            wizardStep = step;
            const s1 = document.getElementById("wizard-step-1");
            const s2 = document.getElementById("wizard-step-2");
            const s3 = document.getElementById("wizard-step-3");
            const t1 = document.getElementById("step-tab-1");
            const t2 = document.getElementById("step-tab-2");
            const t3 = document.getElementById("step-tab-3");

            if (s1) s1.style.display = step === 1 ? "block" : "none";
            if (s2) s2.style.display = step === 2 ? "block" : "none";
            if (s3) s3.style.display = step === 3 ? "block" : "none";

            if (t1) t1.style.color = step === 1 ? "var(--accent-primary)" : "var(--text-muted)";
            if (t2) t2.style.color = step === 2 ? "var(--accent-primary)" : "var(--text-muted)";
            if (t3) t3.style.color = step === 3 ? "var(--accent-primary)" : "var(--text-muted)";

            if (step === 2) {
                loadWizardPairing();
            }
        }

        async function loadWizardPairing() {
            const qrImg = document.getElementById("wizard-qr-img");
            const pinDisplay = document.getElementById("wizard-pin-display");
            const statusBox = document.getElementById("wizard-device-status-box");

            try {
                const res = await apiRequest("/api/pair/qr", "POST", { trust_tier: "owner" });
                const svgContent = res?.svg || res?.qr_svg || res?.data?.svg;
                const pin = res?.data?.pin || res?.pin;
                if (res && res.success && svgContent) {
                    if (qrImg) qrImg.src = "data:image/svg+xml;utf8," + encodeURIComponent(svgContent);
                    if (pinDisplay) pinDisplay.textContent = pin || "------";
                } else {
                    const st = await apiRequest("/api/pair/state");
                    if (st && st.data) {
                        if (pinDisplay) pinDisplay.textContent = st.data.owner_pin || st.data.pin || "------";
                    }
                }

                const devData = await apiRequest("/api/devices");
                const devList = (devData && Array.isArray(devData.devices)) ? devData.devices :
                    ((devData && devData.data && Array.isArray(devData.data.devices)) ? devData.data.devices : []);
                const count = devList.filter(d => !isLocalNode(d) && d.is_connected).length;
                if (statusBox) {
                    if (count > 0) {
                        statusBox.textContent = `✓ ${count} device(s) connected! Ready for AI capabilities.`;
                        statusBox.style.color = "var(--success-color)";
                    } else {
                        statusBox.textContent = "Waiting for phone to scan QR code or enter PIN...";
                        statusBox.style.color = "var(--text-muted)";
                    }
                }
            } catch (e) {
                console.error("Wizard pairing load failed:", e);
            }
        }

        function openOnboardingWizard(defaultNetworkName = "My SNOW Network") {
            const overlay = document.getElementById("onboarding-overlay");
            const inputName = document.getElementById("wizard-network-name");
            if (inputName && defaultNetworkName) {
                inputName.value = defaultNetworkName;
            }
            setWizardStep(1);
            if (overlay) overlay.style.display = "flex";
        }

        function closeOnboardingWizard() {
            const overlay = document.getElementById("onboarding-overlay");
            if (overlay) overlay.style.display = "none";
        }

        function setupOnboardingWizard() {
            const navWizard = document.getElementById("nav-btn-wizard");
            if (navWizard) {
                navWizard.addEventListener("click", () => {
                    openOnboardingWizard();
                });
            }

            const btnSkip = document.getElementById("btn-skip-onboarding");
            if (btnSkip) {
                btnSkip.addEventListener("click", async () => {
                    await apiRequest("/api/onboarding/complete", "POST", { network_name: "My SNOW Network" });
                    closeOnboardingWizard();
                    refreshActiveTab();
                });
            }

            const btnNext1 = document.getElementById("btn-wizard-next-1");
            if (btnNext1) {
                btnNext1.addEventListener("click", async () => {
                    const nameInput = document.getElementById("wizard-network-name");
                    const netName = (nameInput ? nameInput.value : "").trim() || "My SNOW Network";
                    await apiRequest("/api/network/identity", "POST", { network_name: netName });
                    setWizardStep(2);
                });
            }

            const btnBack2 = document.getElementById("btn-wizard-back-2");
            if (btnBack2) {
                btnBack2.addEventListener("click", () => setWizardStep(1));
            }
            const btnNext2 = document.getElementById("btn-wizard-next-2");
            if (btnNext2) {
                btnNext2.addEventListener("click", () => setWizardStep(3));
            }

            const btnBack3 = document.getElementById("btn-wizard-back-3");
            if (btnBack3) {
                btnBack3.addEventListener("click", () => setWizardStep(2));
            }
            const btnFinish = document.getElementById("btn-wizard-finish");
            if (btnFinish) {
                btnFinish.addEventListener("click", async () => {
                    const nameInput = document.getElementById("wizard-network-name");
                    const netName = (nameInput ? nameInput.value : "").trim() || "My SNOW Network";
                    await apiRequest("/api/onboarding/complete", "POST", { network_name: netName });
                    closeOnboardingWizard();
                    refreshActiveTab();
                });
            }

            const btnCopyCmd = document.getElementById("btn-wizard-copy-cmd");
            if (btnCopyCmd) {
                btnCopyCmd.addEventListener("click", () => {
                    const cmdEl = document.getElementById("wizard-cli-setup-cmd");
                    const text = cmdEl ? cmdEl.textContent : "snow setup";
                    navigator.clipboard.writeText(text).then(() => {
                        btnCopyCmd.textContent = "Copied!";
                        setTimeout(() => { btnCopyCmd.textContent = "Copy"; }, 2000);
                    });
                });
            }
        }

        setupWorkflows();
        setupOnboardingWizard();
        checkOnboardingStatus();
        setupFederation();

        // Initial Data Load
        refreshActiveTab();
        updateSessionIndicator();

        // Background Periodic Poller (every 4 seconds, pauses when tab is hidden)
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(() => {
            if (document.hidden) return;
            loadSystemStatus();
            loadApprovalsCount();
            updateSessionIndicator();
            if (currentTab === "overview") {
                loadOverview();
            } else if (currentTab === "devices") {
                loadDevices();
            } else if (currentTab === "notifications") {
                loadNotifications();
            } else if (currentTab === "clipboard") {
                loadClipboardBuffer();
            } else if (currentTab === "federation") {
                loadFederationData();
            } else if (currentTab === "settings") {
                loadRelayStatus();
                loadMcpGatewayStatus();
                loadNetworkIdentity();
            }
        }, 4000);

        // Resume / immediately refresh when page visibility changes to visible
        document.addEventListener("visibilitychange", () => {
            if (!document.hidden) {
                loadSystemStatus();
                loadApprovalsCount();
                updateSessionIndicator();
                refreshActiveTab();
            }
        });
    }

    // Boot entry point
    document.addEventListener("DOMContentLoaded", initSession);
})();
