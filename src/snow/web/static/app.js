/**
 * SNOW V3 — Vanilla Web Dashboard Client
 * 
 * Secure, zero-dependency local dashboard interface for SNOW Core.
 * Communicates with http://127.0.0.1:8769 over authenticated REST endpoints.
 */

(function () {
    "use strict";

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
                } catch (_) {}
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
            settings: "Settings & Diagnostics",
        };
        activeTabTitle.textContent = titleMap[tabName] || "Dashboard";

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

        btnGlobalRefresh.addEventListener("click", () => {
            refreshActiveTab();
        });
    }

    function refreshActiveTab() {
        loadSystemStatus();
        loadApprovalsCount();

        if (currentTab === "overview") {
            loadOverview();
        } else if (currentTab === "devices") {
            loadDevices();
        } else if (currentTab === "files") {
            loadSafFiles();
        } else if (currentTab === "notifications") {
            loadNotifications();
        } else if (currentTab === "approvals") {
            loadApprovalsList();
        } else if (currentTab === "activity") {
            loadActivityHistory();
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

    async function loadApprovalsCount() {
        const data = await apiRequest("/api/approvals");
        const approvals = (data && Array.isArray(data.requests)) ? data.requests : ((data && Array.isArray(data.approvals)) ? data.approvals : ((data && data.data && Array.isArray(data.data.requests)) ? data.data.requests : []));
        const count = (data && data.success) ? approvals.length : 0;
        const badge = document.getElementById("badge-approvals");
        const statApprovals = document.getElementById("stat-pending-approvals");
        if (badge) badge.textContent = count.toString();
        if (statApprovals) statApprovals.textContent = count.toString();
    }

    function isLocalNode(dev) {
        return dev.transport === "local" || dev.is_local === true || dev.platform === "windows" || dev.device_id === "local" || dev.device_id === "desktop-core";
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
            const connected = peerDevices.filter(d => d.is_connected);
            activeCount = connected.length;
            if (activeCount > 0) {
                const tr = connected[0].transport || "unknown";
                if (tr === "wifi_lan") {
                    primaryTransport = "🟢 Wi-Fi LAN";
                    chipClass = "chip-wifi";
                } else if (tr === "usb_adb") {
                    primaryTransport = "🔌 USB Cable (ADB)";
                    chipClass = "chip-usb";
                } else if (tr === "loopback") {
                    primaryTransport = "🔁 Loopback";
                    chipClass = "chip-loopback";
                } else {
                    primaryTransport = "⚪ " + tr;
                    chipClass = "chip-neutral";
                }
            }
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
            empty.innerHTML = `⚠️ <strong>Desktop Core Offline</strong><br><small class="text-muted">${errMsg}<br>Please launch the core daemon in terminal with <code>python -m snow daemon start</code> or <code>snow</code>, then refresh.</small>`;
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
            if (!dev.is_connected) {
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

            // Populate file selector option
            if (fileDevSelect && dev.is_connected) {
                const opt = document.createElement("option");
                opt.value = dev.device_id;
                opt.textContent = `${dev.device_name || dev.device_id} (${trChip.textContent})`;
                fileDevSelect.appendChild(opt);
                if (!activeDeviceId) {
                    activeDeviceId = dev.device_id;
                    opt.selected = true;
                }
            }
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
                svgBox.innerHTML = `<div class="empty-state text-danger">${errMsg}</div>`;
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
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state text-danger">${errorText}</td></tr>`;
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

        feed.innerHTML = '<div class="empty-state"><div class="spinner"></div> Querying authorization queue...</div>';
        const res = await apiRequest("/api/approvals");
        feed.innerHTML = "";

        const requests = (res && Array.isArray(res.requests)) ? res.requests : ((res && Array.isArray(res.approvals)) ? res.approvals : ((res && res.data && Array.isArray(res.data.requests)) ? res.data.requests : []));
        if (!res || !res.success || requests.length === 0) {
            const empty = document.createElement("div");
            empty.className = "empty-state";
            empty.textContent = "No pending approval requests. System is secure.";
            feed.appendChild(empty);
            return;
        }

        requests.forEach(req => {
            const card = document.createElement("div");
            card.className = "approval-card";

            const header = document.createElement("div");
            header.className = "approval-header";

            const opName = document.createElement("h4");
            opName.textContent = req.action || req.operation || "Sensitive Operation";

            const reqId = document.createElement("span");
            reqId.className = "text-xs text-muted";
            reqId.textContent = req.request_id;

            header.appendChild(opName);
            header.appendChild(reqId);

            const details = document.createElement("div");
            details.className = "approval-details";
            details.appendChild(createDetailRow("Principal:", req.principal || "AI Assistant"));
            details.appendChild(createDetailRow("Target:", req.target_device || "Windows Host"));
            details.appendChild(createDetailRow("Risk Level:", req.risk_level || "standard"));
            if (req.reason) details.appendChild(createDetailRow("Reason:", req.reason));
            details.appendChild(createDetailRow("Params:", JSON.stringify(req.params || {})));

            const actions = document.createElement("div");
            actions.className = "approval-actions mt-3";

            const btnApprove = document.createElement("button");
            btnApprove.className = "btn-success";
            btnApprove.textContent = "Approve Operation";
            btnApprove.addEventListener("click", async () => {
                btnApprove.disabled = true;
                const r = await apiRequest("/api/approvals/resolve", "POST", {
                    request_id: req.request_id,
                    decision: "approve",
                });
                if (r && r.success) {
                    card.remove();
                    loadApprovalsCount();
                } else {
                    alert("Approval failed: " + (r.error || r.status));
                    btnApprove.disabled = false;
                }
            });

            const btnDeny = document.createElement("button");
            btnDeny.className = "btn-danger";
            btnDeny.textContent = "Deny";
            btnDeny.addEventListener("click", async () => {
                btnDeny.disabled = true;
                const r = await apiRequest("/api/approvals/resolve", "POST", {
                    request_id: req.request_id,
                    decision: "deny",
                });
                if (r && r.success) {
                    card.remove();
                    loadApprovalsCount();
                } else {
                    alert("Denial failed: " + (r.error || r.status));
                    btnDeny.disabled = false;
                }
            });

            actions.appendChild(btnApprove);
            actions.appendChild(btnDeny);

            card.appendChild(header);
            card.appendChild(details);
            card.appendChild(actions);
            feed.appendChild(card);
        });
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

        const fileSelect = document.getElementById("files-device-select");
        if (fileSelect) {
            fileSelect.addEventListener("change", () => {
                activeDeviceId = fileSelect.value;
                currentSubpath = "";
                updateBreadcrumbs();
                loadSafFiles();
            });
        }

        const btnRefreshNotifs = document.getElementById("btn-refresh-notifs");
        if (btnRefreshNotifs) btnRefreshNotifs.addEventListener("click", loadNotifications);

        const btnRefreshApprovals = document.getElementById("btn-refresh-approvals");
        if (btnRefreshApprovals) btnRefreshApprovals.addEventListener("click", loadApprovalsList);

        const btnRefreshActivity = document.getElementById("btn-refresh-activity");
        if (btnRefreshActivity) btnRefreshActivity.addEventListener("click", loadActivityHistory);

        // Initial Data Load
        refreshActiveTab();

        // Background Periodic Poller (every 4 seconds)
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(() => {
            loadSystemStatus();
            loadApprovalsCount();
            if (currentTab === "overview") {
                loadOverview();
            } else if (currentTab === "devices") {
                loadDevices();
            } else if (currentTab === "notifications") {
                loadNotifications();
            }
        }, 4000);
    }

    // Boot entry point
    document.addEventListener("DOMContentLoaded", initSession);
})();
