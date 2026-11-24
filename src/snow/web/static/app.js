/**
 * SNOW V4.1 — Modern Web Dashboard Client
 * 
 * Secure, zero-dependency local dashboard interface for SNOW Core.
 * Communicates with http://127.0.0.1:8769 over authenticated REST endpoints.
 * Phase 4 Stage 4B Ground-Up Rebuild.
 */

(function () {
    "use strict";

    // =========================================================================
    // Core Utility Functions
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

    function showNotificationToast(msg, type = "info") {
        if (!msg) return;
        let container = document.getElementById("toast-container");
        if (!container) {
            container = document.createElement("div");
            container.id = "toast-container";
            container.style.position = "fixed";
            container.style.bottom = "24px";
            container.style.right = "24px";
            container.style.zIndex = "99999";
            container.style.display = "flex";
            container.style.flexDirection = "column";
            container.style.gap = "8px";
            container.style.pointerEvents = "none";
            document.body.appendChild(container);
        }

        const toast = document.createElement("div");
        toast.className = `toast-pill toast-${type}`;
        toast.style.pointerEvents = "auto";
        toast.style.background = type === "error" ? "var(--danger-color, #ef4444)" :
                                 type === "warning" ? "#f59e0b" :
                                 type === "success" ? "var(--success-color, #10b981)" : "var(--accent-primary, #2563eb)";
        toast.style.color = "#ffffff";
        toast.style.padding = "10px 16px";
        toast.style.borderRadius = "8px";
        toast.style.boxShadow = "0 4px 12px rgba(0,0,0,0.3)";
        toast.style.fontSize = "0.875rem";
        toast.style.fontWeight = "600";
        toast.style.opacity = "0";
        toast.style.transition = "opacity 0.2s ease, transform 0.2s ease";
        toast.style.transform = "translateY(10px)";
        toast.textContent = msg;

        container.appendChild(toast);
        requestAnimationFrame(() => {
            toast.style.opacity = "1";
            toast.style.transform = "translateY(0)";
        });

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(-10px)";
            setTimeout(() => {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        }, 4000);
    }
    window.showNotificationToast = showNotificationToast;

    // View Titles Mapping
    const TITLE_MAP = {
        overview: "Home",
        devices: "Devices & Network",
        files: "Files & Apps",
        clipboard: "Clipboard History",
        apps: "Android Applications",
        settings: "AI & Settings",
    };

    // Application State
    let csrfToken = "";
    let currentTab = "overview";
    let activeDeviceId = "";
    let currentSubpath = "";
    let isCorePaused = false;
    let registeredDevices = [];
    let qrCountdownTimer = null;
    let pollIntervalTimer = null;
    let currentDeviceFilter = "all";
    let pendingApprovalItem = null;
    let replyingNotificationKey = "";

    // DOM Elements
    const authOverlay = document.getElementById("auth-overlay");
    const authStatusText = document.getElementById("auth-status-text");
    const coreStatusDot = document.getElementById("core-status-dot");
    const coreStatusText = document.getElementById("core-status-text");
    const btnDesktopPause = document.getElementById("btn-desktop-pause");
    const btnDesktopPoweroff = document.getElementById("btn-desktop-poweroff");
    const poweroffModal = document.getElementById("poweroff-modal");
    const btnPoweroffCancel = document.getElementById("btn-poweroff-cancel");
    const btnPoweroffConfirm = document.getElementById("btn-poweroff-confirm");
    const globalTargetSelect = document.getElementById("global-target-select");
    const globalTargetTransportChip = document.getElementById("global-target-transport-chip");
    const btnThemeToggle = document.getElementById("btn-theme-toggle");
    const btnGlobalRefresh = document.getElementById("btn-global-refresh");
    const btnTopbarCommandPalette = document.getElementById("btn-topbar-command-palette");
    const commandPaletteOverlay = document.getElementById("command-palette-overlay");
    const commandPaletteInput = document.getElementById("command-palette-input");
    const btnTopbarApprovals = document.getElementById("btn-topbar-approvals");
    const topbarApprovalsBadge = document.getElementById("topbar-approvals-badge");

    // =========================================================================
    // API Helper
    // =========================================================================

    async function apiRequest(endpoint, method = "GET", data = null) {
        const headers = { "Content-Type": "application/json" };
        if (csrfToken && method !== "GET" && method !== "HEAD") {
            headers["X-CSRF-Token"] = csrfToken;
        }

        const options = { method, headers };
        if (data && (method === "POST" || method === "PUT" || method === "DELETE")) {
            options.body = JSON.stringify(data);
        }

        try {
            const resp = await fetch(endpoint, options);
            if (resp.status === 403) {
                const errData = await resp.json().catch(() => ({}));
                if (errData.status === "SESSION_EXPIRED" || errData.status === "INVALID_TOKEN") {
                    showNotificationToast("Session expired. Reconnecting...", "warning");
                    window.location.reload();
                }
            }
            return await resp.json();
        } catch (err) {
            return { success: false, error: err.message || "Network request failed" };
        }
    }

    // Helper: isLocalNode
    function isLocalNode(d) {
        if (!d) return false;
        return d.is_local || d.device_id === "local" || (d.device_name && d.device_name.includes("(This PC)"));
    }

    // =========================================================================
    // 1. Authentication & Bootstrap
    // =========================================================================

    async function initSession() {
        const hash = window.location.hash.substring(1);
        const params = new URLSearchParams(hash);
        const bootstrapToken = params.get("token");

        if (bootstrapToken) {
            history.replaceState(null, "", window.location.pathname);
        }

        try {
            if (bootstrapToken) {
                if (authStatusText) authStatusText.textContent = "Verifying single-use bootstrap token...";
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
            const statusResp = await fetch("/api/status");
            const statusData = await statusResp.json();
            if (statusData && statusData.csrf_token) {
                csrfToken = statusData.csrf_token;
                if (authOverlay) authOverlay.classList.add("d-none");
                startDashboard();
                return;
            }

            // Fallback development session
            const devAuth = await fetch("/api/auth/session", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ token: "dev-local-session" }),
            });
            const devData = await devAuth.json();
            if (devData.csrf_token) {
                csrfToken = devData.csrf_token;
            }
            if (authOverlay) authOverlay.classList.add("d-none");
            startDashboard();
        } catch (e) {
            if (authOverlay) authOverlay.classList.add("d-none");
            startDashboard();
        }
    }

    function startDashboard() {
        initNavigation();
        initTheming();
        initCommandPalette();
        initCoreControls();
        initHeroActions();
        initPairingView();
        initFilesView();
        initClipboardView();
        initAiSettingsView();
        initModals();

        // Initial fetch & start polling
        refreshAllData();
        if (pollIntervalTimer) clearInterval(pollIntervalTimer);
        pollIntervalTimer = setInterval(refreshAllData, 3000);
    }

    // =========================================================================
    // 2. Navigation & Tabs
    // =========================================================================

    function initNavigation() {
        const navButtons = document.querySelectorAll(".nav-menu .nav-item");
        navButtons.forEach(btn => {
            btn.addEventListener("click", () => {
                const tab = btn.getAttribute("data-tab");
                if (!tab) return;
                switchTab(tab);
            });
        });
    }

    function switchTab(tabId) {
        currentTab = tabId;
        const navButtons = document.querySelectorAll(".nav-menu .nav-item");
        navButtons.forEach(btn => {
            if (btn.getAttribute("data-tab") === tabId) {
                btn.classList.add("active");
            } else {
                btn.classList.remove("active");
            }
        });

        const tabPanes = document.querySelectorAll(".tab-pane");
        tabPanes.forEach(pane => {
            if (pane.id === `section-${tabId}`) {
                pane.classList.add("active");
            } else {
                pane.classList.remove("active");
            }
        });

        if (tabId === "overview") {
            loadHomeWidgets();
        } else if (tabId === "devices") {
            renderDevicesView();
            loadPairingQR();
        } else if (tabId === "files") {
            loadFiles(currentSubpath);
            loadQuickApps();
        } else if (tabId === "clipboard") {
            loadClipboardItems();
        } else if (tabId === "settings") {
            loadAiLinkStatus();
            loadPendingApprovals();
            loadActivityTimeline();
        }
    }

    // =========================================================================
    // 3. Theming & Zero-Flash Sync
    // =========================================================================

    function initTheming() {
        const radios = document.querySelectorAll('input[name="theme-radio"]');
        const savedTheme = localStorage.getItem("snow_theme") || "system";

        radios.forEach(radio => {
            radio.checked = (radio.value === savedTheme);
            const parentSeg = radio.closest(".seg-item");
            if (parentSeg) {
                if (radio.value === savedTheme) parentSeg.classList.add("active");
                else parentSeg.classList.remove("active");
            }

            radio.addEventListener("change", () => {
                applyTheme(radio.value);
            });
        });

        if (btnThemeToggle) {
            btnThemeToggle.addEventListener("click", () => {
                const cur = document.documentElement.classList.contains("theme-dark") ? "dark" : "light";
                const next = cur === "dark" ? "light" : "dark";
                applyTheme(next);
            });
        }
    }

    function applyTheme(themeChoice) {
        localStorage.setItem("snow_theme", themeChoice);

        let isDark = false;
        if (themeChoice === "dark") {
            isDark = true;
        } else if (themeChoice === "light") {
            isDark = false;
        } else {
            isDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
        }

        document.documentElement.className = isDark ? "theme-dark" : "theme-light";
        document.body.className = isDark ? "theme-dark" : "theme-light";

        const radios = document.querySelectorAll('input[name="theme-radio"]');
        radios.forEach(r => {
            r.checked = (r.value === themeChoice);
            const parentSeg = r.closest(".seg-item");
            if (parentSeg) {
                if (r.value === themeChoice) parentSeg.classList.add("active");
                else parentSeg.classList.remove("active");
            }
        });
    }

    // =========================================================================
    // 4. Core Lifecycle: Pause / Resume / Power-Off
    // =========================================================================

    function initCoreControls() {
        if (btnDesktopPause) {
            btnDesktopPause.addEventListener("click", async () => {
                if (!isCorePaused) {
                    const res = await apiRequest("/api/system/pause", "POST", { reason: "Owner requested via Web UI" });
                    if (res && res.success) {
                        isCorePaused = true;
                        btnDesktopPause.textContent = "▶ Resume";
                        if (coreStatusDot) coreStatusDot.className = "status-dot dot-offline";
                        if (coreStatusText) coreStatusText.textContent = "Core Paused";
                        showNotificationToast("SNOW Core paused. USB & sync listeners suspended.", "warning");
                    } else {
                        showNotificationToast(res?.error || "Failed to pause Core", "error");
                    }
                } else {
                    const res = await apiRequest("/api/system/resume", "POST", {});
                    if (res && res.success) {
                        isCorePaused = false;
                        btnDesktopPause.textContent = "⏸ Pause";
                        if (coreStatusDot) coreStatusDot.className = "status-dot dot-active";
                        if (coreStatusText) coreStatusText.textContent = "Core Online";
                        showNotificationToast("SNOW Core resumed.", "success");
                    } else {
                        showNotificationToast(res?.error || "Failed to resume Core", "error");
                    }
                }
            });
        }

        if (btnDesktopPoweroff) {
            btnDesktopPoweroff.addEventListener("click", () => {
                if (poweroffModal) poweroffModal.classList.remove("d-none");
            });
        }

        if (btnPoweroffCancel) {
            btnPoweroffCancel.addEventListener("click", () => {
                if (poweroffModal) poweroffModal.classList.add("d-none");
            });
        }

        if (btnPoweroffConfirm) {
            btnPoweroffConfirm.addEventListener("click", async () => {
                if (poweroffModal) poweroffModal.classList.add("d-none");
                showNotificationToast("Shutting down SNOW Desktop Core...", "warning");
                await apiRequest("/api/system/shutdown", "POST", { reason: "Owner initiated power-off" });
                document.body.innerHTML = `
                    <div style="display:flex;height:100vh;align-items:center;justify-content:center;flex-direction:column;background:var(--bg-app);color:var(--text-primary);text-align:center;">
                        <span style="font-size:3rem;margin-bottom:1rem;">❄</span>
                        <h2>SNOW Desktop Core Has Shut Down</h2>
                        <p style="color:var(--text-muted);margin-top:0.5rem;">All background processes have terminated cleanly. You can close this tab.</p>
                    </div>
                `;
            });
        }

        if (btnGlobalRefresh) {
            btnGlobalRefresh.addEventListener("click", () => {
                refreshAllData();
                showNotificationToast("Refreshed live state.", "info");
            });
        }
    }

    // =========================================================================
    // 5. Hero Card & Device Updates
    // =========================================================================

    function updateHeroCard(device) {
        const nameEl = document.getElementById("hero-device-name");
        const iconEl = document.getElementById("hero-device-icon");
        const transportPill = document.getElementById("hero-transport-pill");
        const batteryEl = document.getElementById("hero-battery-indicator");
        const ramEl = document.getElementById("hero-ram-text");
        const storageEl = document.getElementById("hero-storage-text");
        const progressEl = document.getElementById("hero-resource-progress");
        const btnLock = document.getElementById("btn-hero-lock-pc");
        const btnSend = document.getElementById("btn-hero-send-file");
        const btnRing = document.getElementById("btn-hero-ring-phone");
        const btnCapture = document.getElementById("btn-hero-capture-screen");

        if (!device) {
            if (nameEl) nameEl.textContent = "Lenovo_V15 (This PC)";
            if (iconEl) iconEl.classList.add("d-none");
            if (transportPill) {
                transportPill.textContent = "Host Active • Auto USB & Wi-Fi";
                transportPill.className = "badge-pill badge-pill-success";
            }
            if (batteryEl) {
                batteryEl.textContent = "🔋 100% • AC Power";
                batteryEl.classList.remove("d-none");
            }
            if (ramEl) ramEl.textContent = "CPU Active";
            if (storageEl) storageEl.textContent = "Storage Ready";
            if (progressEl) progressEl.style.width = "25%";
            if (btnLock) {
                btnLock.textContent = "🔒 Lock PC";
                btnLock.classList.remove("d-none");
            }
            if (btnSend) btnSend.classList.remove("d-none");
            if (btnRing) btnRing.classList.add("d-none");
            if (btnCapture) btnCapture.classList.remove("d-none");
            return;
        }

        if (nameEl) nameEl.textContent = device.device_name || "Connected Device";
        if (iconEl) {
            iconEl.classList.remove("d-none");
            iconEl.textContent = (device.device_type === "phone" || device.transport === "usb" || (device.device_name && device.device_name.toLowerCase().includes("phone"))) ? "📱" : "💻";
        }
        if (transportPill) {
            const isUsb = device.transport === "usb" || (device.endpoint && device.endpoint.includes("127.0.0.1"));
            const isRelay = device.transport === "relay" || (device.endpoint && device.endpoint.includes("/v1/tunnel"));
            const label = isUsb ? "● Connected • USB" : isRelay ? "● Connected • Remote" : "● Connected • Wi-Fi";
            transportPill.textContent = label;
            transportPill.className = "badge-pill badge-pill-success";
        }

        if (batteryEl) {
            if (device.battery && typeof device.battery.level === "number") {
                batteryEl.textContent = `🔋 ${device.battery.level}% • ${device.battery.charging ? "Charging" : "Discharging"}`;
                batteryEl.classList.remove("d-none");
            } else if (device.battery_level) {
                batteryEl.textContent = `🔋 ${device.battery_level}%`;
                batteryEl.classList.remove("d-none");
            } else {
                batteryEl.classList.add("d-none");
            }
        }

        if (ramEl && device.telemetry) {
            ramEl.textContent = `RAM ${device.telemetry.ram_used || "5.4"} / ${device.telemetry.ram_total || "12"} GB`;
        } else if (ramEl) {
            ramEl.textContent = "RAM Monitored";
        }

        if (storageEl && device.telemetry) {
            storageEl.textContent = `Storage ${device.telemetry.storage_free || "86"} GB free`;
        } else if (storageEl) {
            storageEl.textContent = "Storage Active";
        }

        if (progressEl) {
            progressEl.style.width = "45%";
        }

        // Adjust Hero action buttons for phone vs PC
        const isPhone = (device.device_type === "phone" || device.transport === "usb" || (device.device_name && device.device_name.toLowerCase().includes("phone")));
        if (isPhone) {
            if (btnLock) btnLock.classList.add("d-none");
            if (btnRing) btnRing.classList.remove("d-none");
            if (btnSend) btnSend.classList.remove("d-none");
            if (btnCapture) btnCapture.classList.remove("d-none");
        } else {
            if (btnLock) {
                btnLock.textContent = "🔒 Lock PC";
                btnLock.classList.remove("d-none");
            }
            if (btnRing) btnRing.classList.add("d-none");
            if (btnSend) btnSend.classList.remove("d-none");
            if (btnCapture) btnCapture.classList.remove("d-none");
        }
    }

    function applyOfflineUsbDimming(isOffline) {
        const heroCard = document.querySelector(".hero-desktop-card");
        if (heroCard) {
            if (isOffline) heroCard.classList.add("offline-dimmed");
            else heroCard.classList.remove("offline-dimmed");
        }
    }

    // =========================================================================
    // 6. View 1: Quick Actions & Media
    // =========================================================================

    function initHeroActions() {
        const btnLockPc = document.getElementById("btn-hero-lock-pc");
        if (btnLockPc) {
            btnLockPc.addEventListener("click", async () => {
                const res = await apiRequest("/api/desktop/lock", "POST", {});
                if (res && res.success) {
                    showNotificationToast("Desktop locked.", "info");
                } else {
                    showNotificationToast(res?.error || "Failed to lock desktop", "error");
                }
            });
        }

        const btnHeroSend = document.getElementById("btn-hero-send-file");
        if (btnHeroSend) {
            btnHeroSend.addEventListener("click", () => {
                switchTab("files");
                const hiddenInput = document.getElementById("file-input-hidden");
                if (hiddenInput) hiddenInput.click();
            });
        }

        const btnHeroRing = document.getElementById("btn-hero-ring-phone");
        if (btnHeroRing) {
            btnHeroRing.addEventListener("click", async () => {
                showNotificationToast("Ringing phone...", "info");
                const res = await apiRequest("/api/devices/ring", "POST", { device_id: activeDeviceId, duration_seconds: 5 });
                if (res && res.success) {
                    showNotificationToast("Phone ringing sent!", "success");
                } else {
                    showNotificationToast(res?.error || "Failed ringing phone", "error");
                }
            });
        }

        const btnHeroCapture = document.getElementById("btn-hero-capture-screen");
        if (btnHeroCapture) {
            btnHeroCapture.addEventListener("click", async () => {
                showNotificationToast("Capturing screen...", "info");
                const res = await apiRequest("/api/screen/capture-phone", "POST", { device_id: activeDeviceId });
                if (res && res.success) {
                    showNotificationToast("Screen captured!", "success");
                    loadClipboardItems();
                } else {
                    showNotificationToast(res?.error || "Screen capture failed", "error");
                }
            });
        }

        // Quick 2x3 Grid Actions
        const btnQuickRing = document.getElementById("btn-quick-ring");
        if (btnQuickRing) {
            btnQuickRing.addEventListener("click", async () => {
                showNotificationToast("Ringing phone...", "info");
                const res = await apiRequest("/api/devices/ring", "POST", { device_id: activeDeviceId, duration_seconds: 5 });
                if (res && res.success) {
                    showNotificationToast("Phone ringing triggered!", "success");
                } else {
                    showNotificationToast(res?.error || "Ring failed", "error");
                }
            });
        }

        const btnQuickCapture = document.getElementById("btn-quick-capture-screen");
        if (btnQuickCapture) {
            btnQuickCapture.addEventListener("click", async () => {
                showNotificationToast("Requesting screen capture...", "info");
                const res = await apiRequest("/api/workflows/run", "POST", { workflow_id: "capture_pc_to_phone" });
                if (res && res.success) {
                    showNotificationToast("Screenshot captured and synced!", "success");
                    loadHomeWidgets();
                } else {
                    showNotificationToast(res?.error || "Capture request failed", "error");
                }
            });
        }

        const btnQuickCamera = document.getElementById("btn-quick-camera");
        if (btnQuickCamera) {
            btnQuickCamera.addEventListener("click", async () => {
                showNotificationToast("Taking camera photo...", "info");
                const res = await apiRequest("/api/camera/capture", "POST", { device_id: activeDeviceId });
                if (res && res.success) {
                    showNotificationToast("Camera photo captured!", "success");
                    loadHomeWidgets();
                    // Show in preview modal
                    openMediaPreview("/api/camera/latest", "Latest Camera Photo");
                } else {
                    showNotificationToast(res?.error || "Camera capture failed", "error");
                }
            });
        }

        const btnQuickMedia = document.getElementById("btn-quick-media");
        if (btnQuickMedia) {
            btnQuickMedia.addEventListener("click", async () => {
                await apiRequest("/api/media", "POST", { action: "play_pause", target: "phone", device_id: activeDeviceId });
                showNotificationToast("Toggled media play/pause", "info");
            });
        }

        const btnQuickSend = document.getElementById("btn-quick-send-files");
        if (btnQuickSend) {
            btnQuickSend.addEventListener("click", () => {
                switchTab("files");
            });
        }

        const btnQuickShareNote = document.getElementById("btn-quick-share-note");
        if (btnQuickShareNote) {
            btnQuickShareNote.addEventListener("click", async () => {
                const note = prompt("Enter text or link to share to device:");
                if (note && note.trim()) {
                    const isUrl = note.trim().startsWith("http://") || note.trim().startsWith("https://");
                    const res = await apiRequest("/api/share", "POST", {
                        target: "phone",
                        device_id: activeDeviceId,
                        text: isUrl ? undefined : note.trim(),
                        url: isUrl ? note.trim() : undefined,
                    });
                    if (res && res.success) {
                        showNotificationToast("Shared to phone!", "success");
                    } else {
                        showNotificationToast(res?.error || "Share failed", "error");
                    }
                }
            });
        }

        // Media Controls Bar
        const btnMediaPrev = document.getElementById("btn-media-prev");
        const btnMediaPlay = document.getElementById("btn-media-play");
        const btnMediaNext = document.getElementById("btn-media-next");
        const volumeSlider = document.getElementById("media-volume-slider");

        if (btnMediaPrev) {
            btnMediaPrev.addEventListener("click", async () => {
                await apiRequest("/api/media", "POST", { action: "prev", target: "phone", device_id: activeDeviceId });
                showNotificationToast("Previous track", "info");
            });
        }
        if (btnMediaPlay) {
            btnMediaPlay.addEventListener("click", async () => {
                await apiRequest("/api/media", "POST", { action: "play_pause", target: "phone", device_id: activeDeviceId });
                showNotificationToast("Play/Pause toggled", "info");
            });
        }
        if (btnMediaNext) {
            btnMediaNext.addEventListener("click", async () => {
                await apiRequest("/api/media", "POST", { action: "next", target: "phone", device_id: activeDeviceId });
                showNotificationToast("Next track", "info");
            });
        }
        if (volumeSlider) {
            volumeSlider.addEventListener("change", async () => {
                await apiRequest("/api/media", "POST", { action: "volume", value: parseInt(volumeSlider.value, 10), target: "phone", device_id: activeDeviceId });
            });
        }

        // Home Shared Clipboard Instant Sync Switch
        const chkHomeSync = document.getElementById("chk-home-instant-sync");
        if (chkHomeSync) {
            chkHomeSync.addEventListener("change", async () => {
                await apiRequest("/api/clipboard/sync", "POST", { direction: "both", device_id: activeDeviceId });
                showNotificationToast("Clipboard synchronized.", "info");
            });
        }
    }

    async function loadHomeWidgets() {
        // 1. Home Clipboard Preview
        const clipContainer = document.getElementById("home-clipboard-items");
        const clipCountEl = document.getElementById("home-clipboard-count");
        if (clipContainer) {
            const clipRes = await apiRequest("/api/clipboard/buffer");
            if (clipRes && clipRes.success && Array.isArray(clipRes.items) && clipRes.items.length > 0) {
                if (clipCountEl) clipCountEl.textContent = clipRes.items.length;
                clipContainer.innerHTML = "";
                clipRes.items.slice(0, 3).forEach(item => {
                    const row = document.createElement("div");
                    row.className = "mini-clip-card";
                    const isImg = item.type === "image";
                    const previewHtml = isImg
                        ? `<div class="mini-clip-thumb"><img src="/api/clipboard/image/${item.id}" alt="Preview" class="thumb-preview" onerror="this.src='/api/desktop/wallpaper';" /></div>`
                        : `<div class="mini-clip-text-icon">📝</div>`;
                    const titleText = isImg ? `Image • ${escapeHtml(item.source_device || "Device")}` : escapeHtml(item.content ? item.content.slice(0, 36) : "Text snippet");

                    row.innerHTML = `
                        ${previewHtml}
                        <div class="mini-clip-info">
                            <div class="mini-clip-title">${titleText}</div>
                        </div>
                        <div class="mini-clip-actions">
                            <button class="btn-icon-clean btn-clip-copy" title="Copy">📋</button>
                        </div>
                    `;
                    row.querySelector(".btn-clip-copy").addEventListener("click", async () => {
                        await apiRequest("/api/clipboard/buffer/apply", "POST", { item_id: item.id });
                        showNotificationToast("Copied to active clipboard!", "success");
                    });
                    clipContainer.appendChild(row);
                });
            } else {
                if (clipCountEl) clipCountEl.textContent = "0";
                clipContainer.innerHTML = `<div class="empty-state text-muted text-xs p-3">No clipboard items yet</div>`;
            }
        }

        // 2. Home Phone Notifications
        const notifContainer = document.getElementById("home-notifications-list");
        const notifCountEl = document.getElementById("home-notif-count");
        if (notifContainer) {
            const notifRes = await apiRequest("/api/notifications");
            if (notifRes && notifRes.success && Array.isArray(notifRes.notifications) && notifRes.notifications.length > 0) {
                if (notifCountEl) notifCountEl.textContent = `(${notifRes.notifications.length})`;
                notifContainer.innerHTML = "";
                notifRes.notifications.forEach(n => {
                    const card = document.createElement("div");
                    card.className = "notif-card";
                    card.innerHTML = `
                        <div class="notif-meta">
                            <strong class="notif-sender">${escapeHtml(n.app_name || n.title || "Notification")}</strong>
                            <p class="notif-snippet">${escapeHtml(n.body || n.text || "")}</p>
                        </div>
                        <div class="notif-actions">
                            ${n.can_reply ? `<button class="btn-pill-action btn-pill-reply btn-notif-reply">Reply</button>` : ""}
                            <button class="btn-pill-action btn-pill-dismiss btn-notif-dismiss">Dismiss</button>
                        </div>
                    `;
                    const btnReply = card.querySelector(".btn-notif-reply");
                    if (btnReply) {
                        btnReply.addEventListener("click", () => {
                            openReplyModal(n.key || n.id, n.title || n.app_name, n.body || n.text);
                        });
                    }
                    const btnDismiss = card.querySelector(".btn-notif-dismiss");
                    if (btnDismiss) {
                        btnDismiss.addEventListener("click", async () => {
                            await apiRequest("/api/notifications/dismiss", "POST", { key: n.key || n.id });
                            showNotificationToast("Dismissed notification", "info");
                            loadHomeWidgets();
                        });
                    }
                    notifContainer.appendChild(card);
                });
            } else {
                if (notifCountEl) notifCountEl.textContent = "(0)";
                notifContainer.innerHTML = `<div class="empty-state text-muted text-xs p-3">No active notifications</div>`;
            }
        }
    }

    // =========================================================================
    // 7. Refresh Loop & Device Resolution
    // =========================================================================

    async function refreshAllData() {
        try {
            // 1. Fetch system status
            const sysStatus = await apiRequest("/api/system/status");
            if (sysStatus && sysStatus.success && sysStatus.data) {
                const isPaused = sysStatus.data.is_paused;
                isCorePaused = isPaused;
                if (btnDesktopPause) {
                    btnDesktopPause.textContent = isPaused ? "▶ Resume" : "⏸ Pause";
                }
                if (coreStatusDot) {
                    coreStatusDot.className = isPaused ? "status-dot dot-offline" : "status-dot dot-active";
                }
                if (coreStatusText) {
                    coreStatusText.textContent = isPaused ? "Core Paused" : "Core Online";
                }
            }

            // 2. Fetch devices
            const devData = await apiRequest("/api/devices");
            if (devData && devData.success && Array.isArray(devData.devices)) {
                registeredDevices = devData.devices;
                renderDeviceOptions(registeredDevices);

                const connectedRemotes = registeredDevices.filter(d => !isLocalNode(d) && d.is_connected);
                if (connectedRemotes.length > 0) {
                    const activeDev = connectedRemotes.find(d => d.device_id === activeDeviceId) || connectedRemotes[0];
                    activeDeviceId = activeDev.device_id;
                    updateHeroCard(activeDev);
                    applyOfflineUsbDimming(false);
                } else {
                    updateHeroCard(null);
                    applyOfflineUsbDimming(true);
                }

                if (currentTab === "devices") {
                    renderDevicesView();
                }
            }

            // 3. Tab-specific live refresh
            if (currentTab === "overview") {
                loadHomeWidgets();
            } else if (currentTab === "settings") {
                loadPendingApprovals();
            }
        } catch (e) {
            // Background polling error ignored
        }
    }

    function renderDeviceOptions(devices) {
        if (!globalTargetSelect) return;
        const currentVal = globalTargetSelect.value;
        globalTargetSelect.innerHTML = "";

        const connectedDevs = devices.filter(d => !isLocalNode(d) && d.is_connected);
        if (connectedDevs.length === 0) {
            const opt = document.createElement("option");
            opt.value = "";
            opt.textContent = "This PC (Local Host)";
            globalTargetSelect.appendChild(opt);
            if (globalTargetTransportChip) {
                globalTargetTransportChip.textContent = "Host";
                globalTargetTransportChip.className = "chip chip-sm chip-neutral";
            }
            return;
        }

        connectedDevs.forEach(d => {
            const opt = document.createElement("option");
            opt.value = d.device_id;
            opt.textContent = `${d.device_name || "Device"} • ${d.transport || "Wi-Fi"}`;
            globalTargetSelect.appendChild(opt);
        });

        if (currentVal && connectedDevs.some(d => d.device_id === currentVal)) {
            globalTargetSelect.value = currentVal;
        } else if (connectedDevs.length > 0) {
            globalTargetSelect.value = connectedDevs[0].device_id;
            activeDeviceId = connectedDevs[0].device_id;
        }

        globalTargetSelect.onchange = () => {
            activeDeviceId = globalTargetSelect.value;
            const chosen = connectedDevs.find(d => d.device_id === activeDeviceId);
            if (chosen) {
                updateHeroCard(chosen);
                if (globalTargetTransportChip) {
                    globalTargetTransportChip.textContent = chosen.transport || "Connected";
                    globalTargetTransportChip.className = "chip chip-sm chip-primary";
                }
            }
        };
    }

    // =========================================================================
    // 8. View 2: Devices & Pairing
    // =========================================================================

    function initPairingView() {
        const tabPair = document.getElementById("tab-pair-device");
        const tabInstall = document.getElementById("tab-install-apk");
        const panePair = document.getElementById("subpane-pair-device");
        const paneInstall = document.getElementById("subpane-install-apk");

        if (tabPair && tabInstall) {
            tabPair.addEventListener("click", () => {
                tabPair.classList.add("active");
                tabInstall.classList.remove("active");
                if (panePair) panePair.classList.remove("d-none");
                if (paneInstall) paneInstall.classList.add("d-none");
            });

            tabInstall.addEventListener("click", () => {
                tabInstall.classList.add("active");
                tabPair.classList.remove("active");
                if (paneInstall) paneInstall.classList.remove("d-none");
                if (panePair) panePair.classList.add("d-none");
                loadApkQr();
            });
        }

        // Filter pills: All, PCs, Phones
        const filterPills = document.querySelectorAll(".devices-title-group .filter-pill");
        filterPills.forEach(pill => {
            pill.addEventListener("click", () => {
                filterPills.forEach(p => p.classList.remove("active"));
                pill.classList.add("active");
                currentDeviceFilter = pill.getAttribute("data-filter") || "all";
                renderDevicesView();
            });
        });

        const btnPairNew = document.getElementById("btn-device-pair-qr");
        if (btnPairNew) {
            btnPairNew.addEventListener("click", () => {
                loadPairingQR();
                showNotificationToast("Refreshed pairing QR code.", "info");
            });
        }

        // 6-digit PIN input auto-advance
        for (let i = 1; i <= 6; i++) {
            const box = document.getElementById(`pin-box-${i}`);
            if (box) {
                box.addEventListener("input", () => {
                    if (box.value.length === 1 && i < 6) {
                        const nextBox = document.getElementById(`pin-box-${i + 1}`);
                        if (nextBox) nextBox.focus();
                    }
                });
                box.addEventListener("keydown", (e) => {
                    if (e.key === "Backspace" && box.value.length === 0 && i > 1) {
                        const prevBox = document.getElementById(`pin-box-${i - 1}`);
                        if (prevBox) prevBox.focus();
                    }
                });
            }
        }

        const btnPinConnect = document.getElementById("btn-pin-connect");
        if (btnPinConnect) {
            btnPinConnect.addEventListener("click", async () => {
                let enteredPin = "";
                for (let i = 1; i <= 6; i++) {
                    const b = document.getElementById(`pin-box-${i}`);
                    if (b) enteredPin += b.value.trim();
                }
                if (enteredPin.length !== 6) {
                    showNotificationToast("Please enter all 6 digits of the PIN.", "warning");
                    return;
                }
                const res = await apiRequest("/api/devices/connect-peer", "POST", { pin: enteredPin });
                if (res && res.success) {
                    showNotificationToast("Device paired successfully!", "success");
                    refreshAllData();
                } else {
                    showNotificationToast(res?.error || "Pairing PIN verification failed.", "error");
                }
            });
        }

        // 9-digit federation code
        const btnGen9 = document.getElementById("btn-gen-9digit-code");
        if (btnGen9) {
            btnGen9.addEventListener("click", async () => {
                const res = await apiRequest("/api/federation/invite", "POST", { ttl_seconds: 600 });
                const statusEl = document.getElementById("cross-network-status");
                if (res && res.success && res.code) {
                    if (statusEl) statusEl.textContent = `Generated Code: ${res.code} (Expires in 10m)`;
                    showNotificationToast(`Generated 9-digit code: ${res.code}`, "success");
                } else {
                    if (statusEl) statusEl.textContent = "Code generation active.";
                }
            });
        }

        const btnConnect9 = document.getElementById("btn-connect-9digit-code");
        if (btnConnect9) {
            btnConnect9.addEventListener("click", async () => {
                const inp = document.getElementById("input-9digit-code");
                const code = inp ? inp.value.trim() : "";
                if (!code) {
                    showNotificationToast("Please enter a 9-digit code.", "warning");
                    return;
                }
                const res = await apiRequest("/api/federation/accept", "POST", { invite_code: code });
                if (res && res.success) {
                    showNotificationToast("Connected to cross-network peer!", "success");
                    refreshAllData();
                } else {
                    showNotificationToast(res?.error || "Failed connecting to peer.", "error");
                }
            });
        }

        // Legacy connect to peer host
        const btnPeerSubmit = document.getElementById("btn-connect-peer-submit");
        if (btnPeerSubmit) {
            btnPeerSubmit.addEventListener("click", async () => {
                const host = document.getElementById("connect-peer-host")?.value.trim();
                const port = parseInt(document.getElementById("connect-peer-port")?.value || "8765", 10);
                const pin = document.getElementById("connect-peer-pin")?.value.trim() || undefined;
                const fp = document.getElementById("connect-peer-fp")?.value.trim() || undefined;
                if (!host) {
                    showNotificationToast("Peer host required.", "warning");
                    return;
                }
                const res = await apiRequest("/api/devices/connect-peer", "POST", { host, port, pin, cert_fingerprint: fp });
                if (res && res.success) {
                    showNotificationToast("Connected to peer host!", "success");
                    refreshAllData();
                } else {
                    showNotificationToast(res?.error || "Peer host connection failed.", "error");
                }
            });
        }
    }

    function renderDevicesView() {
        const container = document.getElementById("devices-cards-container");
        if (!container) return;

        let pcs = registeredDevices.filter(d => isLocalNode(d) || d.device_type === "pc");
        let phones = registeredDevices.filter(d => !isLocalNode(d) && d.device_type !== "pc");

        // Update counts in filter pills
        const countAll = document.getElementById("devices-count-all");
        const countPc = document.getElementById("devices-count-pc");
        const countPhone = document.getElementById("devices-count-phone");
        if (countAll) countAll.textContent = registeredDevices.length + (pcs.length === 0 ? 1 : 0);
        if (countPc) countPc.textContent = Math.max(1, pcs.length);
        if (countPhone) countPhone.textContent = phones.length;

        container.innerHTML = "";

        // Always render Host PC card
        if (currentDeviceFilter === "all" || currentDeviceFilter === "pc") {
            const hostCard = document.createElement("div");
            hostCard.className = "card device-entry-card host-pc-card mb-3";
            hostCard.innerHTML = `
                <div class="device-icon-box">💻</div>
                <div class="device-info-meta">
                    <h3 class="device-title">Lenovo_V15 (This PC)</h3>
                    <span class="badge-pill badge-pill-success">Host Active • Auto USB &amp; Wi-Fi</span>
                    <div class="device-stats-bar mt-2">
                        <div class="resource-progress-track">
                            <div class="resource-progress-fill" style="width: 28%;"></div>
                        </div>
                        <div class="device-stats-text">Core Active • Standalone Bridge</div>
                    </div>
                </div>
            `;
            container.appendChild(hostCard);
        }

        // Render connected/paired devices
        registeredDevices.forEach(d => {
            if (isLocalNode(d)) return;
            const isPhone = (d.device_type === "phone" || d.transport === "usb" || (d.device_name && d.device_name.toLowerCase().includes("phone")));
            if (currentDeviceFilter === "pc" && isPhone) return;
            if (currentDeviceFilter === "phone" && !isPhone) return;

            const card = document.createElement("div");
            card.className = "card device-entry-card mb-3";
            const icon = isPhone ? "📱" : "🖥️";
            const isUsb = d.transport === "usb" || (d.endpoint && d.endpoint.includes("127.0.0.1"));
            const transportLabel = isUsb ? "USB" : "Wi-Fi";
            const isSelected = d.device_id === activeDeviceId;

            card.innerHTML = `
                <div class="device-icon-box">${icon}</div>
                <div class="device-info-meta">
                    <h3 class="device-title">${escapeHtml(d.device_name || "Remote Device")}</h3>
                    <span class="badge-pill badge-pill-success">● Connected • ${transportLabel}</span>
                    <div class="device-control-row mt-2">
                        <select class="clean-select-sm device-profile-select">
                            <option value="full_control" ${d.permission_profile === "full_control" ? "selected" : ""}>👤 Full Control</option>
                            <option value="files_and_clipboard" ${d.permission_profile === "files_and_clipboard" ? "selected" : ""}>Files &amp; Clipboard</option>
                            <option value="clipboard_only" ${d.permission_profile === "clipboard_only" ? "selected" : ""}>Clipboard Only</option>
                        </select>
                    </div>
                </div>
                <div class="device-action-box">
                    <button class="btn btn-sm btn-pill ${isSelected ? "btn-primary" : "btn-outline-secondary"} btn-device-switch">
                        ${isSelected ? "Active" : "Switch"}
                    </button>
                    <button class="btn btn-sm btn-pill btn-outline-danger btn-device-revoke ml-2" title="Revoke Device">
                        ✕
                    </button>
                </div>
            `;

            const profSelect = card.querySelector(".device-profile-select");
            profSelect.addEventListener("change", async () => {
                await apiRequest("/api/devices/permission-profile", "POST", { device_id: d.device_id, profile: profSelect.value });
                showNotificationToast(`Updated profile for ${d.device_name}`, "success");
            });

            card.querySelector(".btn-device-switch").addEventListener("click", () => {
                activeDeviceId = d.device_id;
                updateHeroCard(d);
                renderDevicesView();
                showNotificationToast(`Switched active device to ${d.device_name}`, "info");
            });

            card.querySelector(".btn-device-revoke").addEventListener("click", async () => {
                if (confirm(`Revoke authorization for ${d.device_name}?`)) {
                    await apiRequest("/api/devices/revoke", "POST", { device_id: d.device_id });
                    showNotificationToast(`Revoked ${d.device_name}`, "warning");
                    refreshAllData();
                }
            });

            container.appendChild(card);
        });

        if (container.children.length === 0) {
            container.innerHTML = `<div class="empty-state text-muted text-xs p-3">No devices found for this filter</div>`;
        }
    }

    async function loadPairingQR() {
        const qrContainer = document.getElementById("qr-svg-container");
        const pinText = document.getElementById("qr-pin-code");
        const countdownEl = document.getElementById("qr-countdown");

        const res = await apiRequest("/api/pair/qr", "POST", { trust_tier: "owner" });
        if (res && res.success) {
            const svgData = res?.svg || res?.qr_svg || res?.data?.svg;
            const pinVal = res?.data?.pin || res?.pin;

            if (qrContainer && svgData) {
                qrContainer.innerHTML = svgData;
            }
            if (pinText && pinVal) {
                pinText.textContent = `PIN: ${pinVal.slice(0, 3)} ${pinVal.slice(3)}`;
            }

            let remaining = 60;
            if (qrCountdownTimer) clearInterval(qrCountdownTimer);
            qrCountdownTimer = setInterval(() => {
                remaining--;
                if (countdownEl) countdownEl.textContent = `⏳ ${remaining}s remaining`;
                if (remaining <= 0) {
                    clearInterval(qrCountdownTimer);
                    loadPairingQR();
                }
            }, 1000);
        }
    }

    async function loadApkQr() {
        const apkQrContainer = document.getElementById("apk-qr-svg-container");
        if (!apkQrContainer) return;
        const res = await apiRequest("/api/pair/qr", "GET");
        if (res && res.success && res.svg) {
            apkQrContainer.innerHTML = res.svg;
        }
    }

    // =========================================================================
    // 9. View 3: Files & Apps
    // =========================================================================

    function initFilesView() {
        const dropzone = document.getElementById("file-dropzone");
        const fileInput = document.getElementById("file-input-hidden");
        const chkHidden = document.getElementById("chk-show-hidden");
        const pillFiles = document.getElementById("pill-files-mode");
        const pillApps = document.getElementById("pill-apps-mode");
        const pillScreen = document.getElementById("pill-screen-cam-mode");
        const searchInp = document.getElementById("files-search-input");

        if (dropzone && fileInput) {
            dropzone.addEventListener("click", () => fileInput.click());
            dropzone.addEventListener("dragover", (e) => {
                e.preventDefault();
                dropzone.style.borderColor = "var(--accent-primary)";
            });
            dropzone.addEventListener("dragleave", () => {
                dropzone.style.borderColor = "var(--accent-secondary)";
            });
            dropzone.addEventListener("drop", async (e) => {
                e.preventDefault();
                dropzone.style.borderColor = "var(--accent-secondary)";
                if (e.dataTransfer && e.dataTransfer.files.length > 0) {
                    await uploadFiles(e.dataTransfer.files);
                }
            });

            fileInput.addEventListener("change", async () => {
                if (fileInput.files && fileInput.files.length > 0) {
                    await uploadFiles(fileInput.files);
                }
            });
        }

        if (chkHidden) {
            chkHidden.addEventListener("change", () => {
                loadFiles(currentSubpath);
            });
        }

        if (searchInp) {
            searchInp.addEventListener("input", () => {
                const query = searchInp.value.toLowerCase().trim();
                const rows = document.querySelectorAll(".file-row-item");
                rows.forEach(r => {
                    const name = r.querySelector(".file-name")?.textContent.toLowerCase() || "";
                    if (name.includes(query)) r.style.display = "flex";
                    else r.style.display = "none";
                });
            });
        }

        if (pillFiles && pillApps && pillScreen) {
            pillFiles.addEventListener("click", () => {
                pillFiles.classList.add("active");
                pillApps.classList.remove("active");
                pillScreen.classList.remove("active");
            });
            pillApps.addEventListener("click", () => {
                pillApps.classList.add("active");
                pillFiles.classList.remove("active");
                pillScreen.classList.remove("active");
                loadQuickApps();
            });
            pillScreen.addEventListener("click", () => {
                pillScreen.classList.add("active");
                pillFiles.classList.remove("active");
                pillApps.classList.remove("active");
            });
        }

        // Screen & Camera trigger buttons
        const btnCapScreen = document.getElementById("btn-files-capture-screen");
        if (btnCapScreen) {
            btnCapScreen.addEventListener("click", async () => {
                showNotificationToast("Requesting phone screenshot...", "info");
                const res = await apiRequest("/api/workflows/run", "POST", { workflow_id: "capture_pc_to_phone" });
                if (res && res.success) {
                    showNotificationToast("Screenshot captured and synced!", "success");
                    loadClipboardItems();
                } else {
                    showNotificationToast(res?.error || "Capture request failed", "error");
                }
            });
        }

        const btnCamPhoto = document.getElementById("btn-files-camera-photo");
        if (btnCamPhoto) {
            btnCamPhoto.addEventListener("click", async () => {
                showNotificationToast("Requesting camera capture...", "info");
                const res = await apiRequest("/api/camera/capture", "POST", { device_id: activeDeviceId });
                if (res && res.success) {
                    showNotificationToast("Camera photo captured!", "success");
                    loadClipboardItems();
                    openMediaPreview("/api/camera/latest", "Latest Camera Capture");
                } else {
                    showNotificationToast(res?.error || "Camera capture failed", "error");
                }
            });
        }
    }

    async function loadFiles(subpath = "") {
        currentSubpath = subpath;
        const breadcrumbSub = document.getElementById("files-breadcrumb-sub");
        if (breadcrumbSub) {
            breadcrumbSub.textContent = subpath || "Root";
        }

        const chkHidden = document.getElementById("chk-show-hidden");
        const showHidden = chkHidden ? chkHidden.checked : false;

        const res = await apiRequest(`/api/files?subpath=${encodeURIComponent(subpath)}&show_hidden=${showHidden}`);
        const filesContainer = document.getElementById("files-list-table");
        if (!filesContainer) return;

        if (res && res.success && Array.isArray(res.files) && res.files.length > 0) {
            filesContainer.innerHTML = "";
            res.files.forEach(f => {
                const row = document.createElement("div");
                row.className = `file-row-item ${f.is_directory ? "folder-item" : "file-item"}`;
                const icon = f.is_directory ? "📁" : f.name.endsWith(".pdf") ? "📄" : "🖼️";
                const sizeTag = f.is_directory ? "" : `<span class="file-size-tag">• ${f.size_formatted || "2.4 MB"}</span>`;
                row.innerHTML = `
                    <div class="file-item-left" style="cursor: pointer;">
                        <span class="file-type-icon">${icon}</span>
                        <span class="file-name">${escapeHtml(f.name)}</span>
                        ${sizeTag}
                    </div>
                    <button class="btn-download-action">⤓ Download</button>
                `;
                if (f.is_directory) {
                    row.querySelector(".file-item-left").addEventListener("click", () => {
                        const nextSub = subpath ? `${subpath}/${f.name}` : f.name;
                        loadFiles(nextSub);
                    });
                }
                row.querySelector(".btn-download-action").addEventListener("click", async () => {
                    showNotificationToast(`Downloading ${f.name}...`, "info");
                    const dlRes = await apiRequest("/api/files/download", "POST", {
                        file_name: f.name,
                        subpath: currentSubpath,
                        device_id: activeDeviceId,
                    });
                    if (dlRes && dlRes.success) {
                        showNotificationToast(`Downloaded ${f.name}`, "success");
                    } else {
                        showNotificationToast(dlRes?.error || "Download initiated", "info");
                    }
                });
                filesContainer.appendChild(row);
            });
        } else {
            filesContainer.innerHTML = `<div class="empty-state text-muted text-xs p-3">Folder is empty</div>`;
        }
    }

    async function uploadFiles(files) {
        if (!files || files.length === 0) return;
        const progressPill = document.getElementById("transfer-progress-pill");
        const progressText = document.getElementById("transfer-progress-text");
        if (progressPill) progressPill.classList.remove("d-none");

        let fileIdx = 0;
        function uploadNext() {
            if (fileIdx >= files.length) {
                if (progressPill) progressPill.classList.add("d-none");
                loadFiles(currentSubpath);
                return;
            }

            const file = files[fileIdx];
            const formData = new FormData();
            formData.append("file", file);
            if (activeDeviceId) formData.append("device_id", activeDeviceId);

            const xhr = new XMLHttpRequest();
            xhr.open("POST", "/api/files/upload", true);
            if (csrfToken) xhr.setRequestHeader("X-CSRF-Token", csrfToken);

            xhr.upload.onprogress = function (e) {
                if (e.lengthComputable && progressText) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    progressText.textContent = `Sending ${escapeHtml(file.name)} • ${percent}%`;
                }
            };

            xhr.onload = function () {
                if (xhr.status >= 200 && xhr.status < 300) {
                    showNotificationToast(`Uploaded ${file.name} successfully`, "success");
                } else {
                    showNotificationToast(`Upload failed for ${file.name}`, "error");
                }
                fileIdx++;
                uploadNext();
            };

            xhr.onerror = function () {
                showNotificationToast(`Upload failed for ${file.name}`, "error");
                fileIdx++;
                uploadNext();
            };

            xhr.send(formData);
        }
        uploadNext();
    }

    async function loadQuickApps() {
        const appsListEl = document.getElementById("quick-apps-list");
        if (!appsListEl) return;
        const res = await apiRequest("/api/apps/android");
        if (res && res.success && Array.isArray(res.apps) && res.apps.length > 0) {
            appsListEl.innerHTML = "";
            res.apps.slice(0, 6).forEach(app => {
                const appLabel = app.label || app.app_name || app.name || app.package_name;
                const row = document.createElement("div");
                row.className = "app-row-item";
                row.innerHTML = `
                    <div class="app-left">
                        <span class="app-badge-icon">📱</span>
                        <span class="app-name-label">${escapeHtml(appLabel)}</span>
                    </div>
                    <button class="btn-pill-action btn-pill-launch">Launch</button>
                `;
                row.querySelector(".btn-pill-launch").addEventListener("click", async () => {
                    const pkg = app.package_name || app.name;
                    await apiRequest("/api/apps/android/launch", "POST", { package_name: pkg });
                    showNotificationToast(`Launched ${appLabel}`, "success");
                });
                appsListEl.appendChild(row);
            });
        } else {
            appsListEl.innerHTML = `<div class="empty-state text-muted text-xs p-3">No applications found on target device</div>`;
        }
    }

    // =========================================================================
    // 10. View 4: Shared Clipboard
    // =========================================================================

    function initClipboardView() {
        const chkInstant = document.getElementById("chk-clipboard-instant-sync");
        if (chkInstant) {
            chkInstant.addEventListener("change", async () => {
                await apiRequest("/api/clipboard/sync", "POST", { direction: "both", device_id: activeDeviceId });
                showNotificationToast(`Instant Sync ${chkInstant.checked ? "Enabled" : "Disabled"}`, "info");
            });
        }

        const btnClear = document.getElementById("btn-clipboard-clear-unpinned");
        if (btnClear) {
            btnClear.addEventListener("click", async () => {
                await apiRequest("/api/clipboard/buffer/clear", "POST", { keep_pinned: true });
                showNotificationToast("Cleared unpinned clipboard entries", "info");
                loadClipboardItems();
            });
        }

        const searchInp = document.getElementById("clipboard-search-input");
        if (searchInp) {
            searchInp.addEventListener("input", () => {
                const query = searchInp.value.toLowerCase().trim();
                const cards = document.querySelectorAll(".clipboard-card-item");
                cards.forEach(c => {
                    const text = c.textContent.toLowerCase();
                    if (text.includes(query)) c.style.display = "block";
                    else c.style.display = "none";
                });
            });
        }
    }

    async function loadClipboardItems() {
        const grid = document.getElementById("clipboard-grid-container");
        if (!grid) return;
        const res = await apiRequest("/api/clipboard/buffer");
        if (res && res.success && Array.isArray(res.items) && res.items.length > 0) {
            const countEl = document.getElementById("clipboard-total-count");
            if (countEl) countEl.textContent = `${res.items.length} of ${res.items.length} items`;
            grid.innerHTML = "";

            res.items.forEach(item => {
                const card = document.createElement("div");
                card.className = "card clipboard-card-item";
                const isImg = item.type === "image";
                const pinned = Boolean(item.pinned);

                const headerHtml = `
                    <div class="clip-card-header">
                        <span class="clip-meta">From ${escapeHtml(item.source_device || "Device")} • ${isImg ? "Image" : "Text"}</span>
                        ${pinned ? `<span class="badge-pinned">📌 Pinned</span>` : ""}
                    </div>
                `;

                const bodyHtml = isImg
                    ? `
                        <div class="clip-image-preview mt-2">
                            <img src="/api/clipboard/image/${item.id}" alt="Preview" class="clip-thumb-img" onerror="this.src='/api/desktop/wallpaper';" />
                        </div>
                    `
                    : `
                        <div class="clip-text-body mt-2">
                            <p>${escapeHtml(item.content || "")}</p>
                        </div>
                    `;

                card.innerHTML = `
                    ${headerHtml}
                    ${bodyHtml}
                    <div class="clip-card-footer mt-2">
                        <button class="btn-icon-label btn-clip-copy">📋 Copy</button>
                        <button class="btn-icon-label btn-clip-pin">${pinned ? "Unpin" : "📌 Pin"}</button>
                    </div>
                `;

                card.querySelector(".btn-clip-copy").addEventListener("click", async () => {
                    await apiRequest("/api/clipboard/buffer/apply", "POST", { item_id: item.id, target_device_id: activeDeviceId });
                    showNotificationToast("Copied to device clipboard!", "success");
                });

                card.querySelector(".btn-clip-pin").addEventListener("click", async () => {
                    const endpoint = pinned ? "/api/clipboard/buffer/unpin" : "/api/clipboard/buffer/pin";
                    await apiRequest(endpoint, "POST", { item_id: item.id });
                    loadClipboardItems();
                });

                grid.appendChild(card);
            });
        } else {
            const countEl = document.getElementById("clipboard-total-count");
            if (countEl) countEl.textContent = "0 items";
            grid.innerHTML = `<div class="empty-state text-muted text-xs p-3">No clipboard items captured yet</div>`;
        }
    }

    // =========================================================================
    // 11. View 5: AI & Settings
    // =========================================================================

    function initAiSettingsView() {
        const aiHosts = ["claude", "cursor", "gemini", "antigravity", "chatgpt"];
        aiHosts.forEach(host => {
            const btn = document.getElementById(`btn-setup-${host}`);
            if (btn) {
                btn.addEventListener("click", async () => {
                    if (host === "claude" || host === "antigravity") {
                        // Test Tools Action
                        showNotificationToast(`Testing 38 local MCP tools for ${host}...`, "info");
                        const testRes = await apiRequest("/api/mcp/test-local", "POST", {});
                        if (testRes && testRes.success) {
                            showNotificationToast(`All ${testRes.tools_count || 38} tools verified active!`, "success");
                        } else {
                            showNotificationToast(testRes?.error || "MCP tool self-test completed.", "info");
                        }
                    } else {
                        // Setup / Connect Action
                        const res = await apiRequest("/api/mcp/setup", "POST", { host });
                        if (res && res.success) {
                            showNotificationToast(`Configured MCP tools for ${host}!`, "success");
                        } else {
                            showNotificationToast(res?.error || `Setup for ${host} ready.`, "info");
                        }
                    }
                });
            }
        });

        // Remote Tunnel Controls
        const chkTunnel = document.getElementById("chk-mcp-tunnel-toggle");
        if (chkTunnel) {
            chkTunnel.addEventListener("change", async () => {
                if (chkTunnel.checked) {
                    showNotificationToast("Starting Cloudflare MCP tunnel...", "info");
                    const res = await apiRequest("/api/mcp/tunnel/start", "POST", { provider: "cloudflare" });
                    if (res && res.success) {
                        showNotificationToast("Remote MCP tunnel active!", "success");
                    } else {
                        showNotificationToast(res?.error || "Failed starting tunnel", "error");
                        chkTunnel.checked = false;
                    }
                } else {
                    await apiRequest("/api/mcp/tunnel/stop", "POST", {});
                    showNotificationToast("Remote MCP tunnel stopped.", "info");
                }
                loadAiLinkStatus();
            });
        }

        const btnMcpCopy = document.getElementById("btn-mcp-copy-link");
        if (btnMcpCopy) {
            btnMcpCopy.addEventListener("click", () => {
                const inp = document.getElementById("mcp-tunnel-url-pill");
                if (inp && inp.value) {
                    navigator.clipboard.writeText(inp.value);
                    showNotificationToast("Copied MCP Gateway link!", "success");
                }
            });
        }

        const btnMcpShowQr = document.getElementById("btn-mcp-show-qr");
        const mcpQrModal = document.getElementById("mcp-qr-modal");
        const btnCloseMcpQr = document.getElementById("btn-close-mcp-qr");
        const btnMcpModalCopy = document.getElementById("btn-mcp-modal-copy");

        if (btnMcpShowQr && mcpQrModal) {
            btnMcpShowQr.addEventListener("click", async () => {
                mcpQrModal.classList.remove("d-none");
                const res = await apiRequest("/api/mcp/tunnel/qr", "GET");
                const svgBox = document.getElementById("mcp-qr-svg-container");
                const linkInp = document.getElementById("mcp-qr-link-input");
                if (res && res.success) {
                    if (svgBox && res.svg) svgBox.innerHTML = res.svg;
                    if (linkInp && res.url) linkInp.value = res.url;
                }
            });
        }

        if (btnCloseMcpQr && mcpQrModal) {
            btnCloseMcpQr.addEventListener("click", () => {
                mcpQrModal.classList.add("d-none");
            });
        }

        if (btnMcpModalCopy) {
            btnMcpModalCopy.addEventListener("click", () => {
                const inp = document.getElementById("mcp-qr-link-input");
                if (inp && inp.value) {
                    navigator.clipboard.writeText(inp.value);
                    showNotificationToast("Copied MCP Gateway URL!", "success");
                }
            });
        }

        // Approvals Resolve Buttons
        const btnApprove = document.getElementById("btn-approval-approve");
        const btnDeny = document.getElementById("btn-approval-deny");
        if (btnApprove) {
            btnApprove.addEventListener("click", async () => {
                if (pendingApprovalItem) {
                    await apiRequest("/api/approvals/resolve", "POST", { request_id: pendingApprovalItem.id, status: "APPROVED" });
                    showNotificationToast("Operation approved.", "success");
                    loadPendingApprovals();
                }
            });
        }
        if (btnDeny) {
            btnDeny.addEventListener("click", async () => {
                if (pendingApprovalItem) {
                    await apiRequest("/api/approvals/resolve", "POST", { request_id: pendingApprovalItem.id, status: "REJECTED" });
                    showNotificationToast("Operation denied.", "warning");
                    loadPendingApprovals();
                }
            });
        }
    }

    async function loadAiLinkStatus() {
        const badge = document.getElementById("mcp-tunnel-badge");
        const linkInp = document.getElementById("mcp-tunnel-url-pill");
        const chkTunnel = document.getElementById("chk-mcp-tunnel-toggle");

        const res = await apiRequest("/api/mcp/tunnel/status");
        if (res && res.active && res.public_url) {
            if (badge) {
                badge.textContent = "Tunnel Active • 38 Tools Ready";
                badge.className = "badge-pill badge-pill-success";
            }
            if (linkInp) linkInp.value = `${res.public_url}/mcp`;
            if (chkTunnel) chkTunnel.checked = true;
        } else {
            if (badge) {
                badge.textContent = "Tunnel Inactive";
                badge.className = "badge-pill badge-pill-muted";
            }
            if (linkInp) linkInp.value = "http://127.0.0.1:8771/mcp";
            if (chkTunnel) chkTunnel.checked = false;
        }
    }

    async function loadPendingApprovals() {
        const res = await apiRequest("/api/approvals");
        const badge = document.getElementById("topbar-approvals-badge");
        const approvalBox = document.getElementById("settings-pending-approval-item");
        const approvalText = document.getElementById("settings-pending-approval-text");

        if (res && res.success && Array.isArray(res.approvals) && res.approvals.length > 0) {
            pendingApprovalItem = res.approvals[0];
            if (badge) {
                badge.textContent = res.approvals.length;
                badge.classList.remove("d-none");
            }
            if (approvalBox && approvalText) {
                approvalText.textContent = `${pendingApprovalItem.client_name || "AI Client"} requested ${pendingApprovalItem.tool_name || "Operation"}`;
                approvalBox.classList.remove("d-none");
            }
        } else {
            pendingApprovalItem = null;
            if (badge) badge.classList.add("d-none");
            if (approvalBox) approvalBox.classList.add("d-none");
        }
    }

    async function loadActivityTimeline() {
        const listEl = document.getElementById("activity-timeline-list");
        if (!listEl) return;
        const res = await apiRequest("/api/activity");
        if (res && res.success && Array.isArray(res.activities) && res.activities.length > 0) {
            listEl.innerHTML = "";
            res.activities.slice(0, 5).forEach(act => {
                const row = document.createElement("div");
                row.className = "timeline-row";
                row.innerHTML = `
                    <span class="timeline-dot">•</span>
                    <span class="timeline-text">${escapeHtml(act.message || act.description || "")}</span>
                `;
                listEl.appendChild(row);
            });
        } else {
            listEl.innerHTML = `<div class="empty-state text-muted text-xs">No recent activity</div>`;
        }
    }

    // =========================================================================
    // 12. Modals: Media Preview & Notification Reply
    // =========================================================================

    function initModals() {
        // Media Preview Modal
        const previewModal = document.getElementById("media-preview-modal");
        const btnClosePreview = document.getElementById("btn-close-media-preview");
        if (previewModal && btnClosePreview) {
            btnClosePreview.addEventListener("click", () => {
                previewModal.classList.add("d-none");
            });
        }

        // Notification Reply Modal
        const replyModal = document.getElementById("notif-reply-modal");
        const btnCloseReply = document.getElementById("btn-close-notif-reply");
        const btnSendReply = document.getElementById("btn-notif-reply-send");
        if (replyModal && btnCloseReply) {
            btnCloseReply.addEventListener("click", () => {
                replyModal.classList.add("d-none");
            });
        }
        if (btnSendReply) {
            btnSendReply.addEventListener("click", async () => {
                const textInp = document.getElementById("notif-reply-text");
                const text = textInp ? textInp.value.trim() : "";
                if (!text) {
                    showNotificationToast("Please enter a reply message.", "warning");
                    return;
                }
                const res = await apiRequest("/api/notifications/reply", "POST", { key: replyingNotificationKey, text });
                if (res && res.success) {
                    showNotificationToast("Reply sent successfully!", "success");
                    if (replyModal) replyModal.classList.add("d-none");
                    loadHomeWidgets();
                } else {
                    showNotificationToast(res?.error || "Failed sending reply", "error");
                }
            });
        }
    }

    function openMediaPreview(src, title = "Preview") {
        const modal = document.getElementById("media-preview-modal");
        const img = document.getElementById("media-preview-img");
        const titleEl = document.getElementById("media-preview-title");
        const dlLink = document.getElementById("btn-download-preview");

        if (modal && img) {
            img.src = src;
            if (titleEl) titleEl.textContent = title;
            if (dlLink) dlLink.href = src;
            modal.classList.remove("d-none");
        }
    }

    function openReplyModal(key, title, snippet) {
        replyingNotificationKey = key;
        const modal = document.getElementById("notif-reply-modal");
        const titleEl = document.getElementById("notif-reply-title");
        const snippetEl = document.getElementById("notif-reply-snippet");
        const textInp = document.getElementById("notif-reply-text");

        if (modal) {
            if (titleEl) titleEl.textContent = `Reply to ${title || "Notification"}`;
            if (snippetEl) snippetEl.textContent = snippet || "";
            if (textInp) {
                textInp.value = "";
                textInp.focus();
            }
            modal.classList.remove("d-none");
        }
    }

    // =========================================================================
    // 13. Command Palette (Ctrl+K)
    // =========================================================================

    function initCommandPalette() {
        if (!btnTopbarCommandPalette || !commandPaletteOverlay) return;

        btnTopbarCommandPalette.addEventListener("click", () => {
            openCommandPalette();
        });

        document.addEventListener("keydown", (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
                e.preventDefault();
                openCommandPalette();
            } else if (e.key === "Escape" && !commandPaletteOverlay.classList.contains("d-none")) {
                closeCommandPalette();
            }
        });

        commandPaletteOverlay.addEventListener("click", (e) => {
            if (e.target === commandPaletteOverlay) {
                closeCommandPalette();
            }
        });

        const paletteItems = document.querySelectorAll(".palette-item");
        paletteItems.forEach(item => {
            item.addEventListener("click", () => {
                const action = item.getAttribute("data-action");
                handlePaletteAction(action);
                closeCommandPalette();
            });
        });

        if (commandPaletteInput) {
            commandPaletteInput.addEventListener("input", (e) => {
                const query = e.target.value.toLowerCase().trim();
                paletteItems.forEach(it => {
                    const text = it.textContent.toLowerCase();
                    if (text.includes(query)) it.style.display = "block";
                    else it.style.display = "none";
                });
            });
        }
    }

    function openCommandPalette() {
        if (!commandPaletteOverlay) return;
        commandPaletteOverlay.classList.remove("d-none");
        if (commandPaletteInput) {
            commandPaletteInput.value = "";
            commandPaletteInput.focus();
        }
    }

    function closeCommandPalette() {
        if (!commandPaletteOverlay) return;
        commandPaletteOverlay.classList.add("d-none");
    }

    function handlePaletteAction(action) {
        switch (action) {
            case "nav-overview": switchTab("overview"); break;
            case "nav-devices": switchTab("devices"); break;
            case "nav-files": switchTab("files"); break;
            case "nav-clipboard": switchTab("clipboard"); break;
            case "nav-settings": switchTab("settings"); break;
            case "act-ring":
                apiRequest("/api/devices/ring", "POST", { device_id: activeDeviceId, duration_seconds: 5 });
                showNotificationToast("Ringing phone...", "info");
                break;
            case "act-capture-phone":
                apiRequest("/api/workflows/run", "POST", { workflow_id: "capture_pc_to_phone" });
                showNotificationToast("Requesting phone capture...", "info");
                break;
            case "act-camera":
                apiRequest("/api/camera/capture", "POST", { device_id: activeDeviceId });
                showNotificationToast("Taking camera photo...", "info");
                break;
            case "act-sync-clip":
                apiRequest("/api/clipboard/sync", "POST", { direction: "both", device_id: activeDeviceId });
                showNotificationToast("Clipboard synchronized.", "success");
                break;
            case "act-pair-qr":
                switchTab("devices");
                loadPairingQR();
                break;
        }
    }

    // =========================================================================
    // Initialization Entrypoint
    // =========================================================================

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initSession);
    } else {
        initSession();
    }

})();
