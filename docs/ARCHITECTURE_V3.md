# SNOW V3 Architecture Specification

**Project:** SNOW — Synthesized Node Orchestration Wireless
**Version:** 3.0.0 (Phase 25 Final Baseline)
**Classification:** Academic Capstone Architecture Document
**Target Hardware:** Lenovo V15 (Intel Core i5-1235U, ~7.9 GB RAM, Windows 11) & Realme RMX5110 (Android 14 verified baseline; Android 15–17 / ColorOS 17 target)

---

## 1. Executive Summary & Evolution

SNOW is a headless, cross-device AI capability bridge that allows AI assistants (Claude Desktop, Google Antigravity, Cursor, ChatGPT) to perform explicitly authorized operations across Windows desktop workstations and Android mobile hardware via the standardized Model Context Protocol (MCP).

### Architectural Milestones

- **SNOW V1 (Phases 1–11):** Established the foundation: loopback MCP stdio transport, encrypted WSS control channel (port 8765), authenticated HTTPS transfer server (port 8766), pairing lifecycle with PIN/QR and mutual TLS pinning, and initial device runtimes for Windows and Android.
- **SNOW V2 (Phases 12–18):** Introduced the Capability Engine (`CapabilityRegistry`), centralized `SessionRouter`, dynamic node management (`NodeRegistry`), symmetric device mesh abstractions, and unified host onboarding CLI (`snow setup`, `snow doctor`).
- **SNOW V3 (Phases 19–25):** Complete production maturity:
  1. *Transfer & Framing Hardening (Phase 19):* Strict 64 KiB WSS control frame boundaries and cryptographic transfer tickets.
  2. *Zero-Data Local Mesh (Phase 20):* USB ADB reverse port forwarding bypasses restrictive Wi-Fi access-point isolation.
  3. *Zero-CDN Web Dashboard (Phase 21):* Loopback-only Web UI (port 8769) replacing legacy TUI, native pairing, and trust tiers (`OWNER` vs `PEER`).
  4. *3-Plane Remote Relay (Phase 22):* TLS 1.3 MemoryBIO encrypted tunnel (port 8770) for out-of-LAN presence, control, and transfer routing with rolling quotas.
  5. *Remote MCP Gateway (Phase 23):* Streamable HTTP gateway (port 8771) with RFC 6749/7636 OAuth 2.1 PKCE authorization code flow and Bearer tokens.
  6. *Consent-Gated Capture & Multi-Step Workflows (Phase 24):* Interactive human approval UX, Android `MediaProjection` token lifecycle, Windows desktop screenshot, out-of-band HTTPS preview, and composite multi-step workflows.
  7. *Consumer Polish & Low-Spec Packaging (Phase 25):* Structured Glacier/Obsidian consumer cards, resilient multi-peer federation, low-spec benchmarking (< 85 MB RSS per component), and 3.0.0 release readiness.

---

## 2. Four-Layer System Architecture

```
+=========================================================================+
|                        LAYER 1: AI INTEGRATION                          |
|  - MCP stdio Server (JSON-RPC 2.0 over standard I/O)                    |
|  - Remote MCP Gateway (Port 8771, Streamable HTTP, OAuth 2.1 + PKCE)    |
|  - SNOW Web Dashboard (Port 8769, Loopback only, Zero CDN)              |
|  - Unified CLI (`snow daemon`, `snow devices`, `snow pair`, `snow doctor`)|
+=========================================================================+
                                    |
+=========================================================================+
|                     LAYER 2: CAPABILITY ENGINE                          |
|  - Dynamic 34-Tool Capability Catalog (`CAPABILITY_REGISTRY`)           |
|  - CapabilityEngine: Centralized execution & argument validation        |
|  - ApprovalPolicyEngine: Principle-based access control                |
|      * AI_MCP (Restricted, requires explicit interactive approval)       |
|      * OWNER_MANUAL (Direct physical operator, auto-approved)           |
|  - Approval Token Store: One-time cryptographic nonces with TTL         |
|  - Multi-Step Workflow Orchestrator: 4 pre-packaged pipelines           |
+=========================================================================+
                                    |
+=========================================================================+
|                     LAYER 3: DEVICE NETWORKING                          |
|  - Local-First Discovery & Transport Hierarchy:                         |
|      1. Local Wi-Fi / LAN (mDNS + WSS Port 8765)                        |
|      2. Zero-Data USB Mesh (ADB Reverse Port Forwarding)                |
|      3. Remote Relay Tunnel (TLS 1.3 MemoryBIO Port 8770)               |
|  - NodeRegistry & SessionRouter: Routing, presence, and ping keepalive  |
|  - WSS Control Plane: Port 8765, strictly enforced <= 64 KiB frame size |
|  - HTTPS Transfer Plane: Port 8766, out-of-band chunked file streaming  |
|  - Mutual TLS: Ephemeral/self-signed certs with pinned SHA-256 digests  |
+=========================================================================+
                                    |
+=========================================================================+
|                       LAYER 4: DEVICE RUNTIME                           |
|  - Windows Python Runtime:                                              |
|      * Native desktop status (battery, memory, CPU)                     |
|      * Windows clipboard read/write via ctypes/User32                   |
|      * Consent-gated desktop screenshot capture                         |
|  - Android Kotlin Runtime:                                              |
|      * Foreground Service (`SnowForegroundService`)                     |
|      * MediaProjection screen capture with system consent intent        |
|      * Android Keystore AES-GCM hardware token encryption               |
|      * Notification-based clipboard ingestion & write                   |
|      * Quarantined multi-phone mesh host (`IS_QUARANTINED = true`)      |
+=========================================================================+
```

---

## 3. Dynamic 34-Tool Capability Catalog

SNOW exposes 34 capabilities dynamically registered in `CAPABILITY_REGISTRY` (sourced canonically from `src/snow/mcp/registry.py`). These are categorized across local Windows operations, cross-device Android bridge capabilities, media/system tools, and multi-step workflows:

### A. Local Windows Capabilities (11 Tools)
1. `snow_windows_battery`: Query Windows host battery telemetry and power source.
2. `snow_windows_system_info`: Inspect CPU utilization, memory, disk, and OS hardware identifiers.
3. `snow_windows_processes`: Enumerate running Windows processes sorted by memory or CPU.
4. `snow_windows_launch_app`: Launch permitted Windows desktop applications or lock workstation.
5. `snow_windows_file_read`: Read sandboxed file contents under allowed desktop roots.
6. `snow_windows_file_write`: Write content to files within scoped desktop directories.
7. `snow_windows_file_list`: Enumerate directories and inspect file metadata.
8. `snow_windows_file_search`: Search for files matching patterns within allowed roots.
9. `snow_windows_terminal_exec`: Execute safe bounded terminal commands (echo/read-only auto-allowed; mutating gated).
10. `snow_windows_clipboard_get`: Inspect local Windows clipboard availability and length.
11. `snow_windows_clipboard_set`: Write plain text to the Windows host clipboard.

### B. Core Cross-Device & Mesh Capabilities (5 Tools)
12. `snow_get_device_status`: Retrieve real-time connectivity and transport status for paired nodes.
13. `snow_list_devices`: List all registered nodes, trust tiers (`OWNER` vs `PEER`), and reachability.
14. `snow_sync_clipboard`: Synchronize clipboard text across connected devices.
22. `snow_transfer_file`: High-level peer-to-peer file transfer initiation.
23. `snow_mesh_connect_peer`: Initiate mesh session connection to an authenticated peer.

### C. Android Mobile Capabilities (10 Tools)
15. `snow_android_battery`: Query paired Android phone battery level and charging state.
16. `snow_android_ring`: Ring paired Android phone for locating or audible alerting.
17. `snow_android_clipboard_push`: Push text to paired Android clipboard (`clipboard_push`).
18. `snow_android_launch_app`: Launch an approved Android application via intent.
19. `snow_android_list_apps`: Enumerate installed non-system applications on Android.
20. `snow_android_file_send`: Stage and transfer a file to the paired Android device.
21. `snow_android_file_receive`: Pull a file from Android storage to the Windows desktop.
24. `snow_android_send_message`: Compose or dispatch SMS/messaging intent on Android.
25. `snow_android_file_list`: List files in permitted Android app-specific directories.
26. `snow_android_notifications_list`: Inspect active notifications on the Android device.

### D. Media, Sharing & Notification Management (4 Tools)
27. `snow_android_notification_dismiss`: Dismiss an active notification on the Android device.
28. `snow_media_control`: Control Android audio and media playback state.
29. `snow_share_link`: Open a URL in the default browser on the target device.
30. `snow_activity_history`: Inspect secret-redacted audit activity log records.

### E. Consent-Gated Capture & Composite Workflows (4 Tools)
31. `snow_windows_screenshot`: Consent-gated desktop capture with out-of-band HTTPS preview.
32. `snow_android_screenshot`: Interactive Android `MediaProjection` screen capture.
33. `snow_android_camera_capture`: Foreground-only Android camera capture with live preview.
34. `snow_workflow_run`: Orchestrate composite multi-step declarative workflows (`device_health_snapshot`, `pc_screenshot`, `capture_pc_to_phone`, `share_clipboard_and_notify`).

---

## 4. Security & Policy Enforcement

### 4.1 Principal Separation: `AI_MCP` vs `OWNER_MANUAL`

SNOW enforces strict separation of callers:
1. **`SecurityPrincipal.AI_MCP`**: Invoked by an AI agent (Claude Desktop, Antigravity, Cursor) via MCP stdio or Remote MCP Gateway. Sensitive actions (screen capture, camera capture, file transfers) are gated by `ApprovalPolicyEngine`. Execution pauses and creates a pending approval request.
2. **`SecurityPrincipal.OWNER_MANUAL`**: Invoked directly by the device owner via the Web Dashboard or local CLI. Pre-authorized; does not require self-approval prompts.

### 4.2 Non-Bypassable Cryptographic Approval Tokens

When an approval request is confirmed by the operator:
- `ApprovalPolicyEngine` generates a single-use cryptographically random token (`secrets.token_urlsafe(32)`).
- The token is tied to a specific `(principal, action, target_device, params_hash)`.
- The token expires after a configurable TTL (default: 300 seconds).
- `CapabilityEngine.execute()` requires and consumes the token atomically. Replays and parameter modifications are rejected.

### 4.3 64 KiB WSS Boundary & Out-of-Band HTTPS Transfer

- **WebSocket Control Plane (Port 8765):** Strictly limited to messages $\le 65,536$ bytes. Any frame exceeding 64 KiB is rejected immediately at the wire validator level with `PAYLOAD_TOO_LARGE`.
- **Out-of-Band Transfer (Port 8766):** All binary payloads, desktop screenshots, and camera photos are transferred over authenticated HTTPS using cryptographic transfer tickets. Zero image bytes are ever transmitted as Base64 strings over WebSockets.

---

## 5. Device Networking & Remote Topology

### 5.1 Local-First Routing Hierarchy

```
[ AI Assistant ] -> [ CapabilityEngine ] -> [ SessionRouter ]
                                                  |
                  +-------------------------------+-------------------------------+
                  |                               |                               |
          1. Direct LAN WSS               2. USB ADB Reverse              3. Remote Relay
          (Fastest, Low Latency)          (Zero-Data, AP Bypass)          (Out-of-LAN Fallback)
```

1. **Direct LAN:** Connects via authenticated WSS (`wss://<ip>:8765`) over local Wi-Fi.
2. **Zero-Data USB:** Uses ADB reverse port forwarding (`adb reverse tcp:8765 tcp:8765`) to establish a physical USB loopback link when Wi-Fi is unavailable or AP isolation blocks client-to-client traffic.
3. **Remote Relay:** Automatically routes through the SNOW Relay Server (`wss://relay:8770`) using TLS 1.3 MemoryBIO and device session token routing when peers are on different networks.

### 5.2 Remote MCP Streamable HTTP Gateway (Phase 23)

- **Port 8771** serves remote MCP clients.
- Compliant with **OAuth 2.1 (RFC 6749 / RFC 7636)**:
  - Authorization code exchange with mandatory PKCE (`code_challenge` / `code_verifier`).
  - Strict loopback redirect URI validation.
  - Ephemeral client registration.
  - Token-bucket rate limiting on `/oauth/token`.

---

## 6. Android Platform & OS Privacy Architecture

SNOW Android runtime respects all modern Android security paradigms:

1. **Android 14+ Foreground Service:**
   `SnowForegroundService` runs with type `connectedDevice` and `mediaProjection`. It maintains an ongoing system notification so the OS does not terminate the connection in Doze mode.
2. **MediaProjection Token Lifecycle:**
   Android strictly prohibits silent screen capture. Screen capture requires launching an interactive system consent dialog (`MediaProjectionManager.createScreenCaptureIntent()`). The resulting token is used to create a short-lived `VirtualDisplay`, capture a frame into an `ImageReader`, and immediately release all resources.
3. **Active Camera Preview Requirement:**
   Background camera access is blocked on Android 11+. Camera capture in SNOW is tied to a user-visible activity with live preview feedback.
4. **Android 10+ Background Clipboard Restrictions:**
   The Android OS blocks reading clipboard text in the background. Inbound clipboard synchronization from Windows is delivered via Android push notifications and written to the Android clipboard upon user activation.
5. **AndroidPeerHostManager Quarantine:**
   Multi-phone federation (`AndroidPeerHostManager`) is marked `IS_QUARANTINED = true`. It is kept in a verified, non-active state until multi-phone physical testing is conducted.

---

## 7. Resource Benchmarking (Lenovo V15 Target)

Empirical testing on the Lenovo V15 (Intel Core i5-1235U, ~7.9 GB RAM, Windows 11) confirms sub-second startup and low idle memory footprints across full process trees and verified operational readiness:

```
============================================================================
Component          | Startup Latency  | Aggregate RSS  | CPU %    | Status
----------------------------------------------------------------------------
Core Daemon        | 0.776 s          | 58.3 MB        | 0.0 %    | SUCCESS
Web Dashboard      | 1.047 s          | 81.2 MB        | 0.0 %    | SUCCESS
MCP stdio          | 0.700 s          | 72.1 MB        | 0.0 %    | SUCCESS
MCP Gateway        | 1.062 s          | 82.1 MB        | 0.0 %    | SUCCESS
Relay Server       | 0.536 s          | 44.7 MB        | 0.0 %    | SUCCESS
============================================================================
```

### Measurement Methodology
- **Process Tree Discovery:** `[ps_proc] + ps_proc.children(recursive=True)` aggregates real memory and CPU without double-counting launcher shims.
- **True Readiness Verification:**
  - *Core Daemon:* Verified via active WSS socket connection on port 8765.
  - *Web Dashboard:* Verified via HTTP loopback socket on port 8779.
  - *MCP stdio:* Verified via end-to-end JSON-RPC `initialize` protocol exchange over stdin/stdout.
  - *MCP Gateway:* Verified via Streamable HTTP socket connection on port 8781.
  - *Relay Server:* Verified via TLS 1.3 MemoryBIO socket connection on port 8770.
- **Resource Discipline:** Clean process tree termination prevents orphaned background processes. Idle CPU utilization remains at 0.0% across all components.
