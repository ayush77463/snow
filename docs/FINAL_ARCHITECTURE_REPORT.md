# SNOW: A Headless, Cross-Device AI Capability Bridge
## Final Comprehensive System Architecture, Security & Engineering Report

**Author / Project Lead**: Ayush<br/>
**Academic Degree**: Bachelor of Technology (B.Tech) — 7th Semester Capstone Project<br/>
**Department**: Computer Science and Engineering<br/>
**Repository**: `D:\Codes 2\Snow`<br/>
**Document Version**: 1.0 (Final Integration & Architecture Baseline)<br/>
**Date of Verification**: November 2026

---

## A. Executive Summary

### 1. Project Purpose & Problem Statement
Modern personal computing is fragmented across desktop operating systems (e.g., Windows) and mobile operating systems (e.g., Android). Emerging conversational AI assistants (such as Google Antigravity, Claude Desktop, and ChatGPT) operate as software agents with advanced reasoning capabilities, yet they lack standardized, safe, and hardware-grounded execution capabilities on user devices.

Existing remote management tools (e.g., SSH, RDP, TeamViewer, ADB-over-Wi-Fi) either introduce catastrophic security vulnerabilities by exposing raw shell access, require cloud relays that compromise data privacy, or demand continuous manual interaction through complex user interfaces.

### 2. The SNOW Solution
**SNOW** is an open-source, headless, cross-device AI capability bridge. It establishes an explicitly authorized, bidirectional operational bridge that allows compatible AI assistants to execute authorized commands on a Windows host and an Android mobile device through the standardized Model Context Protocol (MCP).

### 3. Key Contributions
- **Strictly Scoped Headless Execution**: Zero arbitrary remote shell execution (`cmd`, `powershell`, or `Runtime.getRuntime().exec()`). All operations follow an explicit allowlist and scoped directory boundaries.
- **Dual-Plane Local Network Architecture**: Clean architectural separation between control-plane signalling (authenticated TLS/WSS) and data-plane binary streaming (authenticated HTTPS).
- **Hardware-Backed Cryptographic Security**: Trust-On-First-Use (TOFU) SHA-256 certificate pinning on Android, hardware-backed Android Keystore AES-GCM token encryption, constant-time comparison attacks mitigation (`hmac.compare_digest`), and Windows user-access control lists (`icacls`) for local IPC.
- **Cross-Language Wire Protocol Parity**: A formal bidirectional test fixture suite confirming 100% serialization and validation parity (144 verified envelopes) across Python and Kotlin.
- **Empirically Verified on Physical Hardware**: Verified on a Windows 11 host and a physical Realme RMX5110 smartphone running Android 17.

---

## B. System Architecture & Component Topology

SNOW follows a strict four-tier architecture designed around least privilege, loopback process isolation, and network boundary enforcement.

```
+-----------------------------------------------------------------------------+
|                                AI HOST                                      |
|            (e.g., Google Antigravity, Claude Desktop, LLM Agent)            |
+-----------------------------------------------------------------------------+
                                      |
                       MCP JSON-RPC over stdio
                                      v
+-----------------------------------------------------------------------------+
|                            SNOW MCP SERVER                                  |
|            (FastMCP Server Subprocess, Stdout Exclusively Reserved)         |
+-----------------------------------------------------------------------------+
                                      |
                 Authenticated Loopback IPC (127.0.0.1:8767)
                     Using Windows ACL-Protected Secret
                                      v
+-----------------------------------------------------------------------------+
|                          SNOW DESKTOP CORE                                  |
|  - Connection Manager             - SQLite Device & Audit Database          |
|  - Session Manager                - Pairing & PIN Manager                   |
|  - Windows Capability Engine      - Transfer Manager (Staging & SHA-256)    |
|  - WSS Control Server (0.0.0.0:8765) - HTTPS Transfer Server (0.0.0.0:8766) |
+-----------------------------------------------------------------------------+
               |                                            |
   Control Plane: TLS 1.2+ WSS                  Data Plane: HTTPS Streaming
       (Port 8765, JSON Envelopes)                  (Port 8766, 64 KiB Chunks)
               \                                            /
                v                                          v
+-----------------------------------------------------------------------------+
|                        ANDROID CLIENT APPLICATION                           |
|  - Foreground Service (Connected Device)  - Hardware Keystore (AES-GCM)     |
|  - TOFU SnowTrustManager & Pinning        - Capability Dispatcher           |
|  - Scoped Storage (Downloads/SNOW)        - OkHttp WSS & HTTPS Clients      |
+-----------------------------------------------------------------------------+
```

### The Three Operational Channels

| Channel | Protocol & Transport | Network Endpoint | Primary Responsibility |
| :--- | :--- | :--- | :--- |
| **AI Host Interface** | MCP JSON-RPC 2.0 via `stdio` | Subprocess Standard I/O | Tool schema discovery and structured invocation. `stdout` is strictly reserved for JSON-RPC frames. |
| **Local Bridge IPC** | Authenticated JSON-RPC over loopback TCP | `127.0.0.1:8767` | Isolates the AI client's ephemeral subprocess from the persistent Desktop Core daemon. |
| **Network Control Plane** | SNOW Device Protocol v1 over TLS 1.2+ WSS | `0.0.0.0:8765` | Device pairing, mutual authentication, keepalives, notifications, and capability dispatch. |
| **Network Data Plane** | Authenticated HTTPS Binary Streaming | `0.0.0.0:8766` | Reliable large-file streaming, chunking (64 KiB), resume support, and SHA-256 integrity checks. |

### Architectural Invariant: Why Control and Data Planes are Separated
WebSocket frames are designed for lightweight, low-latency, bidirectional message passing. Transmitting large binary files (e.g., 500 MB videos) across a WebSocket connection causes:
1. **Head-of-Line Blocking**: Heartbeats and control commands cannot interleave, triggering false timeout disconnects.
2. **Buffer Bloat & Memory Exhaustion**: WebSocket framing buffers payloads in user memory before delivery.
3. **Loss of HTTP Transport Semantics**: HTTP provides native byte-range streaming (`Range: bytes=X-`), standard status codes (200, 206, 404, 422), and mature kernel-level streaming primitives (`aiohttp` / `OkHttp`).

SNOW isolates control frames to WSS port `8765` and binary streaming to HTTPS port `8766`.

---

## C. SNOW Device Protocol v1 & Cross-Language Parity

### 1. Message Structure
All control-plane communication adheres to the **SNOW Device Protocol v1** specification:

```json
{
  "version": 1,
  "type": "request | response | error | heartbeat | heartbeat_ack",
  "id": "urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "timestamp": "2026-11-16T22:20:00Z",
  "correlation_id": "urn:uuid:...",
  "payload": { ... },
  "error": { "code": "...", "message": "..." }
}
```

### Invariants Enforced on the Wire:
- **Exact Schema Enforcement**: `version` must be integer `1`; `id` must be a valid UUIDv4 string; `timestamp` must be ISO-8601 UTC with explicit timezone indicator (`Z`).
- **Null Omission Rule**: Optional keys (`correlation_id`, `payload`, `error`) must be omitted entirely from the serialized JSON string when absent. Explicit nulls (`"payload": null`) are rejected.
- **Maximum Frame Bounding**: Maximum single message size is capped at 65,536 bytes (64 KiB) to prevent memory denial-of-service attacks.

### 2. Bidirectional Parity Fixture Suite
To guarantee that the Python Desktop Core and Kotlin Android app never deviate in protocol semantics, the project implements an automated, bidirectional cross-language test harness (`scripts/run_cross_language_tests.py`):
- **Direction A (Kotlin $\rightarrow$ Python)**: Android JVM tests export 45 valid and 27 negative JSON fixtures; Python's `validate_raw_message()` parses and validates every envelope.
- **Direction B (Python $\rightarrow$ Kotlin)**: Python generates 45 valid and 27 negative fixtures; Android's `ProtocolValidator.kt` parses and validates every envelope.
- **Result**: **144 / 144 fixtures pass (100% wire-level parity)** across all 7 capability schemas.

---

## D. Cryptography, Security Boundaries & Threat Modeling

| Threat Vector | Mitigation Strategy in SNOW | Verified Code Location |
| :--- | :--- | :--- |
| **Man-in-the-Middle (MitM)** | TLS 1.2+ enforced; Trust-On-First-Use (TOFU) SHA-256 certificate pinning on Android. | `src/snow/security/tls.py`<br/>`android/.../SnowTrustManager.kt` |
| **Credential Theft at Rest** | Android Keystore hardware-backed master key (AES-GCM); encrypted in TEE/StrongBox. | `android/.../EncryptedCertPinStorage.kt` |
| **Token Brute-Force / Timing Attacks** | Cryptographic 256-bit random tokens, SHA-256 hashed in SQLite, constant-time `hmac.compare_digest`. | `src/snow/security/session.py`<br/>`src/snow/security/pairing.py` |
| **Unauthorized Local Process Access** | Loopback IPC bound to `127.0.0.1:8767`, protected by random 256-bit token with Windows ACL (`icacls`). | `src/snow/core/ipc.py` |
| **Path Traversal Attacks** | Strict canonical resolution (`resolve()`), whitelist root scoping, anti-traversal validation. | `src/snow/capabilities/windows/files.py` |
| **Arbitrary Code Execution** | Strict application whitelist (`notepad`, `calc`, `explorer`, `taskmgr`, `mspaint`). | `src/snow/capabilities/windows/apps.py` |
| **Data Integrity Corruption** | Incremental SHA-256 computation over 64 KiB chunks; atomic `.part` staging commit. | `src/snow/transfer/http_server.py`<br/>`android/.../AndroidFileHandler.kt` |

---

## E. Windows System Capabilities (Phase 5)

SNOW exposes four core Windows capability modules to the AI assistant through standardized MCP tools:

1. **System & Battery Telemetry (`snow_windows_battery`, `snow_windows_system_info`)**:
   - Gathers CPU utilization percentage, RAM available/total, disk capacity, Windows build version, system uptime, and battery health via `psutil`.
2. **Process Monitoring (`snow_windows_processes`)**:
   - Enumerates active processes with PID, process name, CPU percent, and memory footprint.
   - Constrained to prevent leaking sensitive command-line parameters or process environment variables.
3. **Scoped Filesystem Engine (`snow_windows_file_read`, `snow_windows_file_write`, `snow_windows_file_list`)**:
   - Access is restricted exclusively to user-configured directories (`~/.snow/transfers`, `~/Documents/SNOW`).
   - Any path resolving outside permitted roots via `../` or symlinks is rejected immediately with `PATH_TRAVERSAL_DETECTED`.
4. **Allowlisted Application Launcher (`snow_windows_launch_app`)**:
   - Restricts application launching to an explicit whitelist of safe system executables (`notepad`, `calc`, `explorer`, `taskmgr`, `mspaint`). Non-allowlisted binaries are rejected with `APP_NOT_ALLOWED`.

---

## F. Android Control Capabilities (Phase 6)

The native Android client implements seven authorized capabilities, managed by `AndroidCapabilityDispatcher.kt`:

1. **Hardware Telemetry (`snow_android_battery`)**:
   - Queries `BatteryManager` broadcast intent for live percentage, charging status (AC/USB/Wireless), battery health, temperature, device model (`RMX5110`), and Android release (`17`).
2. **Audible Alert / Find My Phone (`snow_android_ring`)**:
   - Uses `RingtoneManager` with `AudioAttributes.USAGE_ALARM` (`STREAM_ALARM`) to sound an audible alert for a bounded duration (1–15 seconds).
3. **User-Authorized Clipboard Push (`snow_android_clipboard_push`)**:
   - Writes desktop text directly to the Android `ClipboardManager`. Bounded to 64 KiB.
   - *Security Note*: In compliance with Android 10+ privacy restrictions, background clipboard *reading* is strictly prohibited and not implemented.
4. **App Listing (`snow_android_list_apps`)**:
   - Uses `PackageManager.queryIntentActivities()` with `<queries>` package visibility to enumerate user-launchable applications.
5. **Application Launching (`snow_android_launch_app`)**:
   - **Android 10–17 OS Reality**: Under Android Background Activity Launch (BAL) restrictions, non-interactive background services cannot bring an Activity to the foreground without user mediation. When SNOW is in the foreground, `startActivity()` with `FLAG_ACTIVITY_NEW_TASK` succeeds immediately. When backgrounded, BAL policies apply.
6. **Scoped Storage File Transfer (`snow_android_file_send`, `snow_android_file_receive`)**:
   - Receives files streamed from the desktop over HTTPS (port 8766) and writes directly to scoped storage under `Downloads/SNOW` (`/storage/emulated/0/Android/data/org.snow/files/Download/SNOW/`).

---

## G. Large-File Transfer Architecture & Verification

The data plane handles reliable file transmission without loading entire files into memory:
1. **WebSocket Pre-Negotiation**: The desktop and mobile client exchange a metadata envelope (`file_transfer_offer` / `file_send_request`) containing filename, file size, SHA-256 hash, and transfer ID.
2. **Streaming Transfer**: Binary payload streams over HTTPS (port 8766) in fixed 64 KiB chunks. Memory usage remains constant ($O(1)$) regardless of whether transferring 100 KB or 10 GB.
3. **Staging & Atomic Commit**: Incoming bytes are written to a temporary staging file (`<uuid>.part`).
4. **Cryptographic Integrity**: Both ends compute SHA-256 incrementally as chunks pass through network buffers. If the computed hash matches the pre-negotiated hash, the file is atomically renamed to its final target path. If hashes mismatch, the `.part` file is deleted immediately and HTTP 422 Unprocessable Entity is returned.
5. **Duplicate Prevention**: If a file with matching SHA-256 already exists in the transfer database, binary transmission is skipped entirely, saving bandwidth and battery.

---

## H. Comprehensive Verification & Empirical Results

### Summary Test Matrix

| Verification Domain | Test Suite / Tool | Passing / Total | Status |
| :--- | :--- | :---: | :---: |
| **Python Core & Capabilities** | `unittest discover -s tests` | **174 / 174** | **PASS** |
| **Android JVM Unit Tests** | `gradlew.bat testDebugUnitTest` | **75 / 75** | **PASS** |
| **Bidirectional Wire Parity** | `scripts/run_cross_language_tests.py` | **144 / 144** | **PASS** |
| **Android Debug Compilation** | `gradlew.bat assembleDebug` | **Clean Build (0 errors)** | **PASS** |
| **End-to-End Pipeline Demo** | `scripts/e2e_demo_flow.py` | **6 / 6 Stages** | **PASS** |
| **Physical Hardware Acceptance** | Realme RMX5110 (Android 17, API 36) | **7 / 7 Capabilities** | **PASS** |

### Empirical Physical Hardware Observations (Realme RMX5110)
- **Battery Query**: Returned `78%`, `charging: Yes (USB)`, `model: RMX5110`, `Android 17`.
- **Clipboard Push**: Pushed 56 UTF-8 bytes; verified by pasting in mobile notes app.
- **App Enumeration**: Successfully enumerated installed applications (`Calculator`, `Camera`, `Calendar`, etc.).
- **App Launch**: Successfully launched native Calculator (`com.coloros.calculator`) onto the device screen.
- **File Send to Phone**: Streamed `snow_phase6_test.txt` over HTTPS port 8766 to scoped storage; SHA-256 verified.
- **Audible Alert**: Triggered 3-second audible alarm over `STREAM_ALARM`.

---

## I. Known Limitations & Future Work

1. **Android Background Activity Launch (BAL)**:
   - *Limitation*: When the SNOW Android app is running solely as a background service without recent UI interaction, Android 10+ BAL policies restrict direct activity launching.
   - *Future Work*: Implement a notification-mediated tap action with `PendingIntent` to prompt user authorization when launching apps from background state.
2. **Wi-Fi Access Point (Client) Isolation**:
   - *Limitation*: Certain commercial or public Wi-Fi routers (e.g., JioFiber / AirFiber default profiles) block inter-client Layer 2 communication.
   - *Workarounds Verified*: Mobile Hotspot connection topology or USB reverse tunneling (`adb reverse tcp:8765 tcp:8765`).
   - *Future Work*: Add mDNS / NSD discovery probes with explicit subnet isolation diagnostics.
3. **Encrypted at Rest Local Staging**:
   - *Future Work*: Add AES-GCM envelope encryption for staged transfer files on Windows disk.

---

## J. Conclusion

SNOW successfully bridges the capability gap between modern AI conversational hosts and physical client devices. By adhering to strict least-privilege boundaries, separating control signalling from data streaming, implementing hardware-backed cryptography, and verifying 100% cross-language protocol parity, the project delivers a secure, thesis-grade capability infrastructure ready for academic defense and real-world deployment.
