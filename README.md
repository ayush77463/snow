# SNOW V3 — AI-Native Cross-Device Capability Platform

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](pyproject.toml)
[![Python](https://img.shields.io/badge/python-3.13-brightgreen.svg)](https://python.org)
[![Android](https://img.shields.io/badge/android-14--17-green.svg)](android/)
[![Architecture](https://img.shields.io/badge/architecture-Local--First%204--Layer-orange.svg)](docs/ARCHITECTURE_V3.md)

**SNOW** (Synthesized Node Orchestration Wireless) is a lightweight, headless cross-device AI capability bridge. It allows compatible AI assistants (Claude Desktop, Google Antigravity, Cursor, ChatGPT Desktop) to perform explicitly authorized operations across a Windows laptop and an Android mobile device through the standardized [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).

---

## Architecture Overview

SNOW preserves a strict 4-layer architecture with non-negotiable security boundaries:

```
+-------------------------------------------------------------------------+
| Layer 1: AI Integration                                                 |
| - MCP stdio Server (JSON-RPC 2.0 over standard I/O)                    |
| - Remote MCP Streamable HTTP Gateway (Port 8771, OAuth 2.1 + PKCE)      |
| - Web Dashboard (Port 8769, Loopback only, Zero CDN dependencies)       |
| - Unified CLI (`snow setup`, `snow devices`, `snow doctor`, etc.)       |
+-------------------------------------------------------------------------+
                                    |
+-------------------------------------------------------------------------+
| Layer 2: Capability Engine & Policy Authority                           |
| - Dynamic 34-Tool Capability Catalog                                    |
| - ApprovalPolicyEngine (Security Principals: AI_MCP vs OWNER_MANUAL)    |
| - Cryptographic one-time approval tokens & timeout enforcement          |
| - Multi-step workflow orchestration with partial failure handling       |
+-------------------------------------------------------------------------+
                                    |
+-------------------------------------------------------------------------+
| Layer 3: Device Networking & Transport                                  |
| - Local-First Discovery & Transport Hierarchy (LAN -> USB ADB -> Relay) |
| - Encrypted WSS Control Plane (Port 8765, 64 KiB strict frame limit)    |
| - Authenticated HTTPS Out-of-Band Transfer (Port 8766, zero image Base64) |
| - NodeRegistry, SessionRouter, TLS 1.3 certificate pinning             |
+-------------------------------------------------------------------------+
                                    |
+-------------------------------------------------------------------------+
| Layer 4: Device Runtime                                                 |
| - Windows Python Runtime (Desktop status, clipboard, screen capture)    |
| - Android Kotlin Runtime (Foreground Service, MediaProjection capture)  |
+-------------------------------------------------------------------------+
```

---

## Consumer Quickstart

### 1. Prerequisites & Virtual Environment

SNOW requires Python 3.13 on the host laptop and Android 14+ on the mobile client.

```powershell
# Clone repository and navigate to directory
cd "D:\Codes 2\Snow"

# Create and activate Python 3.13 virtual environment
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install SNOW in editable development mode
pip install -e .
```

### 2. Starting SNOW Core Services

SNOW runs as a headless desktop core daemon with an accompanying local-only web dashboard.

**Terminal 1 — Start the Core Daemon:**
```powershell
.\.venv\Scripts\python.exe -m snow daemon start
```
*(Alternatively, run directly in foreground mode with live console diagnostics: `python -m snow`)*

**Terminal 2 — Launch the Web Dashboard:**
```powershell
.\.venv\Scripts\python.exe -m snow web
```
The Web Dashboard opens automatically at `http://127.0.0.1:8769`.

### 3. Pairing an Android Device

1. In PowerShell, generate a pairing session:
   ```powershell
   .\.venv\Scripts\python.exe -m snow pair
   ```
   Or navigate to the **Devices** tab in the Web Dashboard (`http://127.0.0.1:8769`).
2. Scan the QR code or enter the 6-digit PIN in the SNOW Android application.
3. Upon mutual PIN verification, self-signed TLS certificates are pinned and trust tiers (`OWNER` vs `PEER`) are persisted in local SQLite storage.

### 4. Configuring MCP AI Hosts

To link your AI assistants directly to SNOW:

```powershell
# Configure specific hosts or all supported hosts (gemini, claude, cursor, chatgpt)
.\.venv\Scripts\python.exe -m snow setup --host gemini
.\.venv\Scripts\python.exe -m snow setup --host all

# Verify system readiness and configuration
.\.venv\Scripts\python.exe -m snow doctor
```

---

## Pre-Packaged Multi-Step Workflows

Available directly from the Web Dashboard (`http://127.0.0.1:8769`) or programmatically via the `snow_workflow_run` MCP tool:

1. **Device Health Snapshot (`device_health_snapshot`):**
   - Queries Windows laptop and paired Android phone simultaneously.
   - Summarizes CPU utilization, RAM usage, storage utilization, phone battery percentage, charging state, and active transport in side-by-side consumer cards.

2. **Capture PC Screen (`pc_screenshot`):**
   - Interactive consent-gated desktop capture.
   - Exposes an authenticated local preview URL (`/api/captures/<file_name>`).
   - Image bytes are transferred via out-of-band HTTPS (Port 8766) — never as Base64 over the WebSocket control channel.

3. **Capture PC → Phone (`capture_pc_to_phone`):**
   - Captures Windows desktop screenshot and stages it into the local encrypted transfer spool.
   - Initiates an out-of-band HTTPS push to the paired Android device storage.
   - Verifies SHA-256 integrity upon arrival.

4. **Sync Clipboard & Notify (`share_clipboard_and_notify`):**
   - Reads the current Windows clipboard content.
   - If non-empty, securely dispatches the text to the Android device clipboard (`clipboard_push`) and triggers a native Android notification.
   - Safely warns if the desktop clipboard is empty without failing or sending blank messages.

---

## Android 14–17 Platform & Privacy Architecture

Modern Android operating systems enforce strict sandboxing and user privacy boundaries:

| OS Reality | Platform Constraint | SNOW Architecture Solution |
| :--- | :--- | :--- |
| **Screen Capture** | Prohibits silent or headless screen capture without user consent. | Requires Android `MediaProjectionManager` permission token granted via interactive user prompt. Captures run via an active Foreground Service. |
| **Camera Access** | Background camera access is blocked by Android 11+. | Camera capture is restricted to an active foreground UI session with clear on-screen preview. |
| **Background Clipboard** | Background clipboard access is restricted on Android 10+. | Inbound clipboard sync is delivered via standard notification intents; push writes are applied when active. |
| **Doze Mode & Sleeping** | Battery management suspends background sockets on OEM builds. | SNOW implements a Foreground Service with persistent notification, automatic keepalive pinging, and exponential backoff reconnection. |
| **Zero-Data Transport** | Wi-Fi networks frequently isolate clients (AP isolation). | SNOW supports zero-data local USB mesh via ADB reverse port forwarding (`snow usb`). |

---

## Empirical Benchmark Results (Lenovo V15, Intel Core i5-1235U)

Empirical testing on real capstone target hardware (Lenovo V15, Intel Core i5-1235U, ~7.9 GB RAM, Windows 11) measuring full runtime process trees and verified operational readiness:

| Component | Startup Latency | Aggregate RSS | Idle CPU % | Verified Readiness Mechanism |
| :--- | :---: | :---: | :---: | :--- |
| **Core Daemon** | 0.776 s | 58.3 MB | 0.0 % | WSS socket connect (Port 8765) |
| **Web Dashboard** | 1.047 s | 81.2 MB | 0.0 % | HTTP loopback connect (Port 8779) |
| **MCP stdio** | 0.700 s | 72.1 MB | 0.0 % | Full JSON-RPC `initialize` protocol exchange |
| **MCP Gateway** | 1.062 s | 82.1 MB | 0.0 % | Streamable HTTP socket connect (Port 8781) |
| **Relay Server** | 0.536 s | 44.7 MB | 0.0 % | TLS 1.3 MemoryBIO socket connect (Port 8770) |

*Methodology: Script `scripts/benchmark_phase25_v3.py` launches each component, confirms operational readiness via real protocol handshakes/socket connects, samples CPU over a 1.5s window across `[proc] + proc.children(recursive=True)`, aggregates RSS without double-counting, and cleanly terminates all process trees. All components operate within the < 85 MB aggregate RSS budget on the Lenovo V15 test hardware.*

---

## Security Invariants

- **No Arbitrary Execution:** SNOW does not provide arbitrary bash/shell or raw command execution capabilities.
- **Strict Approval Separation:** Actions initiated by `AI_MCP` require interactive human confirmation. Only `OWNER_MANUAL` is authorized to approve or deny requests.
- **64 KiB WSS Limit:** All WebSocket messages are strictly capped at 64 KiB. Binary files and captured images must use authenticated HTTPS transfer on port 8766.
- **Loopback Enforcement:** IPC (8767) and Web Dashboard (8769) strictly bind to `127.0.0.1`.
