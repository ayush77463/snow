# SNOW — Synthesized Node Orchestration Wireless (`v7.0.0` Pre-Release)

[![Version](https://img.shields.io/badge/version-7.0.0-blue.svg)](pyproject.toml)
[![Python](https://img.shields.io/badge/python-3.13-brightgreen.svg)](https://python.org)
[![Android](https://img.shields.io/badge/android-14--17-green.svg)](android/)
[![Architecture](https://img.shields.io/badge/architecture-Local--First%204--Layer-orange.svg)](ARCHITECTURE.md)

**SNOW** (*Synthesized Node Orchestration Wireless*) is a headless, local-first, cross-device AI capability bridge. It enables compatible AI assistants (Claude Desktop, ChatGPT Desktop, Google Gemini & Antigravity) to perform explicitly authorized operations across a Windows laptop, Android smartphones, and consented peer devices through a standardized [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) interface.

---

## What's New in SNOW V7 (`7.0.0`)

- **Hardened Pairing, Revocation & Android Trust (Milestone 1):** Authoritative QR pairing with strict Token/PIN separation, authenticated SNOW ID directory resolution, fail-closed relay secret handling, consolidated idempotent unpair/revocation, Share Code authority guards, safe battery optimization settings routing, and fail-closed Android release signing (`versionCode = 5`).
- **Universal Clipboard (Milestone 2):** Thread-safe persistent **15-item** multi-format queue (max **5 pinned**, **100 MiB** persisted media budget) supporting `text`, `image`, `file`, and `file_bundle` (Windows `CF_HDROP`), cross-process Core IPC image previews, zero-echo propagation, durable per-device acknowledgements, and resumable SHA-256 HTTPS file delivery (`:8766`) into Android user-selected Transfer Folders.
- **Refined Cross-Platform UX & Multi-Device Stabilization (Milestones 3A–3B):** Unified snowflake emblem from `design/snow.png`, Windows Web UI (`Home`, `Clipboard`, `Files & Apps`, `Devices`, `AI & Settings`) & Android Compose (`Home`, `Tools`, `Devices`, `Settings`) polish, Play Protect compliance, and removal of legacy XML UI artifacts.
- **Reliability, Universal Pairing & 16 GiB Streaming (Milestones 4.1–4.2):** Single-instance Core/tray lifecycle and browser polling stability, WebSocket generation guards, streaming SHA-256 transfers up to **16 GiB**, live QR v2 + PIN rendezvous, Mutual Network Merge vs Keep Separate conflict resolution, and phone-to-phone peer streaming.
- **Intelligent Transport Orchestration (Milestone 4.3):** Unified priority routing (`USB -> Hotspot -> Wi-Fi LAN -> Remote Relay`), make-before-break switching, bidirectional USB ADB tunneling, and accurate transfer-socket route attribution.
- **Permanent Device Identity & Native Android MCP (Milestone 4.4):** Persistent per-device Ed25519 keys deriving canonical `SNW-XXXX-XXXX` identities with cryptographic recovery (`SNW-REC-V1` & passphrase-encrypted backup), per-device Render Hub URL routing (hub acts solely as transport/rendezvous, never a trust root), standalone native Android MCP + OAuth 2.1 + PKCE (`S256`), and expansion to **60 MCP tools** / **SQLite Schema v8**.
- **Final UI Parity & Security Controls (Milestone 4.5):** Immediate zero-PIN live QR v2 pairing with optional 6-digit PIN + pasteable QR v2 JSON validation, streamlined 3-card AI assistant hub (Claude, ChatGPT, Gemini & Antigravity), top-level Remote AI Link toggle + Authorized AI Clients revocation UI, collapsed Advanced Settings with Cryptographic Identity Recovery modals, and clear `"Transfer Folder"` terminology across Android.

---

## Four-Layer Architecture

SNOW preserves a strict four-layer architecture with frozen security and transport boundaries:

```text
+-----------------------------------------------------------------------------+
| Layer 1: AI Integration                                                     |
| - FastMCP stdio Server (60 tools, JSON-RPC 2.0 on pure stdout; stderr logs) |
| - Remote MCP Streamable HTTP Gateway (:8771, OAuth 2.1 + PKCE S256, CIMD)   |
| - Native Standalone Android MCP Responder (OAuth 2.1 + PKCE via Render Hub) |
| - Per-Device Render Hub Remote AI Link (`snow expose` / Web & Android UI)   |
| - Headless Companion Web Dashboard (`127.0.0.1:8769`, zero external CDNs)   |
| - Win32 System Tray Companion (`snow-tray.exe`, lightweight ctypes)          |
| - Unified CLI (`snow setup`, `snow doctor`, `snow daemon`, `snow devices`)  |
+-----------------------------------------------------------------------------+
                                      |
+-----------------------------------------------------------------------------+
| Layer 2: Capability Engine & Policy Authority                               |
| - 60-Tool FastMCP Capability Catalog (`src/snow/mcp/registry.py`)           |
| - Permanent Per-Device Ed25519 Identity (`SNW-XXXX-XXXX`) & Recovery        |
| - Dual-Principal Enforcement (`AI_MCP` restricted vs `OWNER_MANUAL`)        |
| - 5-Tier Access Profiles (`full_control`, `files_and_clipboard`,            |
|   `files_only`, `clipboard_only`, `not_allowed`) — fail-closed default      |
| - Mutual Network Merge / Keep Separate Isolation & Authorized OAuth Revoke  |
| - Universal Clipboard Engine (15-item ring buffer, Schema v8 SQLite)        |
+-----------------------------------------------------------------------------+
                                      |
+-----------------------------------------------------------------------------+
| Layer 3: Device Networking & Transport                                      |
| - SNOW Device Protocol v1 (`228/228` bidirectional wire fixtures)           |
| - Priority Routing: USB ADB -> Hotspot -> Wi-Fi LAN -> Remote Relay (:8770) |
| - WSS Control Plane (:8765): metadata only, strict <= 64 KiB frame limit    |
| - HTTPS Transfer Plane (:8766): resumable SHA-256 chunks up to 16 GiB       |
| - Render Hub Transport & Rendezvous (zero trust authority; local E2E trust) |
| - Core Loopback IPC (:8767) & UDP Discovery (:8768)                         |
+-----------------------------------------------------------------------------+
                                      |
+-----------------------------------------------------------------------------+
| Layer 4: Device Runtimes                                                    |
| - Windows Python 3.13 Core (`asyncio`, SQLite Schema v8, CF_HDROP, Win32)   |
| - Android Kotlin + Jetpack Compose app (`minSdk 26`, `targetSdk 34`,        |
|   Keystore AES-GCM tokens, user-selected Transfer Folder, MediaProjection)  |
+-----------------------------------------------------------------------------+
```

---

## Quickstart (Windows + Android)

### 1. Environment Setup (Python 3.13 Required)

```powershell
cd "D:\Codes 2\Snow"
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

### 2. Start Core & Companion Web UI

```powershell
# Start headless background Core daemon
.\.venv\Scripts\python.exe -m snow daemon start

# Open companion Web Dashboard (http://127.0.0.1:8769)
.\.venv\Scripts\python.exe -m snow web
```

*(Alternatively launch `snow-tray.exe` from the local pre-release bundle in `dist\snow\` or install via `packaging\output\SNOW-Setup-7.0.0.exe`.)*

### 3. Configure AI MCP Hosts & Run Diagnostics

```powershell
# Configure Gemini CLI / Antigravity / Claude Desktop / ChatGPT / Remote MCP
.\.venv\Scripts\python.exe -m snow setup --host all

# Verify 60-tool FastMCP catalog, schema, runtime, and readiness
.\.venv\Scripts\python.exe -m snow doctor --json
```

### 4. Local Pre-Release Packaging (Owner QA)

```powershell
# Build signed release Android APK (requires android/keystore.properties or SNOW_KEYSTORE_* env)
Push-Location android; .\gradlew.bat assembleRelease --no-daemon; Pop-Location

# Build PyInstaller bundle, Inno Setup installer, Web UI ZIP, and OTA manifest
.\.venv\Scripts\python.exe packaging\windows\build_release.py
```

Outputs land locally in `packaging\output\` (`SNOW-Setup-7.0.0.exe`, `SNOW-Mobile-7.0.0.apk`, `snow-web-ui-7.0.0.zip`, `update_manifest.json`) for physical device verification on Lenovo V15 & Realme P4 before public `v7.0.0` release tagging.

---

## Android 14–17 Platform & Security Invariants

- **Strict Protocol & Port Boundaries:** Control traffic stays under 64 KiB on WSS `:8765`; all files, screenshots, camera photos, and clipboard binaries transfer over authenticated HTTPS `:8766`. Core IPC (`:8767`) and Web UI (`:8769`) bind strictly to loopback `127.0.0.1`.
- **Android Storage & Hardware Reality:** Uses hardware-backed Android Keystore AES-GCM (never deprecated `EncryptedSharedPreferences`), SAF/MediaStore scoped storage (`READ_MEDIA_IMAGES` / user-picked folder), interactive `MediaProjection` consent for screen capture, and honest Foreground Service reconnect backoff without claiming permanent Doze immunity.
- **No Arbitrary Shell & No Credential Leaks:** Application launching uses explicit allowlists, file operations stay path-contained, and `stdout` is strictly reserved for MCP JSON-RPC frames (`sys.stderr` logging only).
