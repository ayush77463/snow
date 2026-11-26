# SNOW Changelog

All notable changes to the SNOW platform are documented in this file.

---

## [7.0.0] — Pre-Release Candidate (Milestones 1, 2, and 3A)

> Local pre-release build prepared for physical owner verification (Lenovo V15 + Realme P4 + Render Hub) prior to final `v7.0.0` release tagging.

### Milestone 1 — Pairing, Security, Revocation & Android Trust (`d46579c`)
- **Authoritative QR Pairing & Token/PIN Separation:** Separated short-lived pairing PIN entry from long-lived token authentication and enforced canonical identity matching.
- **Authenticated SNOW ID Directory:** Secured directory resolution for `SNW-XXXX-XXXX` endpoints.
- **Fail-Closed Relay Secret Handling:** Removed permissive fallbacks for relay/tunnel credentials.
- **Consolidated Idempotent Device Removal:** Unified revoke/unpair paths across Core, SQLite, Web UI, and Android.
- **Android Trust & Release Hardening:** Separated Trust Tier vs 5-tier permission profile handling, added Share Code authority/capability guards (`evaluateShareCodeEligibility`), replaced direct ignore-battery-optimization prompts with safe settings routing, and enforced fail-closed Gradle release signing.

### Milestone 2 — Universal Clipboard (`f361813`)
- **Persistent 15-Item Multi-Format Queue:** Thread-safe SQLite Schema v7 clipboard history supporting `text`, `image`, `file`, and `file_bundle` (up to 5 pinned items, 100 MiB persisted-media budget).
- **Windows & Android Capture/Apply Parity:** Added Windows `CF_HDROP` capture/apply, zero-echo deduplication, durable per-device acknowledgements, Android text/image system clipboard apply, and SAF-backed file/bundle delivery over resumable SHA-256 HTTPS (`:8766`).
- **Cross-Process Web Image Previews:** Routed authenticated Web UI clipboard thumbnail/image previews cleanly through Core loopback IPC (`127.0.0.1:8767`).

### Milestone 3A — Product Completion, UI/UX Polish, Branding & Packaging (`7.0.0`, `versionCode = 5`)
- **Universal Branding Regeneration:** Generated clean snowflake assets from `design/snow.png` for Windows `.ico`, Web UI PNG/ICO, and Android drawable/mipmap adaptive launchers; restored root `snow.png`.
- **Windows Web UI Refinement:** Reordered sidebar navigation (`Home -> Clipboard -> Files & Apps -> Devices -> AI & Settings`), refined `Devices` and `AI & Settings` layouts (`Handled automatically` Remote Access), preserved `8fr 4fr` desktop grid for Files & Apps down to `1280x720`, unified `.qr-surface` offline/active contrast, implemented 15-item 4-type Universal Clipboard UI, simplified Render-default Remote AI controls, and added async loading feedback.
- **Android Compose UI Refinement:** Reordered bottom tabs (`Home -> Tools -> Devices -> Settings`) with accessibility semantics, added bidirectional `HorizontalPager` + pill sync in `ToolsScreen` with state retention, replaced off-theme dark `#0F172A` / `#64748B` terminal colors with WCAG AA SNOW semantic tokens, and wired async loading/failure-recovery guards.
- **Verified Dead-File Cleanup:** Removed obsolete legacy XML layouts/drawables, Fragment/ViewModel screens, and scratch/deprecated helper scripts after repo-wide reference checks and unit test migration.
- **Dynamic Versioning & Documentation Alignment:** Promoted version to `7.0.0` / Android `versionCode = 5`, removed the hardcoded version code ceiling in `handle_app_update_info`, fixed `CoreConfig.from_env().version` and `snow_setup.iss` URL, and synchronized docs.

---

## [5.2.0] — V5 Stage 6C (`50ab0c9`)
- Added universal any-to-any live screen sharing across LAN/USB/Relay (`Screen` tab & Web viewer).
- Implemented battery, RAM, and data optimizations and Render Hub default discovery.
- Expanded FastMCP catalog to 54 tools, SQLite Schema v7, and `228/228` wire protocol parity fixtures.

## [5.1.0] — V5 Stage 5–6 (`2b0bcb4`, `a815a4e`)
- Introduced canonical `SNW-XXXX-XXXX` identity routing, 5-tier fail-closed permission profiles (`full_control`, `files_and_clipboard`, `files_only`, `clipboard_only`, `not_allowed`), direct signed APK/Web UI updater, and Windows release packaging pipeline.

## [5.0.0] — V5 Flagship Compose & Web V5 (`ee8c7cb`, `dcfd2e7`, `395bf96`)
- Rebuilt Android UI in Jetpack Compose Material 3 (`SnowTheme` Dark/Light) alongside the Windows Web V5 UI (`127.0.0.1:8769`) and expanded MCP catalog to 42 tools.

## [4.0.0] — V4 Local Mesh & Cross-Network Federation (Phases 26–30)
- Added `MediaProjection` screen capture, shared clipboard ring buffer, allowlisted app launcher, Win32 tray companion (`snow-tray.exe`), Inno Setup installer, and non-transitive Cross-Network Federation with 9-digit PINs and Emergency Kill Switch.

---

## [3.0.0] — 2026-11-21 (Phase 25 Release)

### Added
- **Multi-Step Composite Workflows (Phase 24 & 25):**
  - Added 4 pre-packaged consumer workflows: `device_health_snapshot`, `pc_screenshot`, `capture_pc_to_phone`, and `share_clipboard_and_notify`.
  - Structured Glacier/Obsidian consumer cards in the Web Dashboard (`#workflow-summary-card`) with side-by-side device metrics, authenticated capture previews, and collapsible technical JSON details.
  - Partial failure detection and graceful handling when paired peer nodes are offline.
- **Consent-Gated Screen & Camera Capture (Phase 24):**
  - Interactive approval user experience for `SecurityPrincipal.AI_MCP`, strictly resolvable only by `ExecutionPrincipal.OWNER_MANUAL`.
  - Android `MediaProjection` token lifecycle with system confirmation dialogs.
  - Native Windows desktop screenshot capture via Win32 GDI.
  - Out-of-band HTTPS capture preview (`http://127.0.0.1:8769/api/captures/<file_name>`) exposed on Web Dashboard port 8769, while full authenticated image/file transfer bytes are served through the transfer service on port 8766.
- **Remote MCP Streamable HTTP Gateway (Phase 23):**
  - OAuth 2.1 authorization code flow with mandatory PKCE (RFC 7636).
  - Streamable HTTP endpoint (`/mcp`) with Bearer token authentication on port 8771.
  - Token-bucket rate limiting and loopback redirect URI validation.
- **3-Plane Remote Relay (Phase 22):**
  - TLS 1.3 MemoryBIO encrypted WebSocket relay server on port 8770.
  - Tokenized message routing across presence, control, and transfer planes.
  - Rolling hourly transfer quota enforcement (100 MB default) and max frame size limits.
- **Zero-CDN Vanilla Web Dashboard (Phase 21):**
  - Local-only web dashboard on `http://127.0.0.1:8769` replacing legacy Textual TUI.
  - Complete device trust management (`OWNER` vs `PEER` tiers), QR code pairing, and live system status.
- **Zero-Data USB Transport (Phase 20):**
  - Automatic ADB reverse port forwarding (`snow usb`) for environments with restrictive Wi-Fi or AP isolation.
- **Ticket-Based Transfer & Hardening (Phase 19):**
  - Cryptographic single-use transfer tickets for file transfers.
  - Strict 64 KiB WebSocket control frame boundary enforcement.
- **Dynamic 34-Tool Capability Catalog Expansion:**
  - Expanded tool catalog from V2's 24 baseline static tools to V3's dynamic 34-tool capability registry with strict schema metadata.
- **Packaging & Low-Spec Empirical Benchmarking (Phase 25):**
  - Updated console entry points: `snow`, `snow-mcp`, `snow-relay`.
  - Verified low-spec footprint on Lenovo V15 across full process trees and live protocol readiness (< 85 MB RSS per process, idle CPU 0.0%).

### Changed
- Promoted version from `2.0.0` to `3.0.0` across `pyproject.toml`, `snow.__init__`, and `snow.cli`.
- Replaced Textual TUI with responsive, local-first Web Dashboard.
- Quarantined experimental Android-to-Android mesh (`AndroidPeerHostManager.IS_QUARANTINED = true`) pending physical verification.

---

## [2.0.0] — 2026-11-19 (Phase 18 Release)

### Added
- 24-tool baseline Capability Engine (`CapabilityRegistry`, `CapabilityEngine`).
- Centralized `SessionRouter` for routing requests across LAN, USB, and peer nodes.
- Device discovery and topology management (`NodeRegistry`).
- Unified host onboarding CLI (`snow setup`, `snow doctor`, `snow devices`).
- Cross-language wire protocol parity suite (228 automated JSON fixtures).

---

## [1.0.0] — 2026-11-16 (Phase 11 Release)

### Added
- Standard Model Context Protocol (MCP) stdio server implementation.
- Encrypted WebSocket control channel (port 8765) with pinned self-signed TLS certificates.
- Authenticated HTTPS out-of-band file transfer server (port 8766).
- Android Kotlin mobile runtime with background WebSocket client.
- Initial PIN/QR device pairing flow with SQLite device persistence.
