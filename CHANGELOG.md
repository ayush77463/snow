# SNOW Changelog

All notable changes to the SNOW platform are documented in this file.

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
