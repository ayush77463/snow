# SNOW V4 Architecture Specification (V4.0.0 Release Baseline)

**Project:** SNOW — Synthesized Node Orchestration Wireless  
**Version:** 4.0.0 (Phase 30 Final Release Baseline)  
**Classification:** Academic Capstone Architecture Specification & System Reference  
**Target Hardware:** Lenovo V15 (Intel Core i5-1235U, ~7.9 GB RAM, Windows 11) & Realme RMX5110 (Android 14–17 / ColorOS 17)  
**Execution Base:** Local-First, Zero-Cloud-Dependency, Strict 4-Layer Security Architecture  

---

## 1. Executive Summary & V4 Architectural Evolution

SNOW V4 expands the capability bridge into a multi-device local mesh and secure cross-network federation platform. It enables standardized AI assistants (Claude Desktop, Google Antigravity, Cursor, ChatGPT Desktop) to seamlessly discover, orchestrate, and invoke authorized capabilities across desktop computers, Android devices, and trusted peer networks through the Model Context Protocol (MCP).

### V4 Milestone Progression (Phases 26–30)

1. **Phase 26A: Real-Time Screen Streaming & Media Projection Lifecycle**
   - High-performance cross-process IPC screen-frame bridge between `snow daemon` and `snow web`.
   - Android 14+ `MediaProjection` foreground-service lifecycle management with prompt user consent and clean teardown.
   - Dual-mode Stop Sharing dispatch (desktop-initiated IPC command and device notification intent).
2. **Phase 26B: Shared Clipboard, Capture Hub & Authorized Remote App Launcher**
   - Ring-buffer shared clipboard with PIN/unpin, local PC image snapshot capture, and remote phone capture pull.
   - Secure remote app launcher restricted to explicit user-approved application whitelists on both Windows and Android.
3. **Phase 27: Multi-Device Local SNOW Network**
   - Persistent `network_identity` and `network_endpoints` data model (Schema v5).
   - 42-tool comprehensive MCP registry covering all capabilities (expanded cleanly in V5.0.0 from 38).
   - Safe principal-scoped network topology resource (`snow://network/topology`), preventing `AI_MCP` from inspecting sensitive LAN infrastructure.
4. **Phase 28A: Hybrid All-Pairs Remote Mesh**
   - TLS 1.3 MemoryBIO encrypted control & data tunnel for reliable out-of-LAN device presence.
   - Dynamic transport-tier fallback: Wi-Fi LAN → USB ADB reverse forwarding → Remote Relay Mesh.
5. **Phase 28B: Public Remote MCP Gateway Platform**
   - Streamable HTTP Gateway (Port 8771) with RFC 6749 / RFC 7636 OAuth 2.1 Code Flow and PKCE S256.
   - RFC 8414 Authorization Server Metadata and RFC 7591 Dynamic Client Registration.
   - Client ID Metadata Document (CIMD) validation for URL-based client identities.
   - Zero-port-forwarding public exposure via `snow expose` (Cloudflare Tunnel, ngrok, localxpose, bore).
   - 24/7 autonomous production deployment with Docker Compose, systemd, and Caddy reverse proxy.
6. **Phase 29: Standalone Distribution & Guided Consumer Onboarding**
   - Zero-prerequisite Windows standalone package using PyInstaller (`packaging/windows/snow.spec`) and Inno Setup 6 (`packaging/windows/snow_setup.iss`).
   - Ultra-lean Win32 System Tray Companion (`snow-tray.exe`, pure ctypes, RSS < 35 MB) with live telemetry and autostart toggle.
   - Android release APK signing and authenticated local network download endpoint (`/api/install/android-apk`).
   - 3-step First-Run Guided Consumer Onboarding Wizard in Web Dashboard.
   - Strictly opt-in OIDC Account Discovery service (zero cloud calls when disabled, never bypasses pairing or mTLS).
7. **Phase 30: Cross-Network Federation & Session Controls**
   - Mutual explicit owner consent via 9-digit temporary pairing PINs (format `XXX-XXX-XXX`, 10-minute expiry, SHA-256 hashed).
   - Zero privilege inheritance (`FEDERATED_PEER` tier; incoming federated peers never receive `OWNER_MANUAL` authority).
   - Per-network, per-device, and per-capability granular access control lists (ACLs).
   - Scoped expiring credentials (1h, 24h, 7d TTL options).
   - Immediate single-grant revocation and Global Emergency Kill Switch (nuclear revocation).
   - Secret-safe audit logging in `activity_history`.
   - Strict Anti-Transitivity (`TRANSIT_ROUTING_FORBIDDEN`): non-transitive mesh prevents unauthorized multi-hop routing across networks.
   - Coordinator independence: each local network retains local sovereignty.

---

## 2. Four-Layer System Architecture

```
+===================================================================================+
|                             LAYER 1: AI INTEGRATION                               |
|  - MCP stdio Server: Standard JSON-RPC 2.0 over stdin/stdout                      |
|  - Public Remote MCP Gateway: Port 8771, Streamable HTTP, OAuth 2.1 + PKCE S256   |
|  - RFC 8414 OAuth Metadata & RFC 7591 Dynamic Client Registration                 |
|  - SNOW Web Dashboard: Port 8769, Loopback only, Zero CDN dependencies            |
|  - Win32 System Tray Companion: pure ctypes, live telemetry, RSS < 35 MB          |
|  - Unified CLI: `snow daemon`, `snow expose`, `snow tray`, `snow setup`           |
+===================================================================================+
                                         |
+===================================================================================+
|                         LAYER 2: CAPABILITY ENGINE                                |
|  - Dynamic 42-Tool Capability Catalog (`CAPABILITY_REGISTRY`)                     |
|  - CapabilityEngine: Centralized dispatch, execution, and validation              |
|  - ApprovalPolicyEngine: Principle-based access control                           |
|      * AI_MCP (Restricted, requires interactive confirmation for sensitive tools) |
|      * OWNER_MANUAL (Direct human operator in Web UI / CLI, auto-approved)        |
|  - Cross-Network Federation Engine (`FederationManager`):                          |
|      * 9-Digit PIN verification & single-use code lifecycle                       |
|      * Strict capability and device ACL enforcement                               |
|      * Emergency Global Kill Switch & immediate token invalidation                |
|  - Multi-Step Workflow Orchestrator: Composite automation pipelines               |
+===================================================================================+
                                         |
+===================================================================================+
|                         LAYER 3: DEVICE NETWORKING                                |
|  - Dynamic Transport Hierarchy:                                                   |
|      1. Local Wi-Fi / LAN (mDNS + Encrypted WSS Port 8765)                        |
|      2. Zero-Data USB Mesh (ADB Reverse Port Forwarding)                          |
|      3. Remote Relay Tunnel (TLS 1.3 MemoryBIO Port 8770)                         |
|  - Peer-to-Peer Cross-Network Federation Link (Anti-Transitivity Enforced)        |
|  - NodeRegistry & SessionRouter: Routing, presence, and ping keepalive            |
|  - WSS Control Plane: Port 8765, strictly enforced <= 64 KiB frame size           |
|  - HTTPS Transfer Plane: Port 8766, out-of-band chunked file streaming            |
|  - Mutual TLS: Pinning SHA-256 certificate fingerprints                           |
+===================================================================================+
                                         |
+===================================================================================+
|                           LAYER 4: DEVICE RUNTIMES                                |
|  - Windows Desktop Runtime (Python 3.13):                                         |
|      * Telemetry, file management, app launcher, screen stream, clipboard        |
|  - Android Mobile Runtime (Kotlin, Android 14+ / ColorOS 17):                    |
|      * Foreground Service, MediaProjection capture, camera capture, SAF storage   |
+===================================================================================+
```

---

## 3. Database Schema (Version 6)

SNOW utilizes SQLite with Write-Ahead Logging (WAL) and strict file handle management:

- `paired_devices`: Pinned devices, platforms, reachability, connection mode, trust tiers (`owner`, `peer`).
- `network_identity`: Canonical local mesh identity (`network_id`, `network_name`, `owner_id`).
- `network_endpoints`: Ring-buffer history of verified device host/port endpoints.
- `pairing_audit_log`: Historical security log of pairing events and lifecycle changes.
- `activity_history`: Secret-scrubbed capability execution audit log.
- `app_settings`: Onboarding status, UI theme preferences, discovery toggles.
- `federation_invitations`: Temporary mutual pairing invitations (9-digit PIN hash, 10m TTL, ACLs).
- `federation_grants`: Active/revoked cross-network capability authorization grants (token hash, TTL, ACLs).

---

## 4. Hardware Resource Budgets & Compliance

| Component | Target Spec | Actual Verified Performance |
|---|---|---|
| Desktop Core Daemon | < 85.0 MB RSS | ~48.2 MB RSS |
| Win32 System Tray Companion | < 35.0 MB RSS | ~34.3 MB RSS |
| MCP Gateway (Streamable HTTP) | < 65.0 MB RSS | ~38.6 MB RSS |
| Android Client (Idle Background) | < 45.0 MB RSS | ~26.4 MB RSS |
| Control Frame Size | Strict <= 64 KiB | Enforced by WebSocket Protocol Layer |
| Wire Protocol Parity | 100% Bidirectional Parity | 228 / 228 Cross-Language Test Fixtures PASS |
