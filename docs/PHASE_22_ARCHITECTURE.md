# SNOW Phase 22 Architecture & Remote Relay Specification

## 1. Overview & Scope

Phase 22 introduces **Zero-Trust Remote Relay Infrastructure**, **Dual-Tier Android Storage Access**, and **CLI Isolation** to the SNOW platform.

The architectural boundary strictly enforces local-first routing: local network transports (LAN WSS on port 8765, USB ADB reverse mapping on port 8765) are always prioritized. Remote relay is disabled by default and serves solely as an opt-in fallback when physical local reachability is unavailable.

---

## 2. Remote Relay Architecture (Python Server & Protocol)

### 2.1 Standalone Python Relay Server (`src/snow/relay/`)
- **Endpoint**: `wss://<host>:<port>/v1/tunnel`
- **Transport Security**: Opaque ciphertext routing. The relay server routes encrypted frames between enrolled endpoints without possessing decryption keys.
- **Rendezvous & Presence**: In-memory connection map tracking active devices, group identifiers, and presence states (`ONLINE_RELAY`, `DORMANT_RELAY`, `OFFLINE`).

### 2.2 HMAC-SHA256 Relay Tickets (`src/snow/relay/auth.py`)
- Ticket format: `<payload_b64>.<signature_b64>`
- Enforces device ID, group ID, creation timestamp, and strict 300-second expiration window.
- Signature computed via HMAC-SHA256 using the cluster pairing secret.
- Constant-time comparison (`hmac.compare_digest`) prevents timing attacks.

### 2.3 Quotas, Frame Bounds & Rate Limiting (`src/snow/relay/quotas.py`)
- **Maximum Frame Size**: 25 MiB (`26,214,400` bytes). Frames exceeding this bound are immediately rejected.
- **Hourly Rolling Quota**: Default 100 MiB / hour per device to prevent denial-of-service and network exhaustion.
- **Revocation**: Device revocation instantly closes active relay connections and blocks subsequent ticket generation.

### 2.4 End-to-End Encryption Tunnel (`src/snow/network/e2e_tunnel.py`)
- **TLS Version**: Strict TLS 1.3 via OpenSSL `MemoryBIO`.
- **In-Memory Buffering**: Network I/O is completely decoupled from cryptographic processing.
- **Certificate Fingerprint Pinning**: Endpoints verify and enforce peer SHA-256 certificate fingerprints pinned during initial mutual pairing.

### 2.5 Local-First Routing & Relay Policy (`src/snow/network/router.py`)
- Dispatch Priority:
  1. **Tier 1**: Active Inbound WebSocket session (`active_inbound_wss`).
  2. **Tier 2**: USB ADB Reverse Mapping (`localhost:8765`).
  3. **Tier 3**: UDP Wake Burst & Await (`android_wake_and_await`).
  4. **Tier 4**: Remote Relay (`outbound_relay`), strictly if `relay_enabled = True`.
- Relay is **disabled by default** (`SNOW_RELAY_ENABLED=0`).

---

## 3. Dual-Tier Android Storage Access & Security Boundaries

### 3.1 Principal-Based Execution Model
- **`OWNER_MANUAL` (Web Dashboard & Owner CLI)**:
  - Permitted to access full shared internal storage (`Download`, `DCIM`, `Documents`, `Pictures`, `Music`, `Movies`) when Android 11+ `MANAGE_EXTERNAL_STORAGE` permission is granted.
  - Fallback to user-selected SAF folder tree if All Files Access is not granted.
- **`AI_MCP` (AI Assistant Integrations)**:
  - Strictly restricted to the user-selected Storage Access Framework (SAF) folder tree.
  - Cannot request full shared storage; any attempt is coerced to SAF mode.

### 3.2 Path Traversal & Prefix Containment Security
- **Canonical Containment (`isPathContained`)**:
  - Validates that `candidate.canonicalPath == root.canonicalPath || candidate.canonicalPath.startsWith(root.canonicalPath + File.separator)`.
  - Rejects sibling directory prefix escape attacks (e.g. `/storage/emulated/00` vs `/storage/emulated/0`).
- **Protected OS Directories**:
  - `Android/data` and `Android/obb` are permanently blocked by OS policy checks, preserving app sandbox isolation.

---

## 4. CLI Subcommand Dispatch & Process Isolation (`src/snow/__main__.py`)

- Zero arguments: Launches the headless SNOW Desktop Core (`snow.main.main()`).
- Arguments/Flags provided: Dispatches to the CLI entry point (`snow.cli.main(args)`).
- Prevents CLI utilities (e.g., `snow relay status`, `snow doctor`) from accidentally binding port 8765 or colliding with an existing running daemon.

---

## 5. Explicit Carry-Over Disclosure (Phase 22B)

The following two items are explicitly recorded as outstanding carry-over for **Phase 22B**:

1. **Android Full Shared-Storage File Downloads**:
   - While directory listing, path containment, and upload mechanics are structured, end-to-end download of nested full shared-storage files on physical hardware has not yet been verified.
2. **Android Remote Relay Runtime**:
   - The Python relay server, ticket protocol, and Python E2E tunnel are complete.
   - The Android client-side runtime (`E2eRelayTunnel.kt` using `SSLEngine` TLS 1.3 and `RelayClient.kt` WebSocket handler) is not yet implemented.

Both items remain outstanding and will be executed under Phase 22B.
