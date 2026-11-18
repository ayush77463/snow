# SNOW — Project Implementation Roadmap (Frozen)

> This roadmap is frozen as of Phase 0 completion. Phase ordering, dependencies, and scope boundaries must not be silently changed.

This document outlines the step-by-step, milestone-based development plan for **SNOW**, designed specifically for a single B.Tech Computer Science student completing a 7th-semester capstone project.

Each phase is self-contained, testable, and builds incrementally on previous accomplishments. No phase assumes features work without direct testing. Security is established before device capabilities are implemented.

---

## Roadmap Overview

```mermaid
flowchart LR
    P0["Phase 0\nArchitecture & Docs"] --> P1["Phase 1\nConnectivity &\nCommunication"]
    P1 --> P2["Phase 2\nPairing &\nSecurity"]
    P2 --> P3["Phase 3\nFile Transfer"]
    P3 --> P4["Phase 4\nMCP Server &\nAI Integration"]
    P4 --> P5["Phase 5\nWindows\nCapabilities"]
    P5 --> P6["Phase 6\nAndroid\nCapabilities"]
    P6 --> P7["Phase 7\nIntegration &\nFinalization"]
```

---

## Phase 0: Architecture and Documentation

### Concept Explained
Before writing code, establish a clear blueprint and prepare development tools so that no architectural confusion or dependency conflicts arise later. This phase produces the frozen architecture specification, implementation roadmap, and agent working rules.

### Objectives
- Define and freeze the project architecture, component boundaries, and technical constraints.
- Create coding-agent working guidelines to maintain discipline throughout development.
- Document environment prerequisites and verification steps.
- Perform a final cross-document consistency audit.

### Deliverables
- `ARCHITECTURE.md`: Frozen system architecture and protocol design.
- `ROADMAP.md`: This comprehensive milestone plan.
- `AGENTS.md`: Agent operational guidelines and safety rules.

### Dependencies
- None (first phase).

### Acceptance Criteria
- [x] All three core documentation files exist in workspace root and are internally consistent.
- [x] Clear scope boundaries established (headless desktop, no cloud, no unrestricted shell, local connectivity).
- [x] Technology decisions table is frozen.
- [x] Phase ordering is finalized with explicit dependencies.
- [x] Student understands the high-level role of each component.

### Viva Concept Check
- **What is SNOW?** A headless, cross-device AI capability bridge that lets AI assistants perform authorized operations on a Windows laptop and Android phone through a unified MCP interface.
- **Why no mandatory Windows GUI?** SNOW's desktop core is a headless bridge — AI assistants interact via MCP, and the user interacts via the Android app. A GUI would add complexity without core value.
- **Why avoid cloud infrastructure?** Local-first reduces latency, eliminates hosting costs, preserves privacy, and simplifies networking for a semester project.

---

## Phase 1: Direct Connectivity and Communication

### Concept Explained
This phase builds the entire end-to-end communication pipeline: a Python headless desktop core, the WebSocket-based device protocol, a real Android client, and physical device connectivity testing. By the end of Phase 1, the laptop and phone can exchange messages reliably over a phone hotspot or Wi-Fi LAN.

---

### Sub-Milestone 1.1: Python 3.13 Headless Core

#### Concept Explained
The desktop core must handle asynchronous operations — listening for connections, handling commands, and managing timeouts — without freezing. Python's `asyncio` is the standard for this event-driven architecture. Because this core will support the MCP `stdio` transport, `stdout` is strictly reserved for JSON-RPC. All logging goes to `sys.stderr`.

#### Objectives
- Set up a clean, isolated Python 3.13 virtual environment using `py -3.13 -m venv .venv`.
- Implement an asynchronous server scaffold using `asyncio`.
- Build graceful startup, clean signal handling (`SIGINT`/`Ctrl+C`), and configure Python logging strictly to `sys.stderr`.
- Implement network interface detection: enumerate active interfaces, identify usable IPv4 addresses, exclude loopback and link-local.
- Display detected IP(s) and listening port to `sys.stderr` at startup.
- Enforce: zero `print()` or unstructured output to `stdout`.

#### Deliverables
- `pyproject.toml` with minimal dependencies and Python 3.13 requirement.
- `src/snow/core/config.py`: Centralized configuration (bind address, ports, log level).
- `src/snow/core/server.py`: Async server lifecycle manager with graceful shutdown and `sys.stderr` logging.
- `src/snow/core/network.py`: Network interface detection and IPv4 address enumeration.
- `src/snow/main.py`: Entry point for starting the desktop service.
- Verification script to test startup, shutdown, IPv4 detection, and stdout cleanliness.

#### Dependencies
- Completion of Phase 0.
- Python 3.13 installed on Windows (`py -3.13 --version` succeeds).

#### Acceptance Criteria
- [x] Running `py -3.13 -m snow.main` (from within the venv) starts the async core loop, logs structured startup messages strictly to `sys.stderr`, displays detected IPv4 addresses, and responds cleanly to `Ctrl+C`.
- [x] Zero bytes are emitted to `stdout` during startup and operation.
- [x] IPv4 detection correctly identifies the active network interface IP (not `127.0.0.1` or `169.254.x.x`).

#### Viva Concept Check
- **What is an event loop in `asyncio`?** A single-threaded loop that coordinates asynchronous tasks, callbacks, and I/O events cooperatively.
- **Why `asyncio` instead of threading?** Network I/O (WebSockets) is mostly waiting on sockets; coroutines use less memory and eliminate race conditions.
- **Why must logging use `sys.stderr`?** The MCP `stdio` transport uses `stdout` for JSON-RPC protocol frames. Any stray output on `stdout` corrupts the AI host communication.

---

### Sub-Milestone 1.2: WebSocket Server and SNOW Device Protocol v1

#### Concept Explained
The desktop runs a WebSocket server that speaks SNOW Device Protocol v1 — a versioned JSON envelope format for commands, responses, heartbeats, and events. Before building the Android client, we validate the protocol using a lightweight Python mock client.

#### Objectives
- Implement the WebSocket server on `0.0.0.0:8765` using `asyncio` and the `websockets` library.
- Implement SNOW Device Protocol v1 envelope parser and validator using `pydantic`.
- Create a mock Android client in Python that connects, responds to heartbeats, and simulates command responses.
- Implement heartbeat/keepalive (15-second interval, 45-second dead timeout).
- Implement correlation ID matching for request/response pairs with configurable timeout (30 seconds).
- Configure the Windows Firewall rule for the Python 3.13 executable on TCP port 8765.

#### Deliverables
- `src/snow/protocol/`: Protocol constants, models, and strict validator (`constants.py`, `models.py`, `validator.py`).
- `src/snow/network/ws_server.py`: Async WebSocket server with connection handling and bidirectional command routing.
- `src/snow/network/connection_manager.py`: Tracks connected device state (ID, IP, last heartbeat, online/offline status).
- `tests/mock_device.py`: Python CLI mock client supporting ping/pong and generic request/response protocol verification.
- Windows Firewall rule documentation and verification commands.

#### Dependencies
- Completion of Sub-Milestone 1.1.

#### Acceptance Criteria
- [x] Mock client connects over WebSocket to Desktop Core on `ws://<laptop-ip>:8765` (or `ws://127.0.0.1:8765`).
- [x] Bidirectional request/response correlation verified via generic protocol test (`send_request()` matches correlated response `id`; physical Android device capabilities remain unverified until later phases).
- [x] Heartbeats exchange periodically; killing or idling mock client triggers offline reaping after heartbeat timeout.
- [x] Correlation IDs correctly match requests to responses.
- [ ] Windows Firewall rule documented (must be manually created in an elevated PowerShell session when needed; physical firewall rule configuration remains unverified).

#### Viva Concept Check
- **Why WebSockets instead of HTTP polling?** WebSockets provide a persistent, full-duplex TCP channel; the server can push commands to the phone instantly.
- **How do correlation IDs work?** Each request has a unique `id`. The client echoes that `id` in its response, allowing the server to match async responses to waiting requests.
- **Why a firewall rule?** Windows Defender Firewall blocks unsolicited inbound connections by default. A scoped rule allows only SNOW's specific Python process and port.

---

### Sub-Milestone 1.3: Minimal Kotlin Android Connectivity Client

#### Concept Explained
Replace the Python mock client with a real native Android application. The app connects to the desktop's IP address, maintains a WebSocket connection through a Foreground Service, and displays live connection status.

#### Objectives
- Create a clean Android Studio project in Kotlin (Min SDK 26, Target SDK 34/35).
- Build a single-screen UI with:
  - Desktop IP and Port configuration inputs.
  - "Connect" / "Disconnect" button.
  - Live connection status indicator (Connected, Connecting, Disconnected).
  - Simple event/activity log view.
- Implement an OkHttp-based WebSocket client inside an Android Foreground Service with a persistent notification.
- Implement protocol v1 heartbeat handling.
- Implement automatic reconnection logic with exponential backoff.

#### Deliverables
- [x] Android Studio project: `android/` directory with Gradle wrapper (Gradle 8.5, AGP 8.2.2, compileSdk 34, minSdk 26).
- [x] `android/.../network/SnowWebSocketClient.kt`: OkHttp WebSocket wrapper with single lifecycle controller, backoff reconnection, and heartbeats.
- [x] `android/.../service/SnowForegroundService.kt`: Foreground Service (`connectedDevice`) managing connection lifecycle and persistent notification.
- [x] `android/.../protocol/`: Kotlin models, serializer enforcing Clean Serialization Invariant, and strict validator matching SNOW Device Protocol v1.
- [x] `android/.../ui/MainActivity.kt`: User interface with IP/port inputs, connect/disconnect, status indicator, ping test, and activity log.
- [x] `android/README.md`: Android client documentation, architecture, cleartext security model, and build commands.

#### Dependencies
- Completion of Sub-Milestone 1.2.
- Android Studio installed; physical Android phone with Developer Mode and USB debugging enabled.

#### Acceptance Criteria
- [x] Android project compiles cleanly, passes JVM unit tests (`.\gradlew.bat testDebugUnitTest`), and successfully produces debug APK (`.\gradlew.bat assembleDebug`).
- [x] Wire schema parity verified: Kotlin models and serializer enforce the clean serialization invariant (null fields omitted) and validate strictly against SNOW Device Protocol v1.
- [x] Physical Android app connects to the desktop WebSocket server using manually entered IP:port (empirically verified in Sub-Milestone 1.4).
- [x] Desktop logs show the real phone's IP and connection time (empirically verified in Sub-Milestone 1.4).
- [x] Heartbeats exchange correctly between desktop and physical phone (empirically verified in Sub-Milestone 1.4).
- [x] Disconnecting Wi-Fi on the physical phone triggers reconnection attempts with backoff; reconnecting Wi-Fi restores the connection (empirically verified in Sub-Milestone 1.4).

#### Viva Concept Check
- **Why a Foreground Service?** Android aggressively kills background tasks. A Foreground Service with a visible notification elevates process priority, though it does not guarantee permanent connectivity.
- **What is OkHttp?** A robust HTTP & WebSocket client library for Android and Java applications.

---

### Sub-Milestone 1.4: Physical Connectivity and Discovery Testing

#### Concept Explained
Verify that the laptop and phone can actually communicate over real-world network configurations. This is empirical testing — results depend on the specific hardware and Android version.

#### Objectives
- Test connectivity over phone's mobile hotspot (phone creates hotspot; laptop connects; verify WebSocket communication).
- Test connectivity over standard Wi-Fi LAN (both devices on same router).
- Test UDP broadcast discovery feasibility on each network type.
- Document any network-specific issues (AP client isolation, hotspot restrictions).
- Evaluate QR code connection information delivery.

#### Deliverables
- `docs/CONNECTIVITY_TEST_RESULTS.md`: Documented test results for each network configuration on actual hardware.
- Updates to Connection Manager if hotspot-specific behaviour requires adaptation.

#### Dependencies
- Completion of Sub-Milestone 1.3.
- Physical Android phone and Windows laptop available.

#### Acceptance Criteria
- [x] At least one connectivity method (hotspot or Wi-Fi LAN) reliably establishes and maintains a WebSocket connection between the physical devices (both Wi-Fi LAN and Mobile Hotspot verified).
- [x] Test results document which network configurations work, which have limitations, and why (`docs/CONNECTIVITY_TEST_RESULTS.md`).
- [x] Any connectivity workarounds are documented (e.g. Android 14+ FGS permissions, Windows Firewall Public profile constraints).

#### Viva Concept Check
- **Why test on physical hardware?** Network behaviour (hotspot routing, AP isolation, firewall rules) varies by manufacturer and environment. Simulated tests cannot validate real-world connectivity.
- **What is AP client isolation?** A router security feature that prevents connected Wi-Fi clients from communicating with each other directly. It breaks device-to-device protocols.

---

### Sub-Milestone 1.5: Reconnection and Reliability Testing

#### Concept Explained
Stress-test the connection lifecycle under real-world disruption scenarios to ensure the system recovers gracefully.

#### Objectives
- Test connection recovery after: phone screen off → screen on, brief Wi-Fi dropout, airplane mode toggle, phone app force-stop and restart, laptop sleep/wake.
- Measure reconnection time and verify state consistency.
- Document any scenarios where the Foreground Service fails to maintain or recover the connection.

#### Deliverables
- Updated reconnection logic if testing reveals gaps.
- Reliability test results added to `docs/CONNECTIVITY_TEST_RESULTS.md`.

#### Dependencies
- Completion of Sub-Milestone 1.4.

#### Acceptance Criteria
- [x] Connection recovers automatically within 30 seconds after screen-off/screen-on and brief Wi-Fi dropout (verified empirically in Sub-Milestone 1.5: 2.08s for screen-on, 10.0s for Wi-Fi dropout).
- [x] After airplane mode toggle, reconnection occurs within 60 seconds of network restoration (verified empirically in Sub-Milestone 1.5: 35.0s after radio restoration).
- [x] Force-stopping and reopening the Android app re-establishes the connection (verified empirically in Sub-Milestone 1.5).
- [x] All failure modes are documented with observed behaviour (`docs/CONNECTIVITY_TEST_RESULTS.md`).
- [x] Notification shade disconnect lifecycle verified on physical device (Scenario 5B verified on Android 16).

#### Viva Concept Check
- **Does a Foreground Service guarantee the WebSocket stays alive during Doze?** No. Deep Doze restricts network access. The client must implement reconnection logic and test behaviour empirically on the target device.

---

## Phase 2: Pairing and Security

### Concept Explained
Before enabling device capabilities, we must secure the communication channel. Transmitting credentials over plaintext `ws://` is vulnerable to sniffing and MITM attacks. Phase 2 establishes device identity, encrypted transport, and authenticated sessions.

---

### Sub-Milestone 2.1: Device Identity and Pairing

#### Objectives
- Generate a unique device identity (UUID) for each endpoint on first run.
- Implement a 6-digit PIN pairing flow: desktop displays PIN; user enters it on the Android app.
- Enforce PIN expiry (60 seconds) and rate limiting (3 failed attempts → lockout).
- Evaluate QR code as an alternative/supplement to manual PIN entry (manual 6-digit PIN entry remains the supported baseline for Sub-Milestone 2.1).

#### Deliverables
- `src/snow/security/identity.py`: Device identity generation and persistence.
- `src/snow/security/pairing.py`: PIN generation, expiry, and rate limiting.
- `android/.../security/PairingFlow.kt`: PIN entry UI and verification.
- Pairing protocol operations (action: `pair_request`, `pair_verify` inside canonical `request`/`response`/`error` envelopes).

#### Dependencies
- Completion of Phase 1 (all sub-milestones).

#### Acceptance Criteria
- [x] Desktop generates and displays a 6-digit PIN on `sys.stderr` (`src/snow/security/pairing.py`).
- [x] Entering the correct PIN within 60 seconds pairs the devices (empirically verified on physical Realme RMX5110; session established).
- [x] Entering incorrect PIN enforces rate-limiting and attempt countdown (empirically verified with 'WRONG PIN' on physical device; automated suite verified 3-attempt lockout ceiling).
- [x] Expired PINs are rejected with a clear error (`PIN_EXPIRED`).
- [x] Persistent unique device identities (UUIDv4) generated and validated for both desktop and Android (`src/snow/security/identity.py` and `org.snow.security.DeviceIdentity`).
- [x] QR code connection & pairing payload evaluated conceptually for Phase 2 (metadata transfer is out-of-band, observable by cameras; manual 6-digit PIN entry remains the supported baseline).

#### Viva Concept Check
- **Why use a 6-digit PIN?** Out-of-band authentication establishes initial trust between devices. The user physically verifies both endpoints.
- **Why enforce expiry and rate limiting?** Short-lived PINs reduce the window for brute-force attacks. Rate limiting prevents automated guessing.

---

### Sub-Milestone 2.2: SQLite Pairing Records and Session Management

#### Objectives
- Store paired device records (device ID, display name, pairing timestamp, auth token hash) in SQLite using Python standard-library `sqlite3`.
- Store authentication-token hash (SHA-256) as specified by the frozen architecture.
- Do not introduce SQLCipher or third-party SQLite C extensions (standard library `sqlite3` only).
- Implement session management: track active sessions, support device unpairing.
- Log pairing events for audit.

#### Deliverables
- `src/snow/security/db.py`: SQLite schema and data access for pairing records and session state.
- Unpair command support in the device protocol.

#### Dependencies
- Completion of Sub-Milestone 2.1.

#### Acceptance Criteria
- [x] `snow_devices.db` correctly records paired device ID, name, and token hash.
- [x] Unpairing a device removes its record and rejects subsequent connection attempts.
- [x] Database file is added to `.gitignore`.

#### Viva Concept Check
- **Why SQLite?** Lightweight, embedded, zero-configuration database. Perfect for single-user local storage without requiring a database server.

---

### Sub-Milestone 2.3: Android Keystore and AES-GCM Credential Storage

#### Objectives
- Generate an AES encryption key inside the hardware-backed Android Keystore.
- Encrypt pairing tokens using AES-GCM authenticated encryption.
- Store encrypted ciphertext in standard SharedPreferences or Jetpack DataStore.
- Never store plaintext keys in SharedPreferences, DataStore, or source code.

#### Deliverables
- `android/.../security/KeyStoreManager.kt`: Keystore key generation and AES-GCM encrypt/decrypt wrapper.
- `android/.../security/TokenStorage.kt`: Encrypted token persistence in SharedPreferences/DataStore.

#### Dependencies
- Completion of Sub-Milestone 2.2.

#### Acceptance Criteria
- [x] Token encryption uses a Keystore-managed AES key with AES-GCM.
- [x] Ciphertext is stored in SharedPreferences/DataStore; plaintext key is never written to disk.
- [x] Tampering with the stored ciphertext causes decryption to fail with an authentication error.

#### Viva Concept Check
- **How does Android Keystore protect keys?** Keys are generated and stored inside a hardware-isolated security module (TEE/StrongBox). They cannot be extracted, even by a rooted device.
- **Why AES-GCM?** Authenticated encryption: it provides both confidentiality (encryption) and integrity (authentication tag), detecting any tampering.

---

### Sub-Milestone 2.4: Authenticated Communication and TLS/WSS

#### Objectives
- Implement TLS/WSS transport for the WebSocket connection.
- Implement token-based authentication in the connection handshake: the client must present a valid auth token within 5 seconds of connection, or the connection is dropped.
- Evaluate certificate pinning or local self-signed certificates for transport encryption.

#### Deliverables
- TLS configuration for the Python WebSocket server.
- Updated Android client with WSS support.
- `AUTH_REQUEST` and `AUTH_VERIFY` handshake messages in the device protocol.
- Test script verifying unauthenticated connections are rejected.

#### Dependencies
- Completion of Sub-Milestone 2.3.

#### Acceptance Criteria
- [x] Communication occurs over `wss://` (encrypted).
- [x] Unauthenticated connections are rejected within 5 seconds.
- [x] Paired devices authenticate automatically using stored tokens.
- [x] An unpaired device cannot communicate even if it knows the IP:port.

#### Viva Concept Check
- **Why is TLS mandatory before treating pairing as secure?** Without TLS, the PIN, token exchange, and all subsequent commands travel in plaintext and can be intercepted by any observer on the network.

---

## Phase 3: Reliable File Transfer

### Concept Explained
File transfer uses authenticated HTTP streaming — large binary payloads are deliberately kept off the WebSocket control channel. This phase implements bidirectional file transfer with integrity verification.

---

### Sub-Milestone 3.1: Authenticated Bidirectional HTTP Streaming

#### Objectives
- Implement a lightweight HTTP server on the desktop for file uploads and downloads, authenticated using the pairing session token.
- Implement file download (desktop → Android) and file upload (Android → desktop) over HTTP streaming.
- Never transfer large file contents as Base64 through WebSocket messages.

#### Deliverables
- `src/snow/transfer/http_server.py`: Authenticated HTTP file transfer server.
- `android/.../transfer/FileTransferClient.kt`: HTTP streaming download/upload client.
- Device protocol messages for file transfer coordination (metadata exchange via WebSocket; binary transfer via HTTP).

#### Dependencies
- Completion of Phase 2 (authenticated communication established).

#### Acceptance Criteria
- [x] A test file transfers successfully from desktop to phone's `Downloads/SNOW` directory.
- [x] A test file transfers from phone to a configured desktop directory (`~/.snow/transfers/`).
- [x] Unauthenticated HTTP requests are rejected (401 Unauthorized).

#### Viva Concept Check
- **Why HTTP streaming instead of WebSocket Base64?** Base64 encoding increases payload size by ~33% and large frames can block the real-time control channel. HTTP streaming handles large files efficiently with chunked transfer encoding.

---

### Sub-Milestone 3.2: SHA-256 Integrity Verification

#### Objectives
- Compute SHA-256 hash of files before and after transfer.
- Include the hash in the transfer metadata message sent via WebSocket.
- Verify the hash on the receiving end; reject corrupted transfers.

#### Deliverables
- Hash computation and verification integrated into file transfer flow.
- Transfer metadata includes file size and SHA-256 hash.

#### Dependencies
- Completion of Sub-Milestone 3.1.

#### Acceptance Criteria
- [x] Transferred files have matching SHA-256 hashes on source and destination.
- [x] Deliberately corrupting a transferred file (by modifying bytes in transit) triggers a verification failure (422 Unprocessable Entity).

#### Viva Concept Check
- **What is SHA-256?** A cryptographic hash function producing a 256-bit digest. Any change to the input produces a completely different hash, enabling integrity verification.

---

### Sub-Milestone 3.3: Interrupted Transfer Handling and Cleanup

#### Objectives
- Handle transfers interrupted by network disconnection, app kill, or timeout.
- Clean up partial/incomplete files on the receiving end.
- Report transfer failures through the device protocol.

#### Deliverables
- Cleanup logic for incomplete transfers.
- Timeout handling for stalled transfers.
- Error reporting through device protocol and MCP tool results.

#### Dependencies
- Completion of Sub-Milestone 3.2.

#### Acceptance Criteria
- [x] Killing the connection mid-transfer or cancelling does not leave orphaned partial files.
- [x] Transfer timeout or error produces a clear error message.

#### Viva Concept Check
- **Why clean up partial files?** Incomplete files can confuse users and waste storage. A robust transfer system ensures either a complete verified file or a clean failure.

---

### Sub-Milestone 3.4: Resume Support and Duplicate Prevention

#### Objectives
- Implement transfer resume for large files using HTTP Range headers.
- Implement duplicate detection using SHA-256 hash comparison to avoid re-transferring identical files.

#### Deliverables
- HTTP Range header support in file transfer server and client.
- Duplicate detection logic comparing file hashes before transfer.

#### Dependencies
- Completion of Sub-Milestone 3.3.

#### Acceptance Criteria
- [x] Interrupting and resuming a large file transfer completes successfully with correct SHA-256.
- [x] Attempting to transfer an already-present identical file (same hash) skips the transfer and reports "already exists."

#### Viva Concept Check
- **How do HTTP Range headers enable resume?** The client requests bytes starting from where the previous transfer stopped (`Range: bytes=<offset>-`). The server responds with the remaining content.

---

## Phase 4: MCP Server and AI Integration

### Concept Explained
The Model Context Protocol (MCP) allows AI clients to discover and invoke tools. In this phase, we connect the official Python MCP SDK to the desktop core, creating a unified interface for both Windows and Android capabilities.

---

### Sub-Milestone 4.1: Official Python MCP SDK Integration

#### Objectives
- Implement an MCP server using the official Python MCP SDK over `stdio` transport.
- Configure `stdout` to be exclusively reserved for MCP JSON-RPC protocol messages.
- Implement a basic tool (`snow_get_device_status`) to validate the SDK integration.

#### Deliverables
- `src/snow/mcp/server.py`: MCP Server implementation.
- `src/snow/mcp/tools.py`: Tool definitions with docstrings and type annotations.
- Verification using MCP Inspector.

#### Dependencies
- Completion of Phase 3 (secure, authenticated communication pipeline in place).

#### Acceptance Criteria
- [x] MCP server implemented using official Python MCP SDK over stdio transport (`python -m snow.mcp`).
- [x] Zero non-protocol bytes appear on `stdout`; all logging routed to `sys.stderr`.
- [x] Calling `snow_get_device_status` returns current connection status of paired devices.

#### Viva Concept Check
- **What is MCP?** An open standard that lets AI applications discover and invoke external tools, prompts, and data sources through a consistent protocol.
- **Why `stdio` transport?** The AI host launches the MCP server as a child process and communicates via stdin/stdout, which is the standard local transport.

---

### Sub-Milestone 4.2: MCP-to-Device-Protocol Bridge and Local IPC

#### Objectives
- Implement the bridge layer that translates MCP tool calls into SNOW Device Protocol v1 commands and routes them to the appropriate device.
- For Windows-local operations, the bridge calls local capability handlers directly.
- For Android operations, the bridge routes through the Connection Manager and WebSocket.

#### Deliverables
- `src/snow/mcp/bridge.py`: MCP-to-device routing and translation layer.
- Updated Connection Manager to support bridge queries.

#### Dependencies
- Completion of Sub-Milestone 4.1.

#### Acceptance Criteria
- [x] MCP tool calls correctly route to Android device (via WebSocket) or Windows local handlers.
- [x] When the Android device is offline, Android-targeted tools return informative error messages (`DEVICE_OFFLINE`).
- [x] When a Windows tool is called, it executes locally without requiring the Android device.
- [x] Authenticated loopback IPC (`127.0.0.1:8767`) implemented with Windows user ACLs (`icacls`) and shared secret (`~/.snow/ipc.secret`).

#### Viva Concept Check
- **Why separate the bridge from the MCP server?** The bridge handles routing logic (which device? is it online?) while the MCP server handles protocol compliance. Separation keeps each component focused and testable.

---

### Sub-Milestone 4.3: Unified Windows and Android Tool Definitions

#### Objectives
- Define the complete set of MCP tool schemas for both Windows and Android capabilities.
- Include clear tool descriptions, parameter types, and device-target annotations for AI assistants.

#### Deliverables
- Complete tool definitions in `src/snow/mcp/tools.py` covering:
  - Windows: `snow_windows_battery`, `snow_windows_system_info`, `snow_windows_processes`, `snow_windows_launch_app`, `snow_windows_file_read`, `snow_windows_file_write`, `snow_windows_file_list`.
  - Android: `snow_android_battery`, `snow_android_ring`, `snow_android_clipboard_push`, `snow_android_launch_app`, `snow_android_list_apps`, `snow_android_file_send`, `snow_android_file_receive`.
  - General: `snow_get_device_status`, `snow_list_devices`.
- Tool documentation sufficient for an AI assistant to understand usage.

#### Dependencies
- Completion of Sub-Milestone 4.2.

#### Acceptance Criteria
- [x] All 16 static tool schemas are discoverable via MCP `tools/list` even when Core or device is offline.
- [x] Tool descriptions clearly indicate which device/capability they target with parameter constraints.
- [x] Calling each tool returns appropriate results: live status for general tools, structured `NOT_IMPLEMENTED_YET` for Phase 5/6 deferred tools.

#### Viva Concept Check
- **Why prefix tools with `snow_windows_` and `snow_android_`?** Namespace prefixes help the AI assistant understand which device a tool targets, preventing ambiguous invocations.

---

### Sub-Milestone 4.4: MCP Inspector and AI Client Verification

#### Objectives
- Validate all MCP tools using the official MCP Inspector.
- Test compatibility with at least one actual AI host (e.g., Google Antigravity or Claude Desktop).
- Document any client-specific configuration requirements.

#### Deliverables
- MCP Inspector test report and automated JSON-RPC protocol test suite.
- AI host compatibility test report.
- Configuration documentation for tested AI hosts.

#### Dependencies
- Completion of Sub-Milestone 4.3.

#### Acceptance Criteria
- [x] All 16 tools pass automated MCP JSON-RPC protocol validation (initialization, schema discovery, invocation, result format).
- [x] Strict stdout isolation verified with zero stray bytes contaminating the JSON-RPC wire.
- [ ] Manual MCP Inspector interactive session documented (Node.js/npx not present on host; automated MCP client tests pass 100%).
- [x] Any compatibility issues or offline states return structured error responses (`CORE_OFFLINE`, `DEVICE_OFFLINE`).

#### Viva Concept Check
- **Does an MCP server guarantee compatibility with all AI clients?** No. Clients differ in supported transports, sub-process management, and environment handling. Testing verifies specific client compatibility.

---

## Phase 5: Windows Control Capabilities

### Concept Explained
Implement authorized Windows operations that the AI assistant can invoke through MCP tools. All operations are explicitly scoped — no arbitrary shell execution or unrestricted filesystem access.

### Objectives
- System telemetry: battery status, CPU/RAM usage.
- Process monitoring: list running processes with resource usage.
- Scoped file operations: read, write, and list files within configured directories only.
- Approved application launching: launch only applications on an explicit user-configured whitelist.

### Deliverables
- `src/snow/capabilities/windows/telemetry.py`: System battery, CPU, RAM information.
- `src/snow/capabilities/windows/processes.py`: Running process enumeration.
- `src/snow/capabilities/windows/files.py`: Scoped file read/write/list.
- `src/snow/capabilities/windows/apps.py`: Whitelisted application launcher.
- Corresponding MCP tool implementations and tests.

### Dependencies
- Completion of Phase 4 (MCP server and bridge functional).

### Acceptance Criteria
- [x] `snow_windows_battery` returns current battery percentage and charging state (or graceful `NO_BATTERY` for desktop).
- [x] `snow_windows_system_info` returns CPU usage percentage, RAM, disk, OS, and uptime telemetry.
- [x] `snow_windows_processes` returns a bounded, sorted list of running processes without leaking sensitive command-lines or environments.
- [x] `snow_windows_file_list` lists files only within configured allowed directories; requests outside those directories are rejected.
- [x] `snow_windows_launch_app` launches only whitelisted applications (`notepad`, `calc`, `explorer`, `taskmgr`, `mspaint`); non-whitelisted requests are rejected with a clear error (`APP_NOT_ALLOWED`).
- [x] All operations log to `sys.stderr` with zero stdout pollution on MCP stdio.

### Viva Concept Check
- **Why whitelist applications instead of allowing arbitrary launches?** Arbitrary program execution is a critical security risk. An AI assistant (or compromised prompt) could launch malware, delete files, or escalate privileges. Whitelisting restricts launches to user-approved, known-safe applications.
- **Why scope file operations to configured directories?** Unrestricted filesystem access would allow reading sensitive files (passwords, keys) or writing to system directories. Scoping protects the user's system.

---

## Phase 6: Android Control Capabilities

### Concept Explained
Implement authorized Android device capabilities, each verified with tests and then exposed as MCP tools through the desktop bridge. All capabilities respect Android platform restrictions documented in the architecture.

### Sub-Milestones:

#### Milestone 6.1: Battery Information
- Android: Query `BatteryManager` (percentage, plugged status, health).
- MCP Tool: `snow_android_battery`.

#### Milestone 6.2: Ring Phone / Find My Phone
- Android: Play alarm ringtone using `RingtoneManager` or `MediaPlayer` for a specified duration.
- Use `AudioAttributes.USAGE_ALARM` with `STREAM_ALARM` to bypass silent mode where possible.
- MCP Tool: `snow_android_ring(duration_seconds)`.

#### Milestone 6.3: User-Authorized Clipboard Operations
- Android: User-initiated push (phone → desktop) via in-app button or notification action.
- Desktop → phone: write to clipboard via device protocol command.
- Background clipboard reading is not attempted (Android 10+ restriction).
- MCP Tool: `snow_android_clipboard_push(text)`.

#### Milestone 6.4: User-Mediated Application Launching
- Android: App whitelist configured in the Android app settings.
- Compliant with Android 10+ background activity launch restrictions:
  - When in background: post a notification that the user taps to launch the app.
  - Direct launch only attempted when SNOW is already foregrounded.
  - `FLAG_ACTIVITY_NEW_TASK` is an Intent flag, not a background launch bypass.
  - Full-screen intents and `SYSTEM_ALERT_WINDOW` are not used as general solutions.
- MCP Tools: `snow_android_list_apps()`, `snow_android_launch_app(app_name)`.

#### Milestone 6.5: Android File Operations
- Receive files from desktop via authenticated HTTP streaming (Phase 3 infrastructure).
- Send files from phone to desktop via authenticated HTTP upload.
- Files stored in `Downloads/SNOW` using `MediaStore` or SAF (Scoped Storage compliant).
- MCP Tools: `snow_android_file_send(file_path)`, `snow_android_file_receive(file_path)`.

### Deliverables
- Capability handler modules on Android: `BatteryHandler.kt`, `RingerHandler.kt`, `ClipboardHandler.kt`, `AppLauncherHandler.kt`, `FileTransferHandler.kt`.
- Matching MCP tool implementations in `src/snow/mcp/tools.py`.
- Manual and automated verification checklists for each sub-milestone.

### Dependencies
- Completion of Phase 5 (Windows capabilities done; MCP bridge fully functional).

### Acceptance Criteria
- [x] AI agent executing `snow_android_battery` returns the phone's live battery percentage and device status.
- [x] AI agent executing `snow_android_ring` causes the phone to audibly ring for the bounded duration (1–15s).
- [x] Clipboard push from desktop writes text to the phone's clipboard (write-only, bounded to 64 KiB).
- [x] App enumeration and launching via explicit package intent implemented with Android package visibility queries.
- [x] Bidirectional file transfer coordinates desktop core HTTPS streaming (port 8766) and phone scoped storage (`Downloads/SNOW`) with SHA-256 verification.
- [x] All operations log to `sys.stderr` on the desktop with zero stdout pollution on MCP stdio.

### Viva Concept Check
- **Why can't a background service directly launch an app on Android 10+?** The OS restricts background Activity launches to prevent intrusive screen takeovers. `FLAG_ACTIVITY_NEW_TASK` specifies task affinity, not launch permission. SNOW uses a notification-based flow where the user taps to authorize the launch.
- **Why can't SNOW read the clipboard silently in the background?** Android 10+ restricts clipboard read access to apps with active window focus. SNOW requires explicit user action to push clipboard content.

---

## Phase 7: Integration, Testing, Documentation, and Viva Preparation

### Concept Explained
Bring all components together into an end-to-end demonstration, verify resilience under edge cases, prepare viva speaking points, and finalize the project report.

### Objectives
- Run end-to-end user journeys: AI assistant controlling both Windows and Android devices via natural language.
- Test error conditions: phone out of Wi-Fi range, airplane mode toggle, app killed and restarted, laptop sleep/wake.
- Verify security: unpaired device rejection, token expiry, command whitelisting enforcement.
- Produce comprehensive viva preparation documentation.
- Prepare a clean, reproducible setup script for the final demonstration.

### Deliverables
- `scripts/e2e_demo_flow.py`: Safe, reproducible end-to-end capability pipeline demonstration script (supporting both Connect mode and Managed mode).
- `docs/FINAL_ARCHITECTURE_REPORT.md`: Final thesis-grade system architecture, security, and engineering report.
- `docs/VIVA_DEFENSE_GUIDE.md`: Comprehensive 20-question viva voce defense guide with deep technical rationales for B.Tech CSE examiners.
- `docs/CONNECTIVITY_TEST_RESULTS.md`: Verified hardware connectivity, security, and empirical capability test logs.

### Dependencies
- Completion of all prior phases (0 through 6).

### Acceptance Criteria
- [x] Complete end-to-end demonstration succeeds without crashes (`scripts/e2e_demo_flow.py` verified in Connect & Managed modes).
- [x] AI capability tools query Windows system info, check Android battery, ring the phone, transfer a file, and launch a permitted app through standardized MCP/IPC interfaces.
- [x] Security verified: unpaired devices rejected, expired PINs blocked, non-whitelisted commands prevented, path traversal rejected, and TOFU certificate pinning active.
- [x] Comprehensive 20-question viva defense guide completed with deep concept explanations, SNOW implementation details, and design rationales.
- [x] Final architecture report accurately documents the 3-channel topology, protocol v1 contract, security controls, and hardware test results.
- [x] Project complies strictly with all frozen architectural boundaries, security limits, and stdio isolation directives.

### Viva Concept Check
- **Walk through a complete tool invocation**: AI host → MCP tool call → Bridge routing → Device Protocol command → Android handler → Response → MCP result → AI host display.
- **What happens if the phone disconnects mid-command?** The Connection Manager detects the disconnection, the pending request times out, and the MCP bridge returns an error result to the AI host.

---

# SNOW V2 Product Roadmap

> The fundamental product principle of SNOW V2 is:
> **The AI assistant is the interface. SNOW provides capabilities. Devices are the execution environments.**
>
> SNOW V1 established the frozen security, local networking, cross-language protocol parity, and capability transport foundation. SNOW V2 transforms SNOW into an autonomous, multi-device, AI-centric platform that users connect effortlessly to compatible MCP clients (Claude Desktop, Gemini, Cursor, ChatGPT, Antigravity) with zero friction.

```mermaid
flowchart LR
    V1["SNOW V1\nPhases 0-7\n(Frozen Baseline)"] --> P8["Phase 8\nStandalone Execution\n& Product CLI"]
    P8 --> P9["Phase 9\nZero-Touch Discovery\n& Peer Mesh"]
    P9 --> P10["Phase 10\nUnified Operations\n& Bidirectional Mesh"]
    P10 --> P11["Phase 11\nProductization &\nHost Integrations"]
```

---

## Phase 8: Standalone Local Execution, Auto-Daemon Lifecycle, Power-User Windows Capabilities & One-Command Setup

### Concept Explained
In SNOW V1, every MCP tool invocation required the background Desktop Core WebSocket daemon to be actively running, even when performing purely local Windows tasks. If the daemon was offline or the phone was disconnected, local queries could fail.

Phase 8 decouples MCP tool execution into two clear tiers:
1. **Local-Only Windows Tools**: Execute immediately in-process within the FastMCP server process via direct capability handlers, requiring zero daemon overhead and zero network sockets.
2. **Cross-Device Tools**: Automatically check Core daemon health via IPC, seamlessly auto-spawn the detached Core daemon (`CREATE_NO_WINDOW`) if needed, and route requests via authenticated IPC.

In addition, Phase 8 introduces safe, power-user Windows capabilities (sandboxed terminal command execution, Win32 clipboard read/write/sync, recursive filesystem search, and safe application launching) and a unified `snow` product CLI for zero-friction setup and lifecycle management.

### Objectives
- Enable standalone in-process execution for local Windows tools when Core daemon is offline.
- Implement an atomic auto-daemon lifecycle manager (`CoreDaemonManager`) that starts the headless daemon only on cross-device demand.
- Add power-user Windows tools: `snow_windows_terminal_execute`, `snow_windows_clipboard_get`, `snow_windows_clipboard_set`, `snow_windows_clipboard_sync`, and `snow_windows_search_files`.
- Implement `snow` CLI with `setup`, `status`, `daemon start`, and `daemon stop`.
- Maintain strict MCP `stdio` stream isolation and complete zero stdout pollution.

### Deliverables
- `src/snow/mcp/registry.py`: Declarative categorization (`ExecutionTier.LOCAL_WINDOWS` vs `ExecutionTier.CROSS_DEVICE`).
- `src/snow/daemon.py`: `CoreDaemonManager` implementing detached background process spawning with PID tracking, lock coordination, and log redirection.
- `src/snow/capabilities/windows/terminal.py`: `WindowsTerminalExecutor` with output truncation (128 KiB), execution timeouts (30–120s), and catastrophic command blocklist.
- `src/snow/capabilities/windows/clipboard.py`: `WindowsClipboardManager` using standard Win32 `ctypes` (`CF_UNICODETEXT`).
- `src/snow/cli.py`: Production CLI entry points for setup, status, and daemon control.
- `tests/test_phase_8_product_core.py`: 30 unit and integration tests verifying all Phase 8 deliverables.

### Dependencies
- SNOW V1 baseline (`f37626c`).

### Acceptance Criteria
- [x] Local Windows tools execute in-process within MCP without Core daemon running (`snow_windows_system_info`, `snow_windows_list_dir`, `snow_windows_search_files`, `snow_windows_read_file`, `snow_windows_terminal_execute`, `snow_windows_clipboard_get`, `snow_windows_clipboard_set`).
- [x] Cross-device tools trigger automatic on-demand daemon startup (`CoreDaemonManager`) when Core is not running.
- [x] Sandboxed terminal execution supports PowerShell/cmd, enforces timeouts, caps output at 128 KiB, and rejects blocked catastrophic commands.
- [x] Win32 clipboard read and write work cleanly using standard library ctypes without third-party dependencies.
- [x] `snow setup` correctly detects or writes configuration for Claude Desktop and other MCP clients (`--dry-run` supported).
- [x] 204/204 Python tests, 75/75 Android JVM tests, and 144/144 cross-language parity fixtures pass cleanly.

---

## Phase 9: Zero-Touch UDP Discovery, On-Demand Auto-Connect & Multi-Device Peer Mesh

### Concept Explained
In SNOW V1, connecting an Android device required manual IP address entry or hardcoded loopback configurations. Phase 9 introduces zero-touch LAN discovery via UDP beacons on port `8768`, enabling devices on the same local network to discover each other automatically while preserving strict cryptographic trust boundaries.

Discovered beacons serve as connection candidates; full trust still requires TLS/WSS certificate fingerprint pinning and paired session authentication. In addition, Phase 9 adds an on-demand auto-connect grace period, multi-device target resolution (routing commands by device ID, device name, or friendly alias), a Windows-to-Windows peer mesh client (`SnowPeerClient`), and unified file transfer (`snow_transfer_file`).

### Objectives
- Implement UDP discovery announcer and listener on port `8768` for both Windows and Android (`DiscoveryManager.kt`).
- Implement an on-demand connection grace period (up to 6.0s) sending wake bursts when cross-device commands target a known but currently disconnected peer.
- Implement unified target resolution (exact ID, exact name, unambiguous prefix/substring, rejecting ambiguous targets).
- Create a Windows-to-Windows peer client (`SnowPeerClient`) allowing laptop-to-laptop federation.
- Provide unified file transfer tool `snow_transfer_file(source_path, destination_path, direction, target_device)`.
- Update the Android UI with live discovery status and discovered peer candidate cards.

### Deliverables
- `src/snow/network/discovery.py`: Async UDP beacon broadcaster and listener with rate limiting, subnet broadcast calculation, and stale peer eviction.
- `android/app/src/main/java/org/snow/network/DiscoveryManager.kt`: Android UDP discovery service exposing `StateFlow<List<DiscoveredPeer>>`.
- `src/snow/network/peer_client.py`: `SnowPeerClient` implementing Windows-to-Windows WebSocket client with TLS fingerprint pinning.
- `src/snow/mcp/tools.py`: New MCP tools `snow_mesh_connect_peer` and `snow_transfer_file`.
- `tests/test_phase_9_mesh_discovery.py` & `DiscoveryManagerTest.kt`: Unit and integration test suites.

### Dependencies
- Phase 8 standalone execution and auto-daemon lifecycle.

### Acceptance Criteria
- [x] UDP discovery broadcaster sends periodic signed/structured JSON beacons on port `8768`.
- [x] UDP listener discovers active peers on the LAN, parses payloads, and evicts stale beacons after timeout.
- [x] Android `DiscoveryManager.kt` discovers Core daemon on Wi-Fi and updates candidate IP for paired devices.
- [x] Cross-device execution targeting a disconnected paired device triggers a wake burst and awaits reconnection within the configurable grace period.
- [x] Target resolution correctly resolves device by ID, friendly name, or unambiguous substring, returning `AMBIGUOUS_DEVICE` on collision.
- [x] Unified file transfer tool coordinates transfers seamlessly between laptop and remote targets.
- [x] Windows-to-Windows peer client connects, authenticates, and executes remote peer tools.
- [x] Android dashboard displays discovered LAN peers in a clean card view with 1-tap endpoint selection.
- [x] 230/230 Python tests, 83/83 Android JVM tests, and 144/144 cross-language parity fixtures pass cleanly.

---

## Phase 10: Unified Cross-Device Operations and Bidirectional Capability Expansion

### Concept Explained
Phase 10 transitions SNOW into an active bidirectional capability mesh. Paired Android devices are no longer merely command targets; they can act as actuators and query the Windows laptop for status, directory listings, staged HTTPS file downloads, clipboard synchronization, allowlisted application launches, and terminal execution with mandatory on-screen confirmation. Simultaneously, AI assistants can initiate SMS compose workflows via Android system intents (`snow_android_send_message`).

Crucially, Phase 10 enforces strict defense-in-depth boundaries:
1. **Peer Capability Authorization Policy**: An explicit server-side policy (`PeerCapabilityPolicy`) governs peer requests. Sensitive terminal execution (`desktop.exec`) is denied by default for paired peers and requires explicit configuration.
2. **Foreground & User-Intent Clipboard Bounds**: Android clipboard pulling (`phone_to_laptop`) strictly enforces Android OS foreground residency and requires explicit on-device user authorization; background or unconfirmed reads are rejected with `FOREGROUND_REQUIRED` or `USER_CONFIRMATION_REQUIRED`.
3. **AI-Safe Messaging**: MCP messaging requests (`snow_android_send_message`) are restricted strictly to intent-based compose mode (`ACTION_SENDTO`), leaving the final dispatch under the user's deliberate physical control. Direct background SMS dispatch is restricted from AI invocation.
4. **AI-Originated Execution Boundary**: Cross-device command execution from AI/MCP callers is restricted (`APPROVAL_REQUIRED`) as no remote human-approval workflow is currently wired for autonomous AI callers.

### Objectives
- Implement Python backend handlers for phone-to-PC control over authenticated WebSocket sessions (`desktop_status`, `desktop_exec`, `desktop_app_launch`, `desktop_clipboard_get`, `desktop_clipboard_set`, `desktop_file_list`, `desktop_file_stage_download`).
- Implement server-side peer capability authorization policy (`PeerCapabilityPolicy`) with deny-by-default for command execution and session revocation on unpairing.
- Extend HTTPS transfer server on port 8766 to support staged pre-authenticated file downloads for remote clients.
- Implement Android Remote Desktop Control card in `MainActivity.kt` with live telemetry, clipboard synchronization, PC file browsing, allowlisted app launcher, PC lock button, and terminal command execution with mandatory confirmation dialog.
- Implement native Android clipboard pulling with foreground and user-intent enforcement, plus intent-based SMS messaging capability (`MessagingHandler.kt`).
- Register cross-device MCP tool `snow_android_send_message` in the tool registry, bridge, and MCP server.
- Extend cross-language protocol parity fixtures (46–53) in both Python and Kotlin and maintain 100% parity.
- Provide a physical verification checklist for real-device validation on the Realme RMX5110 (Android 17).

### Deliverables
- `src/snow/security/policy.py`: `PeerCapabilityPolicy` enforcing per-device capability sets and deny-by-default for `desktop.exec`.
- `src/snow/network/ws_server.py`: Desktop action dispatcher, session authentication, forged `device_id` rejection, and 7 phone-to-PC action handlers.
- `src/snow/transfer/manager.py` & `src/snow/transfer/http_server.py`: Staged file download support via token authentication on port 8766.
- `src/snow/core/ipc.py`: Restricted AI-originated cross-device execution (`APPROVAL_REQUIRED`).
- `src/snow/mcp/registry.py`, `src/snow/mcp/bridge.py`, `src/snow/mcp/tools.py`: Added `snow_android_send_message` (intent-only) and bidirectional clipboard sync (total: 24 tools).
- `android/app/src/main/java/org/snow/capabilities/ClipboardHandler.kt`: Bidirectional clipboard handler with foreground and user intent checks.
- `android/app/src/main/java/org/snow/capabilities/MessagingHandler.kt`: Native Android messaging capability with intent dispatch and SMS confirmation safeguards.
- `android/app/src/main/java/org/snow/capabilities/AndroidCapabilityDispatcher.kt`: Dispatching `"clipboard_pull"` and `"send_message"`.
- `android/app/src/main/res/layout/activity_main.xml` & `MainActivity.kt`: Glacier Blue Remote Desktop Control card with full bidirectional UI controls and confirmation dialogs.
- `tests/test_phase_10_bidirectional.py`: 30 automated unit and integration tests covering all Phase 10 actions, security policies, and edge cases.
- `android/app/src/test/java/org/snow/capabilities/CapabilityDispatcherTest.kt` & `MessagingHandlerTest.kt`: Native Android JVM test suites for clipboard and messaging capabilities.
- `tests/test_cross_language_parity.py` & `CrossLanguageParityTest.kt`: Added fixtures 46–53 covering Phase 10 payloads.

### Dependencies
- Phase 9 Zero-Touch Discovery and Multi-Device Peer Mesh.

### Acceptance Criteria & Verification Status
- [x] **Automated**: Authenticated Android client can query PC system status, CPU, RAM, battery, and disk telemetry.
- [x] **Automated**: Bidirectional clipboard synchronization: phone can read PC clipboard and push clipboard text (enforcing 64 KiB cap).
- [x] **Automated**: Android clipboard pull enforces Android OS foreground residency (`FOREGROUND_REQUIRED`) and explicit user confirmation (`USER_CONFIRMATION_REQUIRED`).
- [x] **Automated**: Remote PC file browsing scoped strictly to configured allowed directories; path traversal and `.snow` access rejected.
- [x] **Automated**: Remote PC file downloads stage transfer tokens on port 8766 and download files directly to Android `Downloads/SNOW`.
- [x] **Automated**: Peer capability authorization policy (`PeerCapabilityPolicy`) denies `desktop.exec` by default; rejections log caller identity without secrets.
- [x] **Automated**: Mobile terminal execution executes via `WindowsTerminalExecutor` with output truncation and catastrophic command blocking; mobile UI enforces mandatory user confirmation dialog before sending execution requests.
- [x] **Automated**: AI-originated remote terminal execution via MCP/IPC is restricted (`APPROVAL_REQUIRED`) until an approval workflow is established.
- [x] **Automated**: Remote app launcher supports all ten Phase 8 allowlisted applications (`code`, `chrome`, `msedge`, `powershell`, `wt`, `notepad`, `calc`, `explorer`, `taskmgr`, `mspaint`); workstation lock triggers Win32 `LockWorkStation` using the exact `lock_screen` identifier (ambiguous `lock` rejected).
- [x] **Automated**: Android messaging handler dispatches SMS compose intents (`ACTION_SENDTO`); MCP requests are restricted to intent mode; background SMS without deliberate confirmation is blocked.
- [x] **Automated**: MCP tool `snow_android_send_message` routes through bridge to online Android device.
- [x] **Automated**: Cross-language protocol parity suite passes 100% across Python (176 fixtures) and Kotlin (176 fixtures).
- [x] **Automated**: All 260 Python tests and 92 Android JVM tests pass cleanly; debug APK builds successfully (`assembleDebug`).
- [x] **Automated**: MCP `stdio` stream isolation preserved with zero stdout pollution.
- [x] **Physical**: Real-device physical verification of bidirectional capabilities and controls on Realme RMX5110 (Android 17) executed and confirmed passed by project owner (P10-PHY-01 through P10-PHY-16).

---

## Phase 11: V2 Four-Layer Architecture Specification & Codebase Gap Audit

### Concept Explained
Phase 11 formalizes the SNOW V2 architectural evolution from an asymmetric Windows-server / Android-peripheral bridge into an AI-native, symmetric, multi-node capability mesh. It establishes the comprehensive 4-layer specification (`docs/ARCHITECTURE_V2.md`), defines the platform-independent `DeviceNode` contract, maps the Android 17 security and permission boundaries, details the four structured terminal execution security tiers, and audits the Phase 0–10 codebase to eliminate architectural duplication while strictly preserving local-first in-process execution.

### Objectives
- Define the Four Logical Layers: Layer 1 (AI Integration: MCP/CLI), Layer 2 (Capability Engine), Layer 3 (Device Networking), Layer 4 (Device Runtime).
- Establish the platform-independent `DeviceNode` JSON contract and capability manifest schema.
- Define the Android 17 permission and execution matrix (`BACKGROUND_SAFE`, `RUNTIME_PERMISSION_REQUIRED`, `FOREGROUND_USER_INTERACTION_REQUIRED`).
- Define the four structured terminal security tiers (`READ_ONLY`, `WORKSPACE_SCOPED`, `OWNER_CONFIRMED`, `RESTRICTED_BLOCKED`).
- Conduct a complete codebase gap audit identifying execution duplication (GAP-1, GAP-2, GAP-3) while explicitly preserving local-first in-process capability execution for AI assistants when the daemon is offline.
- Update the forward roadmap for Phases 11–18 with frozen approved milestones.

### Deliverables
- `docs/ARCHITECTURE_V2.md`: Comprehensive V2 architecture specification.
- Updated `ROADMAP.md`: Preserved Phase 0–10 historical records and approved Phase 11–18 roadmap.

### Dependencies
- Phase 10 bidirectional control release (`e13bf4a`).

### Acceptance Criteria
- [x] Four-layer architecture specification fully defined with clean Layer 1–4 separation.
- [x] Local-first in-process execution invariant explicitly preserved; daemon-only requirement rejected.
- [x] Structured terminal security tiers specified with exact approved tier names.
- [x] Platform-independent `DeviceNode` schema and Android 17 permission matrix documented.
- [x] Phase 0–10 codebase gaps analyzed with explicit remediation plans.

---

## Phase 12: Layer 2 Unified `CapabilityEngine` & Structured Terminal Security Tiers

### Concept Explained
Phase 12 implements the central Layer 2 `CapabilityEngine` (`src/snow/capabilities/engine.py`), unifying capability execution, shared capability instance ownership, principal-aware authorization, and structured results across all callers (local in-process MCP, loopback IPC, WSS peer dispatch, and CLI). It replaces ad-hoc command filtering with four structured terminal execution security tiers (`READ_ONLY`, `WORKSPACE_SCOPED`, `OWNER_CONFIRMED`, `RESTRICTED_BLOCKED`), enforcing canonical path validation and server-side confirmation validation.

### Objectives
- Create `src/snow/capabilities/engine.py` exposing unified `execute(request: CapabilityRequest, ctx: ExecutionContext) -> CapabilityResponse`.
- Centralize ownership of Windows capability instances (`WindowsTelemetry`, `WindowsFileManager`, `WindowsAppLauncher`, `WindowsTerminalExecutor`, `WindowsClipboardManager`, `WindowsProcessMonitor`).
- Refactor `ws_server.py`, `ipc.py`, and `bridge.py` to delegate capability execution exclusively to the shared `CapabilityEngine`.
- Preserve local-first in-process execution: local Windows MCP tools execute successfully via in-process `CapabilityEngine` when the networking daemon is stopped.
- Implement four structured terminal execution security tiers in `terminal.py`.
- Enforce strict principal isolation: IPC and in-process MCP are stamped `AI_MCP`; WSS derives context from authenticated sessions; client-supplied confirmation or principal fields are never trusted.

### Deliverables
- `src/snow/capabilities/engine.py`: Unified CapabilityEngine, CapabilityRequest, CapabilityResponse.
- Refactored `src/snow/capabilities/windows/terminal.py`: Structured 4-tier terminal execution.
- Refactored `src/snow/network/ws_server.py`, `src/snow/core/ipc.py`, `src/snow/mcp/bridge.py`.
- `tests/test_phase_12_capability_engine.py`: Comprehensive test suite verifying unified dispatch, local-first execution, terminal tiers, and principal isolation.

### Dependencies
- Phase 11 architecture specification.

### Acceptance Criteria
- [x] All capability invocations (WSS, IPC, MCP Bridge, CLI) route through the shared `CapabilityEngine`.
- [x] Local Windows MCP tools succeed when the Core networking daemon is stopped (zero daemon dependency for local ops).
- [x] Terminal execution enforces the four structured security tiers (`READ_ONLY`, `WORKSPACE_SCOPED`, `OWNER_CONFIRMED`, `RESTRICTED_BLOCKED`).
- [x] Principal isolation verified: AI callers cannot acquire owner privilege; client-supplied confirmation booleans are ignored.
- [x] All existing Python tests, Android JVM tests, and cross-language parity tests pass with zero regression.

---

## Phase 13: Layer 3 Unified `NodeRegistry` & Platform-Independent `DeviceNode` Capability Manifest Protocol

### Concept Explained
Phase 13 establishes the unified Layer 3 `NodeRegistry`, consolidating active WSS sessions and UDP mesh discovery peers into a single thread-safe state store backed by SQLite reachability tracking. It implements the platform-independent `DeviceNode` model and introduces the capability manifest exchange protocol during peer handshake.

### Objectives
- Implement `NodeRegistry` consolidating `_authenticated_clients` and `_discovered_peers`.
- Implement `DeviceNode` dataclass with serialized JSON capability manifests.
- Implement bidirectional capability manifest exchange during WSS handshake.
- Support multi-device tracking with unified reachability state queries.

### Dependencies
- Phase 12 unified `CapabilityEngine`.

### Acceptance Criteria
- [x] Unified `NodeRegistry` tracks all local, connected, and discovered nodes.
- [x] Capability manifests dynamically advertised and queried across paired devices.
- [x] Device queries resolve cleanly across heterogeneous nodes without state fragmentation.
- [x] Platform-independent `DeviceNode` and `CapabilityManifest` protocol with Kotlin Android counterpart.
- [x] SQLite schema v3 migration preserving existing pairing data and caching endpoints/manifests.
- [x] Bidirectional manifest-bearing protocol parity tests (184/184 fixtures verified).

---

## Phase 14: Multi-Transport Reachability State Machine & Automatic On-Demand Session Routing

### Concept Explained
Phase 14 delivers full dynamic network resilience and unified capability routing. It establishes the Layer 3 `SessionRouter` coordinating multi-transport escalation across active sessions, direct dials, and on-demand recovery, while enabling Android dynamic endpoint self-healing without endpoint hardcoding.

### Objectives
- Implement Layer 3 `SessionRouter` with automated 4-tier reachability escalation and timeouts.
- Capability-aware target pre-flight resolution (instant fast-fail without network delays).
- Active inbound WSS and outbound peer client session routing (Tier 1).
- Bounded outbound direct dialing for persistent daemon peers with TLS & identity verification (Tier 2).
- Android active-session peer wake burst and bounded grace period recovery (Tier 3).
- Structured failure diagnostics (`DEVICE_UNREACHABLE`) with transport attempt records (Tier 4).
- Android automatic endpoint self-healing (`updateTargetEndpoint`) with connection-storm prevention.

### Dependencies
- Phase 13 `NodeRegistry` and `DeviceNode` capability manifest protocol.

### Acceptance Criteria
- [x] Multi-transport `SessionRouter` coordinating `NodeRegistry`, `SnowWebSocketServer`, and `SnowPeerClient` (`src/snow/network/router.py`).
- [x] Capability-aware target pre-flight resolution (`resolve_target` fast-fails on `NO_DEVICES_PAIRED`, `DEVICE_REQUIRED`, `DEVICE_NOT_FOUND`, `AMBIGUOUS_DEVICE`, `CAPABILITY_NOT_SUPPORTED`).
- [x] Tier 1 active inbound WSS and outbound peer client dispatch implemented and verified.
- [x] Tier 2 bounded outbound direct dialing for `PERSISTENT_DAEMON` peers with identity verification and endpoint caching.
- [x] Tier 3 Android active-session peer wake-and-await recovery with targeted/broadcast bursts and grace period.
- [x] Tier 4 structured `DEVICE_UNREACHABLE` diagnostics reporting attempted transports, target ID, and last known endpoint.
- [x] Android dynamic endpoint self-healing in `SnowWebSocketClient` and `SnowForegroundService` after valid discovery.
- [x] Connection-storm prevention: no redundant reconnect loops when already connected/connecting.
- [x] Automated regression suites: 15 Python unit tests (`tests/test_phase_14_session_router.py`) and 8 Android JVM unit tests (`EndpointSelfHealingTest.kt`) passing.

---

## Phase 15: Android 17 OS Execution Contract, Permission Matrix & Cross-Device Sync Hardening

### Concept Explained
Phase 15 hardens the Android application against modern Android OS restrictions (API 34 through 36+). It formalizes the execution matrix across `BACKGROUND_SAFE`, `RUNTIME_PERMISSION_REQUIRED`, and `FOREGROUND_USER_INTERACTION_REQUIRED`, adds resilient Foreground Service lifecycle handling, and hardens cross-device clipboard and file synchronization against process death and OS throttling.

### Objectives
- Implement runtime permission elevation flows for Android 15–17.
- Enforce strict user-intent gates for foreground clipboard reading and SMS dispatch.
- Optimize foreground service battery utilization and Doze-mode recovery.
- Hardened file transfer client with resume support and integrity checks.

### Dependencies
- Phase 14 dynamic reachability state machine.

### Acceptance Criteria
- [x] Android 17 background execution contract validation in `AndroidCapabilityDispatcher.kt` enforcing foreground requirements and user confirmation.
- [x] Background Activity Launch (BAL) notification fallback via `ActionNotificationHelper.kt` dispatching actionable notifications with immutable `PendingIntent`s (`NOTIFICATION_TAP_REQUIRED`).
- [x] Intent-only messaging hardening in `MessagingHandler.kt` with explicit user confirmation and zero `SEND_SMS` permission requirements.
- [x] Dynamic manifest synchronization over WebSocket (`manifest_update`) updating registry state upon Android foreground/background transitions.
- [x] Idempotent cross-device clipboard sync with scoped SHA-256 duplicate suppression (`ALREADY_IN_SYNC`, `skipped_duplicate = True`).
- [x] Idempotent cross-device file transfer deduplication via `SessionRouter` and `FileTransferManager` (`ALREADY_EXISTS`, `skipped_duplicate = True`) with structured transfer telemetry.
- [x] Bidirectional manifest update protocol fixtures verified in cross-language parity suite.
- [x] Automated regression suites: 13 Python unit tests (`tests/test_phase_15_android_contract_and_sync.py`) and 6 Android JVM unit tests (`AndroidContractAndSyncTest.kt`) passing (total 112 Android JVM tests).

---

## Phase 16: Symmetric Peer-to-Peer Mesh

### Concept Explained
Phase 16 transforms SNOW from a PC-centric hub into a symmetric peer-to-peer mesh. Android devices can operate in explicit foreground Host Mode to serve capabilities to paired peers when the PC is offline, and Windows workstations can federate symmetrically (Windows ↔ Windows, Android ↔ Android).

### Objectives
- Implement lightweight Android WSS host mode in `SnowForegroundService`.
- Enable peer-to-peer capability invocation across any paired node pair.
- Implement symmetric pairing and mutual capability negotiation.

### Deliverables
- `AndroidPeerHostServer.kt` & `AndroidPeerHostManager.kt`: Foreground peer host server on port 8767 accepting authenticated TCP connections with strict token validation and capability dispatch.
- `SessionRouter` Tier 2 & Tier 3.5: Support for `ReachabilityProfile.FOREGROUND_HOST` and authenticated peer relay routing (`mesh.peer_relay`) with loop prevention and hop limit enforcement.
- Multi-Device MCP Operations: Extended `snow_sync_clipboard` (supporting source/target device selection and per-pair SHA-256 deduplication) and `snow_transfer_file` (supporting explicit source and target nodes).
- `mesh_list_peers`: Authenticated peer capability discovery with strict credential and token redaction.
- Cross-Language Parity: Added 4 bidirectional wire fixtures for mesh listing and relay, verified across 196 fixtures (100% PASS).
- Unit Test Suites: 14 Python unit tests (`test_phase_16_symmetric_mesh.py`) and 8 Android JVM unit tests (`AndroidPeerHostTest.kt`).

### Dependencies
- Phase 15 Android hardening and Phase 13 capability manifests.

### Acceptance Criteria
- [x] Android device can accept incoming connections from paired peers in foreground Host Mode (verified via `AndroidPeerHostServer` and `AndroidPeerHostTest` lifecycle, auth, and capability dispatch tests).
- [x] Windows-to-Windows and Android-to-Android capability exchange verified (verified via `SessionRouter`, Windows capability manifests, bidirectional aliases, and foreground host direct dial).
- [x] Consistent security policy and principal isolation enforced across all mesh topologies (verified anti-spoofing stripping caller authority overrides, enforcing 64KB boundary limits, loop detection, and denying unpermitted execution).

#### Viva Concept Check
- **What is the difference between a hub-and-spoke and symmetric mesh topology?** In hub-and-spoke, all traffic flows through a central coordinator (PC); if the PC is offline, peripheral devices cannot communicate. In a symmetric mesh, nodes can act as both clients and servers (e.g., Android Foreground Host Mode), invoking capabilities directly or relaying requests across paired nodes.
- **Why must peer relay enforce hop limits and loop detection?** Without loop detection (tracking `visited_nodes`) and a decrementing hop counter (TTL), routing cycles could cause infinite message amplification and resource exhaustion across mesh peers.
- **Why is principal isolation critical in relayed mesh operations?** When Peer A relays a request through Coordinator B to Node C, Peer A must never inherit Coordinator B's local owner authority; the execution principal must remain strictly bounded (`AI_MCP` / `PEER`) and any caller-supplied privilege escalation headers must be stripped.

---

## Phase 17: One-Command Onboarding & Multi-Host AI Integrations

### Concept Explained
Phase 17 streamlines productization for non-developer end-users. It delivers a one-command installer, automated TLS certificate generation, one-click MCP configuration for major AI desktop clients (Claude Desktop, Cursor, ChatGPT, Antigravity), and an enhanced `snow devices` management CLI.

### Objectives
- Implement `snow setup --host <claude|cursor|chatgpt|antigravity>` automated configurer.
- Provide single-command bootstrap for local TLS and database initialization.
- Enhance CLI for device management, pairing PIN display, and capability inspection.
- Target clean zero-dependency deployment.

### Deliverables
- `src/snow/onboarding.py`: Maintainable multi-host onboarding adapter framework supporting Claude Desktop, Gemini CLI / Antigravity, Cursor, and ChatGPT generic artifact with non-destructive merge, `.bak` backup, atomic write, and safe idempotent `--remove`.
- `src/snow/cli.py`: Enhanced CLI implementing `snow setup` (`--host`, `--dry-run`, `--remove`), `snow devices` (`list`, `trust`, `revoke`, `connect`, `--json`), `snow doctor` (`--json` system health diagnostics), and `snow daemon` lifecycle commands.
- `src/snow/core/ipc.py`: Added IPC operations `device_trust` and `device_revoke` ensuring live daemon immediately enforces trust changes and terminates active revoked sessions.
- `tests/test_phase_17_onboarding_cli.py`: 26 comprehensive unit tests verifying multi-host configuration, single-owner invariant, offline/online device listing, confirmation prompts, and all 9 doctor diagnostic checks.

### Dependencies
- Phases 11–16.

### Acceptance Criteria
- [x] One-click MCP setup configures target AI assistant without manual JSON editing (verified via `snow setup` across Claude Desktop, Gemini CLI, Cursor, and ChatGPT with atomic write and `.bak` backups).
- [x] Zero cloud dependencies, zero external telemetry verified (all operations run on local stdio MCP and local SQLite database without outbound network tracking).
- [x] Clean onboarding flow completes in under 60 seconds (verified sub-second `snow setup` and `snow doctor` diagnostic suite).

#### Viva Concept Check
- **Why is non-destructive merging critical for AI host configurations?** AI desktop clients (like Claude Desktop or Cursor) often have multiple user-configured MCP servers (e.g., filesystem, github, postgres). Overwriting the entire configuration file would destroy the user's existing tools. SNOW safely parses the existing JSON, adds or updates `mcpServers.snow`, and creates a `.bak` backup.
- **Why does `snow doctor` verify the exact 24-tool MCP count?** The frozen architectural specification defines exactly 24 tools across system telemetry, process monitoring, file operations, clipboard sync, messaging, and mesh operations. Accidental addition or deletion of tools breaks client compatibility contracts and regression assertions.
- **How does `snow devices trust` preserve the single-owner invariant?** The database and IPC handlers transactionally demote any previous owner to `peer` when a new device is promoted to `owner`. Furthermore, the CLI requires explicit confirmation before performing any privilege promotion or device revocation.

---

## Phase 18: End-to-End Product Acceptance, Low-Spec Resource Verification & `snow-v2` Release

### Concept Explained
Phase 18 is the capstone release milestone. It validates all functional, performance, and security acceptance criteria across physical devices, verifies the low-spec resource target (< 30 MB idle RAM on Windows, minimal battery drain on Android), updates the viva defense guide, and prepares the repository for final `snow-v2` release tagging.

### Objectives
- Execute full physical test suite across Windows PC and Android smartphone.
- Validate resource consumption: verify Windows headless daemon operates under 30 MB idle RAM.
- Update `docs/VIVA_DEFENSE_GUIDE.md` with complete Phase 11–18 theoretical and practical Q&A.
- Create release artifacts, comprehensive capstone report, and prepare tag `snow-v2`.

### Dependencies
- All prior phases (11–17) complete and verified.

### Acceptance Criteria
- [x] Idle memory consumption of Windows headless core strictly under 30 MB RAM (measured ~8.12 MB total stack; ~4.06 MB standalone).
- [x] 100% pass rate on end-to-end acceptance suite (`tests/test_phase_18_v2_acceptance.py`: 19/19 tests passing).
- [x] Viva defense guide fully covers V2 architecture, security tiers, and mesh networking (`docs/VIVA_DEFENSE_GUIDE.md` 20 comprehensive Q&As).
- [x] Final architecture report synchronized for V2 (`docs/FINAL_ARCHITECTURE_REPORT.md`).
- [x] V2 End-to-End pipeline demonstrator upgraded (`scripts/e2e_demo_flow.py` supporting Connect & `--managed` modes).
- [x] Final `snow-v2` release readiness verified; all Phase 18 files preserved unstaged and uncommitted for review.

### Deliverables Summary
1. **Automated V2 Acceptance Suite (`tests/test_phase_18_v2_acceptance.py`)**:
   - 19 automated tests covering database isolation, standalone offline execution, dual-principal security, terminal policy tiers, symmetric mesh, preflight routing (<5ms benchmark), idempotent sync, memory footprint, and stdio purity.
2. **Database Isolation & Clean User State**:
   - Isolated tests via `DatabaseManager(custom_path)` and `SNOW_DATA_DIR`.
   - Cleaned synthetic test artifacts from user database `~/.snow/snow_devices.db` (reduced from 35 to 4 real physical Realme RMX5110 records; `PRAGMA integrity_check` verified `ok`).
3. **E2E Demonstration Flow (`scripts/e2e_demo_flow.py`)**:
   - Supports Connect Mode and `--managed` mode with isolated temporary state.
   - Showcases 24 MCP tools, CapabilityEngine, NodeRegistry, SessionRouter, and health diagnostics.
4. **Documentation Baseline**:
   - `docs/FINAL_ARCHITECTURE_REPORT.md`: Comprehensive 4-layer architecture, 24 tools catalog, threat modeling, and honest mobile constraints.
   - `docs/VIVA_DEFENSE_GUIDE.md`: 20 thesis-grade Viva questions and defensible answers.

### Viva Concept Check
- **Examiner**: *How does SNOW V2 enforce security boundaries when an AI assistant executes commands?*
  **Student**: SNOW implements a Dual-Principal Security Model. Autonomous AI assistants operate under the `AI_MCP` principal, which is restricted strictly to read-only and workspace-scoped operations. Destructive or system-wide operations require the `OWNER_MANUAL` principal and a server-validated, single-use confirmation ticket with a 60-second TTL. Caller payloads are sanitized to prevent privilege spoofing.
- **Examiner**: *How does SNOW perform on resource-constrained hardware?*
  **Student**: SNOW Desktop Core runs completely headless using Python `asyncio` without heavy GUI dependencies. In acceptance testing, the entire stack consumed approximately 8.12 MB idle RAM, well below our 30 MB capstone acceptance limit. SessionRouter pre-flight checks complete in approximately 2.05 ms, failing fast without generating unnecessary network traffic.
