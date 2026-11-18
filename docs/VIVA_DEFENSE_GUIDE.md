# SNOW — Capstone Viva Voce Defense Guide (V2)
## Comprehensive Q&A for Academic Examiners & Technical Reviewers

**Candidate**: Ayush<br/>
**Degree**: Bachelor of Technology in Computer Science & Engineering (7th Semester Capstone)<br/>
**Project**: **SNOW V2** (Headless Cross-Device AI Capability Platform)<br/>
**Date**: November 2026

---

### Question 1: What core problem does SNOW solve?
- **Concept**: Modern AI models (Claude, Gemini, ChatGPT) are powerful reasoning agents, but they are isolated within host sandbox environments without safe, direct access to physical devices, filesystems, and mobile operating systems.
- **SNOW Implementation**: SNOW acts as an explicitly authorized, bidirectional capability bridge. An AI host talks to SNOW via the standard Model Context Protocol (MCP). SNOW translates AI tool invocations into strictly scoped actions on Windows and Android without requiring cloud relays or exposing arbitrary remote shell access.
- **Design Rationale**: Traditional remote administration tools (SSH, RDP, TeamViewer, ADB-over-Wi-Fi) either introduce catastrophic security vulnerabilities by exposing raw shell access, compromise privacy via third-party cloud servers, or demand continuous human GUI interaction.
- **Source References**: `ARCHITECTURE.md`, `src/snow/capabilities/engine.py`, `src/snow/mcp/tools.py`.

---

### Question 2: Why is SNOW designed as a headless capability platform rather than a remote-control application?
- **Concept**: A remote-control application (e.g., VNC, TeamViewer, AnyDesk) streams display pixels and accepts synthetic mouse/keyboard events. A headless capability platform exposes discrete, semantic APIs (e.g., `query_battery`, `transfer_file`, `launch_app`).
- **SNOW Implementation**: The Windows Desktop Core runs completely headless as a background daemon (`python -m snow`). It creates zero GUI windows and requires zero desktop GUI frameworks. The AI assistant interacts with it programmatically via structured JSON-RPC.
- **Design Rationale**: Screen-scraping and synthetic UI clicks are slow, brittle, resolution-dependent, and prone to vision model hallucinations. Exposing structured, typed capability tools gives the AI deterministic, verifiable execution with clear return values while minimizing system resource consumption (< 10 MB RAM).
- **Source References**: `ARCHITECTURE.md` Section 1, `src/snow/core/server.py`.

---

### Question 3: Why did you adopt the Model Context Protocol (MCP) instead of inventing a proprietary AI protocol?
- **Concept**: Model Context Protocol (MCP) is an open standard introduced by Anthropic and supported across the modern AI ecosystem (Claude Desktop, Google Antigravity, Cursor, Zed) for connecting AI agents to tools and data sources.
- **SNOW Implementation**: The SNOW MCP server exposes 24 standardized tools (`snow_windows_*`, `snow_android_*`, `snow_sync_clipboard`, `snow_transfer_file`) over standard input/output (`stdio`) using JSON-RPC 2.0.
- **Design Rationale**: Standardizing on MCP means any compatible AI assistant can use SNOW without installing custom plugins, proprietary SDKs, or bespoke prompt-injection drivers.
- **Source References**: `src/snow/mcp/server.py`, `src/snow/mcp/tools.py`.

---

### Question 4: Why doesn't the Android device implement MCP directly?
- **Concept**: MCP over `stdio` requires an operating system process with standard input/output streams directly managed by an AI host desktop application.
- **SNOW Implementation**: Android runs a native Kotlin client app communicating over standard network sockets (TLS/WSS). The Windows Desktop Core runs the MCP server subprocess and acts as the capability orchestrator.
- **Design Rationale**: AI hosts run on desktop computers (laptops/workstations), not on mobile devices. An Android device cannot host a stdio pipe directly to an AI host without intermediate desktop orchestration. Furthermore, routing through the desktop core allows centralized security auditing, permission enforcement, and local IPC.
- **Source References**: `ARCHITECTURE.md` Section 2, `src/snow/mcp/bridge.py`.

---

### Question 5: Why separate control traffic (WSS on port 8765) from file-transfer traffic (HTTPS on port 8766)?
- **Concept**: Control traffic consists of lightweight, low-latency, bidirectional JSON messages (heartbeats, commands). Data traffic involves high-throughput, large binary streams (videos, documents, APKs).
- **SNOW Implementation**:
  - Control plane: Port `8765` over TLS 1.2+ WebSockets (`ws_server.py` and `SnowWebSocketClient.kt`).
  - Data plane: Port `8766` over TLS 1.2+ HTTPS streaming (`http_server.py` and `FileTransferClient.kt`).
- **Design Rationale**: Combining binary streaming onto a WebSocket creates head-of-line blocking (where a 500 MB file transfer freezes heartbeat packets, triggering false connection dropouts) and buffer bloat. HTTP provides native chunked streaming, byte-range resumes (`Range: bytes=X-`), and standard HTTP status codes.
- **Source References**: `ARCHITECTURE.md` Section 3, `src/snow/transfer/http_server.py`.

---

### Question 6: Why use local IPC between the MCP process and the Windows Core instead of running everything in one process?
- **Concept**: Process isolation and lifecycle separation.
- **SNOW Implementation**: The AI host spawns an ephemeral Python MCP subprocess whenever an AI session starts. The persistent Desktop Core runs continuously as a background daemon. They communicate over loopback TCP (`127.0.0.1:8767`) using a shared secret file.
- **Design Rationale**:
  1. *Lifecycle mismatch*: The AI host frequently restarts or kills MCP subprocesses. If the core ran in the MCP subprocess, every AI client restart would sever the WebSocket and HTTPS connections to the Android phone.
  2. *Single Owner Invariant*: Only the persistent core manages the database, certificates, pairing PINs, and network ports. Multiple MCP clients can talk to the same running Core without port collisions.
- **Source References**: `src/snow/core/ipc.py`, `src/snow/mcp/bridge.py`.

---

### Question 7: Walk through the device pairing and authentication lifecycle.
- **Concept**: Zero-trust initial pairing transitioning to cryptographically authenticated sessions.
- **SNOW Implementation**:
  1. *Discovery & Connect*: Phone connects to Desktop WSS (`wss://<ip>:8765`). Desktop generates an ephemeral 6-digit PIN valid for 60 seconds.
  2. *Pair Request*: User enters the PIN on the phone. Phone sends `pair_request` over WSS.
  3. *Verification & Token Issuance*: Desktop checks the PIN using constant-time comparison (`hmac.compare_digest`). On success, Desktop generates a 256-bit cryptographic auth token, stores its SHA-256 hash in `snow_devices.db`, and sends the plaintext token to the phone.
  4. *Encrypted Storage*: Phone stores the token in hardware-backed Android Keystore using AES-GCM.
  5. *Reconnection*: On subsequent connections, the phone automatically sends `auth_request` with the stored token. Desktop validates the token hash in SQLite and grants access without prompting for a PIN.
- **Design Rationale**: Minimizes user friction while guaranteeing that unauthenticated connections are rejected after a 5.0-second timeout.
- **Source References**: `src/snow/security/pairing.py`, `src/snow/security/session.py`, `android/.../SnowWebSocketClient.kt`.

---

### Question 8: What is Trust-On-First-Use (TOFU) certificate pinning, and why is it used?
- **Concept**: In local network environments without a public domain name, servers cannot obtain certificates from commercial Certificate Authorities (like Let's Encrypt). They use self-signed certificates.
- **SNOW Implementation**: On startup, the Desktop Core generates a self-signed TLS certificate with a 2048-bit RSA key and computes its colon-separated SHA-256 fingerprint (e.g., `59:EC:2A...`). When Android connects, `SnowTrustManager.kt` checks the certificate:
  - If unpinned: Android shows the fingerprint in a dialog. Upon user approval, it saves the fingerprint into encrypted storage.
  - On subsequent connections: Android verifies that the presented certificate exactly matches the pinned fingerprint. Any mismatch throws `CertificateMismatchException` and aborts the connection.
- **Design Rationale**: Prevents local ARP spoofing and Man-in-the-Middle (MitM) attacks on Wi-Fi networks without relying on external centralized CAs.
- **Source References**: `src/snow/security/tls.py`, `android/.../TlsConfig.kt`.

---

### Question 9: How does the Android Keystore protect cryptographic keys?
- **Concept**: Software-stored keys in ordinary files can be extracted if an attacker gains root or physical access. The Android Keystore system stores cryptographic keys in hardware-isolated security modules (TEE — Trusted Execution Environment or StrongBox Keymaster).
- **SNOW Implementation**: In `EncryptedCertPinStorage.kt`, SNOW generates an AES-256-GCM key inside `AndroidKeyStore`. The key material never leaves the secure hardware. All encryption and decryption operations execute inside the hardware security module; only ciphertext and initialization vectors (IVs) are written to `SharedPreferences`.
- **Design Rationale**: Guarantees that even if device storage is inspected, the plaintext auth token and pinned certificate fingerprints cannot be decrypted without the hardware key.
- **Source References**: `android/app/src/main/java/org/snow/security/EncryptedCertPinStorage.kt`.

---

### Question 10: Why did you choose AES-GCM over AES-CBC?
- **Concept**: Cipher Block Chaining (CBC) provides confidentiality but no built-in integrity check; it requires a separate HMAC (Encrypt-then-MAC) and is vulnerable to padding oracle attacks. Galois/Counter Mode (GCM) is an Authenticated Encryption with Associated Data (AEAD) mode.
- **SNOW Implementation**: SNOW uses AES with 128-bit authentication tags and 12-byte random IVs (`AES/GCM/NoPadding`).
- **Design Rationale**: GCM provides both confidentiality and tamper detection simultaneously in a single cryptographic pass. If an attacker alters a single bit of the stored ciphertext, decryption fails immediately with an `AEADBadTagException`.
- **Source References**: `android/app/src/main/java/org/snow/security/EncryptedCertPinStorage.kt`.

---

### Question 11: Explain the 4-layer architecture of SNOW V2 and why MCP is an adapter rather than the capability owner.
- **Concept**: In V1, capabilities were tightly coupled to the MCP bridge. In V2, SNOW implements a formal 4-layer architecture:
  - **Layer 1: AI Integration**: FastMCP stdio server and AI onboarding CLI.
  - **Layer 2: Capability Engine**: Central owner of capability execution, authorization, and confirmation tickets.
  - **Layer 3: Device Networking**: `NodeRegistry` device reachability synthesis and `SessionRouter` multi-tier routing.
  - **Layer 4: Device Runtime**: Platform-specific execution runtimes on Windows and Android.
- **Design Rationale**: MCP is an *adapter*, not an application core. Native SNOW interfaces (e.g. `snow cli`, local scripts, automated daemons) must execute local capabilities without requiring an AI assistant. Treating the `CapabilityEngine` as the central owner prevents duplication of security logic and enforces unified policy across all callers.
- **Source References**: `ARCHITECTURE.md`, `src/snow/capabilities/engine.py`.

---

### Question 12: How does the Local-First execution model work when the desktop networking daemon is offline?
- **Concept**: Users expect local tools to function even when disconnected from the network or when the background daemon is shut down.
- **SNOW Implementation**: In `src/snow/mcp/bridge.py`, `SnowMcpBridge` attempts loopback IPC if the core daemon is active. If the daemon is offline, it seamlessly falls back to executing directly in-process via `CapabilityEngine`. Local capabilities (telemetry, processes, scoped file operations, workspace terminal execution, clipboard) execute with zero network delay and zero socket dependencies.
- **Design Rationale**: Guarantees that local AI assistant tasks on Windows never stall, time out, or fail because the networking daemon or phone is offline.
- **Source References**: `src/snow/mcp/bridge.py`, `src/snow/capabilities/engine.py`.

---

### Question 13: Detail the Dual-Principal Security Model (`OWNER_MANUAL` vs `AI_MCP`).
- **Concept**: An autonomous AI assistant must not possess the same unrestricted authority as the human owner.
- **SNOW Implementation**:
  - `OWNER_MANUAL`: Direct human operator via CLI or authenticated mobile control session. Authorized to run administrative commands upon explicit confirmation.
  - `AI_MCP`: Autonomous AI assistant via stdio MCP. Restricted strictly to `READ_ONLY` and `WORKSPACE_SCOPED` tiers.
  - **Anti-Spoofing Guarantee**: `CapabilityEngine` unconditionally sanitizes caller payloads, stripping `principal`, `trust_tier`, or `is_owner` fields injected by callers. The execution context is immutably set by the entrypoint.
- **Design Rationale**: Prevents prompt-injection attacks against an LLM from elevating privileges to modify system configuration or delete critical files.
- **Source References**: `src/snow/security/context.py`, `src/snow/capabilities/engine.py`.

---

### Question 14: Explain the Confirmation Ticket lifecycle for terminal execution. How does SNOW prevent replay attacks?
- **Concept**: Two-step interactive confirmation for sensitive operations.
- **SNOW Implementation**:
  1. Human owner initiates a Tier B command (e.g., system process query outside workspace).
  2. `CapabilityEngine` intercepts the command and returns `status: "CONFIRMATION_REQUIRED"`.
  3. The engine generates a 128-bit cryptographic ticket (`secrets.token_hex(16)`) bound to the tuple `(device_id, command, expires_at)` with a 60-second TTL.
  4. When the user confirms the action, the command is executed with `confirmation_ticket: <ticket>`.
  5. **Single-Use Consumption**: During execution, `validate_confirmation_ticket()` verifies the parameters and immediately deletes the ticket from memory. Replaying the ticket returns `CONFIRMATION_REQUIRED`.
- **Design Rationale**: Prevents replay attacks, accidental double-execution, and stale authorization.
- **Source References**: `src/snow/capabilities/engine.py`, `src/snow/capabilities/windows/terminal.py`.

---

### Question 15: How does the symmetric peer-to-peer mesh work? What prevents infinite relay loops?
- **Concept**: Instead of rigid master-slave hierarchy, every node in SNOW V2 can act as a capability consumer or provider.
- **SNOW Implementation**:
  - In `src/snow/network/router.py`, Tier 3.5 enables peer relaying: Node A can route a request to Node C via intermediate Node B.
  - **Loop Prevention**: Every relay payload maintains a `visited_nodes` array. Before forwarding, Node B verifies that target nodes and local node do not appear in `visited_nodes`. If a cycle is detected, routing is immediately aborted.
  - **Authority Stripping**: Forwarded requests are down-scoped to unprivileged peer tier (`AI_MCP`), ensuring a remote peer cannot acquire owner authority simply by proxying through another machine.
- **Design Rationale**: Enables multi-hop capability discovery across mesh networks while maintaining strict security boundaries.
- **Source References**: `src/snow/network/router.py`, `src/snow/network/node.py`.

---

### Question 16: Walk through the SessionRouter pre-flight check and routing tiers. What are the measured latency benchmarks?
- **Concept**: Before attempting slow network connections or wake bursts, requests must be validated in microsecond time.
- **SNOW Implementation**:
  - **Pre-Flight Validation**: `SessionRouter` matches required capability string against `NodeRegistry` capability manifests. If unsupported, it rejects immediately with `CAPABILITY_NOT_SUPPORTED`. Measured benchmark: **2.05 ms median latency (< 5.0 ms target)**.
  - **Tier 1 (Active Session)**: Dispatches immediately over established TLS connection.
  - **Tier 2 (Direct Dial)**: Dials outbound to `PERSISTENT_DAEMON` peers with known IP/port (2.5s timeout).
  - **Tier 3 (Wake-and-Await)**: Sends targeted UDP wake packets to mobile `SLEEPING_CLIENT` and awaits reconnection (6.0s grace period).
  - **Tier 3.5 (Peer Relay)**: Forwards through intermediate mesh peer with loop detection.
  - **Tier 4 (Structured Failure)**: Returns structured `DEVICE_UNREACHABLE` diagnostic payload without hanging.
- **Source References**: `src/snow/network/router.py`, `tests/test_phase_18_v2_acceptance.py`.

---

### Question 17: What are the Reachability Profiles in NodeRegistry, and why are they necessary?
- **Concept**: Different device classes have fundamentally different power, lifecycle, and network characteristics.
- **SNOW Implementation**:
  - `PERSISTENT_DAEMON`: Desktop/server nodes running continuous daemons with open server ports. Reachable via Tier 2 direct dialing.
  - `SLEEPING_CLIENT`: Battery-optimized mobile devices (Android) subject to OS sleep and Doze mode. Cannot host permanent server ports; requires Tier 3 wake hints or inbound sessions.
  - `LAN_DIRECT`: Discovered LAN peers responsive to local UDP beacons.
- **Design Rationale**: Treating a mobile phone like a persistent server causes connection timeouts and battery drain; treating a desktop server like a sleeping client introduces unnecessary wake delays.
- **Source References**: `src/snow/network/node.py`, `src/snow/network/registry.py`.

---

### Question 18: What are the real-world Android platform constraints? Can a remote device arbitrarily wake up a sleeping phone?
- **Concept**: Mobile operating systems enforce aggressive power management to protect battery life.
- **SNOW Implementation & Defense**:
  - **Doze Mode Reality**: When an Android device is unplugged and stationary with the screen off, Android enters Deep Doze. Local Wi-Fi network polling is suspended. A remote PC **cannot arbitrarily wake a sleeping phone** over local Wi-Fi without FCM high-priority cloud push or physical interaction.
  - **Foreground Service**: SNOW runs as a Foreground Service with a persistent notification (`connectedDevice`), preventing OEM memory termination during active use.
  - **Background Activity Launch (BAL)**: Android 10+ forbids background services from directly launching UI activities. `snow_android_launch_app` functions when SNOW is in the foreground, but requires user mediation when backgrounded.
- **Design Rationale**: Academic and engineering honesty. Documenting platform constraints proves deep understanding of modern mobile OS internals.
- **Source References**: `docs/FINAL_ARCHITECTURE_REPORT.md`, `android/.../SnowForegroundService.kt`.

---

### Question 19: How does SNOW achieve less than 10 MB idle RAM across processes, and how is stdio purity guaranteed?
- **Concept**: Resource efficiency on low-specification devices and clean protocol isolation.
- **SNOW Implementation**:
  - **Memory Efficiency**: Built entirely on standard Python `asyncio`, `sqlite3`, and lightweight C-extensions (`cryptography`, `psutil`). Measured idle RSS: **0.04 MB** for CapabilityEngine, **4.06 MB** for standalone Core daemon, **4.06 MB** for standalone MCP server. Total stack: **~8.12 MB** (far below the 30 MB capstone limit).
  - **Stdio Purity**: FastMCP `stdout` is strictly reserved for JSON-RPC 2.0 protocol frames. All application logging, debug statements, and diagnostic outputs route exclusively to `sys.stderr` or log files. Verified by automated subprocess tests.
- **Source References**: `src/snow/main.py`, `src/snow/mcp/server.py`, `tests/test_phase_18_v2_acceptance.py`.

---

### Question 20: How does the multi-host AI onboarding system work safely across Claude, Gemini, Cursor, and ChatGPT?
- **Concept**: Automated configuration without data loss or file corruption.
- **SNOW Implementation**: In `src/snow/onboarding.py`, `HostOnboardingManager`:
  1. Resolves canonical configuration paths (`%APPDATA%\Claude\claude_desktop_config.json`, `~/.gemini/settings.json`, `~/.cursor/mcp.json`).
  2. Creates automatic timestamped `.bak` backups before modifying any existing configuration.
  3. Merges non-destructively: adds or updates the `snow` MCP entry while preserving all other settings and sibling MCP servers.
  4. Uses atomic filesystem replacement (`tempfile` + `os.replace`) to prevent partial writes.
  5. Provides `--dry-run` inspection and `snow doctor` diagnostic health checks.
- **Design Rationale**: Eliminates manual JSON editing errors for users while guaranteeing zero configuration corruption.
- **Source References**: `src/snow/onboarding.py`, `src/snow/cli.py`.
