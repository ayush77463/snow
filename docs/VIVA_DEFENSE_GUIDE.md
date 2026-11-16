# SNOW — Capstone Viva Voce Defense Guide
## Comprehensive Q&A for Academic Examiners & Technical Reviewers

**Candidate**: Ayush<br/>
**Degree**: Bachelor of Technology in Computer Science & Engineering (7th Semester Capstone)<br/>
**Project**: **SNOW** (Headless Cross-Device AI Capability Bridge)<br/>
**Date**: November 2026

---

### Question 1: What core problem does SNOW solve?
- **Concept**: AI models are powerful conversational reasoning engines, but they are isolated within host environments without safe, direct access to physical hardware, filesystems, and mobile operating systems.
- **SNOW Implementation**:SNOW acts as a secure, cross-device bridge. An AI host (e.g. Google Antigravity or Claude Desktop) talks to SNOW via the standard Model Context Protocol (MCP). SNOW translates AI tool invocations into strictly scoped actions on Windows and Android.
- **Design Rationale**: Without SNOW, users must rely on cloud relays, insecure ADB tunnels, or dangerous arbitrary shell access. SNOW provides a zero-cloud, strictly allowlisted, local capability bridge.
- **Source References**: `ARCHITECTURE.md`, `src/snow/mcp/tools.py`.

---

### Question 2: Why is SNOW designed as a headless capability bridge rather than a remote-control application?
- **Concept**: A remote-control application (like VNC, TeamViewer, or AnyDesk) streams screens and accepts synthetic mouse/keyboard events. A headless capability bridge exposes discrete, semantic APIs (e.g., `query_battery`, `transfer_file`, `launch_app`).
- **SNOW Implementation**:The Windows Desktop Core runs completely headless as a background daemon (`python -m snow`). It exposes zero mandatory GUI windows. The AI assistant interacts with it programmatically via structured JSON-RPC.
- **Design Rationale**: Screen-scraping and synthetic UI clicks are slow, brittle, resolution-dependent, and prone to hallucinations. Exposing structured, typed capability tools gives the AI deterministic, verifiable execution with clear return values.
- **Source References**: `ARCHITECTURE.md` Section 1, `src/snow/core/server.py`.

---

### Question 3: Why did you adopt the Model Context Protocol (MCP) instead of inventing a proprietary AI protocol?
- **Concept**: Model Context Protocol (MCP) is an open standard introduced by Anthropic and supported across the modern AI ecosystem (Claude Desktop, Google Antigravity, Cursor, Zed) for connecting AI agents to tools and data sources.
- **SNOW Implementation**:The SNOW MCP server exposes 16 standardized tools (`snow_windows_*`, `snow_android_*`, `snow_get_device_status`) over standard input/output (`stdio`) using JSON-RPC 2.0.
- **Design Rationale**: Standardizing on MCP means any compatible AI assistant can use SNOW without installing custom plugins, proprietary SDKs, or bespoke prompt-injection drivers.
- **Source References**: `src/snow/mcp/server.py`, `src/snow/mcp/tools.py`.

---

### Question 4: Why doesn't the Android device implement MCP directly?
- **Concept**: MCP over `stdio` requires an operating system process with standard input/output streams directly managed by an AI host desktop application.
- **SNOW Implementation**:Android runs a native Kotlin client app communicating over standard network sockets (TLS/WSS). The Windows Desktop Core runs the MCP server subprocess and acts as the capability orchestrator.
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
- **SNOW Implementation**:The AI host spawns an ephemeral Python MCP subprocess whenever an AI session starts. The persistent Desktop Core runs continuously as a background daemon. They communicate over loopback TCP (`127.0.0.1:8767`) using a shared secret file.
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
- **SNOW Implementation**:On startup, the Desktop Core generates a self-signed TLS certificate with a 2048-bit RSA key and computes its colon-separated SHA-256 fingerprint (e.g., `59:EC:2A...`). When Android connects, `SnowTrustManager.kt` checks the certificate:
  - If unpinned: Android shows the fingerprint in a dialog. Upon user approval, it saves the fingerprint into encrypted storage.
  - On subsequent connections: Android verifies that the presented certificate exactly matches the pinned fingerprint. Any mismatch throws `CertificateMismatchException` and aborts the connection.
- **Design Rationale**: Prevents local ARP spoofing and Man-in-the-Middle (MitM) attacks on Wi-Fi networks without relying on external centralized CAs.
- **Source References**: `src/snow/security/tls.py`, `android/.../TlsConfig.kt`.

---

### Question 9: How does the Android Keystore protect cryptographic keys?
- **Concept**: Software-stored keys in ordinary files can be extracted if an attacker gains root or physical access. The Android Keystore system stores cryptographic keys in hardware-isolated security modules (TEE — Trusted Execution Environment or StrongBox Keymaster).
- **SNOW Implementation**:In `EncryptedCertPinStorage.kt`, SNOW generates an AES-256-GCM key inside `AndroidKeyStore`. The key material never leaves the secure hardware. All encryption and decryption operations execute inside the hardware security module; only ciphertext and initialization vectors (IVs) are written to `SharedPreferences`.
- **Design Rationale**: Guarantees that even if device storage is inspected, the plaintext auth token and pinned certificate fingerprints cannot be decrypted without the hardware key.
- **Source References**: `android/app/src/main/java/org/snow/security/EncryptedCertPinStorage.kt`.

---

### Question 10: Why did you choose AES-GCM over AES-CBC?
- **Concept**: Cipher Block Chaining (CBC) provides confidentiality but no built-in integrity check; it requires a separate HMAC (Encrypt-then-MAC) and is vulnerable to padding oracle attacks. Galois/Counter Mode (GCM) is an Authenticated Encryption with Associated Data (AEAD) mode.
- **SNOW Implementation**:SNOW uses AES with 128-bit authentication tags and 12-byte random IVs (`AES/GCM/NoPadding`).
- **Design Rationale**: GCM provides both confidentiality and tamper detection simultaneously in a single cryptographic pass. If an attacker alters a single bit of the stored ciphertext, decryption fails immediately with an `AEADBadTagException`.
- **Source References**: `android/app/src/main/java/org/snow/security/EncryptedCertPinStorage.kt`.

---

### Question 11: Why store SHA-256 hashes of auth tokens in SQLite instead of plaintext tokens?
- **Concept**: One-way cryptographic hashing ensures that database contents cannot be reversed to derive active credentials.
- **SNOW Implementation**:In `src/snow/security/db.py`, when a token is issued, SNOW computes `hashlib.sha256(token.encode()).hexdigest()` and writes only the 64-character hex hash to `snow_devices.db`. When an `auth_request` arrives, the incoming token is hashed and matched against the database.
- **Design Rationale**: Follows standard credential storage best practices (analogous to password hashing). If the local SQLite file (`snow_devices.db`) is read or copied by an unauthorized process, the attacker cannot impersonate the device because SHA-256 is computationally irreversible.
- **Source References**: `src/snow/security/db.py`, `src/snow/security/session.py`.

---

### Question 12: How does `hmac.compare_digest` protect against timing attacks?
- **Concept**: Standard string equality (`a == b`) compares characters sequentially from left to right and short-circuits on the first mismatched character. An attacker measuring execution time with nanosecond precision can infer characters one by one.
- **SNOW Implementation**:In `src/snow/security/pairing.py` and `src/snow/security/session.py`, PIN and token verification strictly use Python's standard `hmac.compare_digest(a, b)`.
- **Design Rationale**: `hmac.compare_digest` compares all bytes in constant time regardless of where the mismatch occurs, completely eliminating timing side-channel leakage.
- **Source References**: `src/snow/security/pairing.py` line 215.

---

### Question 13: How does SNOW prevent path traversal and unauthorized filesystem access?
- **Concept**: An attacker or prompt-injected AI might attempt to read or overwrite critical files using relative paths (e.g., `../../Windows/System32/config/SAM`).
- **SNOW Implementation**:In `src/snow/capabilities/windows/files.py`:
  1. Paths are resolved to their strict canonical absolute form using `pathlib.Path.resolve()`.
  2. The resolved path is checked against configured allowed roots (`~/.snow/transfers`, `~/Documents/SNOW`) using `try: resolved.relative_to(root)`.
  3. Any path resolving outside permitted directories triggers an immediate rejection with status `PATH_TRAVERSAL_DETECTED`.
- **Design Rationale**: Prevents reading sensitive configuration files, SSH keys, or system binaries.
- **Source References**: `src/snow/capabilities/windows/files.py`.

---

### Question 14: How does large-file transfer work without exhausting device RAM?
- **Concept**: Reading an entire 2 GB file into memory (`file.read()`) causes out-of-memory crashes on both the desktop and mobile devices.
- **SNOW Implementation**:The HTTPS data plane streams binary data in fixed 64 KiB chunks:
  - Desktop `TransferManager` and `aiohttp` use asynchronous generator streaming (`content.iter_chunked(65536)`).
  - Android OkHttp `FileTransferClient` streams directly from/to `InputStream` and `OutputStream` with a 64 KiB byte buffer (`ByteArray(65536)`).
- **Design Rationale**: Memory consumption remains strictly bounded at $O(1)$ (approx. 64 KiB) regardless of whether transferring a 10 KB text file or a 10 GB disk image.
- **Source References**: `src/snow/transfer/http_server.py`, `android/.../AndroidFileHandler.kt`.

---

### Question 15: How are transfer integrity and atomic finalization achieved?
- **Concept**: Network glitches can corrupt bytes or produce truncated partial files.
- **SNOW Implementation**:
  1. *Staging*: Incoming files are saved as temporary staging files (`<uuid>.part`).
  2. *Streaming SHA-256*: As chunks arrive, `hashlib.sha256()` (Python) and `MessageDigest.getInstance("SHA-256")` (Kotlin) update the cryptographic digest in real time.
  3. *Validation*: Upon transfer completion, the computed SHA-256 is compared against the pre-negotiated hash.
  4. *Atomic Finalization*: If hashes match, the file is atomically renamed to its destination name (`os.replace()` in Python, `File.renameTo()` in Android). If hashes mismatch, the `.part` file is deleted immediately and HTTP 422 is returned.
- **Design Rationale**: Ensures that corrupted or incomplete files are never left in the target directory or presented as valid downloads.
- **Source References**: `src/snow/transfer/http_server.py`, `android/.../AndroidFileHandler.kt`.

---

### Question 16: How does cross-language protocol parity testing work?
- **Concept**: Cross-language communication often fails due to subtle serialization differences (e.g., camelCase vs snake_case, ISO-8601 formatting, or null field emissions).
- **SNOW Implementation**:`scripts/run_cross_language_tests.py` orchestrates bidirectional validation:
  - Step 1: Python generates 45 valid and 27 negative JSON envelopes to disk.
  - Step 2: Gradle executes JVM unit tests (`CrossLanguageParityTest.kt`), validating every Python envelope and exporting 45 valid and 27 negative Kotlin envelopes.
  - Step 3: Python's `unittest` runner parses and validates every Kotlin envelope.
- **Design Rationale**: Verifies that both sides adhere to the exact same wire contract. 144 / 144 bidirectional fixtures pass with 0 errors.
- **Source References**: `tests/test_cross_language_parity.py`, `android/.../CrossLanguageParityTest.kt`.

---

### Question 17: How does SNOW handle unexpected network disconnection and reconnection?
- **Concept**: Mobile devices frequently experience network drops, Wi-Fi handoffs, and screen-off states.
- **SNOW Implementation**:
  - *Heartbeat Keepalive*: The Android client sends application-level heartbeats every 15 seconds. The desktop responds with `heartbeat_ack`. If 3 consecutive keepalives fail, the connection is considered dead.
  - *Exponential Backoff*: When disconnected, Android's `ExponentialBackoffPolicy.kt` retries connection with backoff intervals ($1\text{s} \rightarrow 2\text{s} \rightarrow 4\text{s} \rightarrow 8\text{s} \dots \max 60\text{s}$) plus random jitter.
  - *Automatic Token Authentication*: Upon socket reconnection, Android auto-authenticates using its stored Keystore token without requiring user intervention.
- **Design Rationale**: Prevents connection storms (thundering herd) and ensures seamless recovery when moving between Wi-Fi access points.
- **Source References**: `android/.../ExponentialBackoffPolicy.kt`, `android/.../SnowWebSocketClient.kt`.

---

### Question 18: Why does Android restrict background activity launches, and how does that affect `snow_android_launch_app`?
- **Concept**: Starting with Android 10 (API 29) and enforced in Android 14–17, Google introduced strict Background Activity Launch (BAL) restrictions to prevent rogue or background apps from stealing user focus or hijacking the screen.
- **SNOW Implementation**:In `AppManagementHandler.kt`, `startActivity()` is flagged with `FLAG_ACTIVITY_NEW_TASK`.
  - When SNOW is in the foreground: The target application launches immediately onto the screen.
  - When SNOW is in the background: The OS blocks direct activity launching (`BAL blocked`).
- **Design Rationale & Viva Defense**: `FLAG_ACTIVITY_NEW_TASK` sets task affinity, but it does NOT grant permission to bypass Android's BAL security restrictions. The proper, platform-compliant architectural solution is posting a high-priority notification with a `PendingIntent`, which the user taps to authorize the launch.
- **Source References**: `android/.../AppLauncherHandler.kt`, `docs/CONNECTIVITY_TEST_RESULTS.md` Section 11.

---

### Question 19: What happens if the AI assistant calls an Android tool when the phone is offline or unpaired?
- **Concept**: An AI assistant must never crash or hang indefinitely if an external hardware dependency is unavailable.
- **SNOW Implementation**:In `src/snow/mcp/bridge.py` and `src/snow/mcp/tools.py`:
  1. The bridge queries the core's `ConnectionManager`.
  2. If the device ID is not found: returns structured status `DEVICE_NOT_PAIRED`.
  3. If the device is paired but the WebSocket is closed: returns structured status `DEVICE_OFFLINE` with an actionable error description.
- **Design Rationale**: Returning clean, structured JSON errors allows the LLM agent to understand that the physical device is temporarily unreachable and explain this to the user without crashing the MCP stdio stream.
- **Source References**: `src/snow/mcp/bridge.py`, `src/snow/mcp/tools.py`.

---

### Question 20: What are the current limitations of SNOW, and what are realistic future improvements?
- **Concept**: Transparent engineering requires honest evaluation of project boundaries and real-world constraints.
- **SNOW Limitations**:
  1. *AP Isolation*: Certain commercial Wi-Fi routers enable Client Isolation, blocking peer-to-peer Wi-Fi packets (mitigated by mobile hotspot or ADB reverse tunneling).
  2. *Clipboard Reading*: Android 10+ restricts clipboard read access to apps with active window focus; therefore, SNOW's clipboard capability is write-only from desktop to mobile.
  3. *Background App Launch*: Background app launching requires user-mediated notification interaction on modern Android versions.
- **Realistic Future Improvements**:
  1. *mDNS / DNS-SD Auto-Discovery*: Implement automated network service discovery (`_snow._tcp.local`) to eliminate manual IP entry.
  2. *Notification-Mediated Background Launch*: Implement `PendingIntent` notifications to bridge background activity launches.
  3. *Encrypted Local Staging*: Encrypt temporary transfer staging files on disk with AES-GCM.
- **Source References**: `docs/FINAL_ARCHITECTURE_REPORT.md` Section I, `ROADMAP.md`.
