# SNOW Android Client

Minimal Kotlin Android connectivity client for **SNOW**, a headless cross-device AI capability bridge.

The Android client connects to the SNOW Desktop Core over a local Wi-Fi / hotspot network using WebSockets and the **SNOW Device Protocol v1**.

---

## 1. Specifications & Environment

- **Language**: Kotlin 1.9.22
- **Android Gradle Plugin**: 8.2.2 / Gradle 8.5
- **Compile SDK**: 34 (Android 14)
- **Target SDK**: 34
- **Min SDK**: 26 (Android 8.0 Oreo)
- **Java Compatibility**: Java 17 (`sourceCompatibility` & `targetCompatibility`)

---

## 2. Package Architecture

The code is located in `android/app/src/main/java/org/snow/`:

```
org.snow/
├── protocol/
│   ├── Constants.kt               # Protocol version (1), limits, message types, and error codes
│   ├── SnowMessage.kt             # Immutable message envelope model and type-safe factories
│   ├── SnowError.kt               # Standardized error structure (code, message)
│   ├── JsonSerialization.kt       # Wire JSON serialization enforcing Clean Serialization Invariant
│   ├── ProtocolValidationError.kt # Typed protocol exception with optional correlation_id
│   └── ProtocolValidator.kt       # Strict wire-level validator conforming to Python schema
├── network/
│   ├── ConnectionState.kt         # DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING
│   ├── BackoffPolicy.kt           # Exponential backoff (1s -> 30s) with randomized jitter
│   └── SnowWebSocketClient.kt     # OkHttp WebSocket client, single lifecycle, heartbeat loop
├── service/
│   └── SnowForegroundService.kt   # Foreground service (connectedDevice) with notification
└── ui/
    └── MainActivity.kt            # Single-screen UI with connection card, status, ping, and logs
```

---

## 3. Wire Protocol & Serialization Invariant

The client adheres to **SNOW Device Protocol v1**:

- **Integer Version**: `version = 1`.
- **Standard Types**: `"request"`, `"response"`, `"error"`, `"heartbeat"`, `"heartbeat_ack"`.
- **UUIDv4**: Strict RFC 4122 UUIDv4 for message `id` and `correlation_id`.
- **Zero-Offset UTC Timestamps**: ISO-8601 timestamps ending in `Z` (e.g., `2026-11-15T14:15:30.123456Z`).
- **Clean Serialization Invariant**:
  Optional fields (`correlation_id`, `payload`, `error`) **must never be serialized as `null`**.
  When null, they are completely omitted from the JSON payload.

---

## 4. Network Security & Cleartext Policy

- **Release Builds**:
  Defined in `app/src/main/res/xml/network_security_config.xml`.
  `cleartextTrafficPermitted="false"` is strictly enforced. Cleartext `ws://` traffic is prohibited in release builds.

- **Debug Builds**:
  Defined in `app/src/debug/res/xml/network_security_config.xml`.
  `cleartextTrafficPermitted="true"` is enabled exclusively for local Wi-Fi/LAN debugging during development.

---

## 5. Foreground Service Lifecycle

- **Foreground Service Type**: `connectedDevice` (declared in `AndroidManifest.xml`).
- **Notification**: Ongoing status notification on channel `snow_connection_channel`.
- **User Control**: Includes a "Disconnect" action directly on the notification to cleanly terminate the background session.
- **Heartbeat & Keepalive**:
  - Heartbeat sent every 15 seconds.
  - 45-second timeout window.
  - Automatically recovers using exponential backoff (1s, 2s, 4s, 8s, 16s, max 30s + jitter).

---

## 6. Build and Verification Commands

From the `android/` directory:

### Run JVM Unit Tests
```powershell
.\gradlew.bat testDebugUnitTest
```

### Build Debug APK
```powershell
.\gradlew.bat assembleDebug
```
Output APK location:
`android/app/build/outputs/apk/debug/app-debug.apk`

---

## 7. Connecting to SNOW Desktop Core

1. On the Windows host, start the SNOW Core server:
   ```powershell
   .\.venv\Scripts\python.exe -m snow.main
   ```
2. Note the LAN IPv4 address logged to stderr (e.g. `192.168.1.50`).
3. Launch the SNOW Android app on a device on the same local network (or Android Emulator using `10.0.2.2`).
4. Enter the desktop IP address and port `8765`, then tap **Connect**.
5. Once connected, tap **Send Ping** to verify end-to-end request/response round-trip.
