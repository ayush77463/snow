# SNOW V4 — Consumer Onboarding & Distribution Guide
## Standalone Windows Packaging, Lightweight System Tray, Android APK Sharing & Guided Onboarding

---

## 1. Architectural Overview

SNOW V4 provides a streamlined consumer onboarding and distribution pipeline across Windows and Android devices:

```
+-------------------------------------------------------------------------------+
|                                  CONSUMER                                     |
+-------------------------------------------------------------------------------+
       |                                                 |
       v (Download & Run)                                v (Local Install)
+-------------------------------+             +----------------------------------+
| Windows Standalone Package    |             | Android Mobile App (APK)         |
| - PyInstaller: dist/snow/     |             | - Signed release APK             |
| - Inno Setup: SNOW-Setup.exe  |             | - Local share: /api/install/apk  |
+-------------------------------+             +----------------------------------+
       |                                                 |
       v (Tray Companion)                                v (QR Pairing)
+-------------------------------+             +----------------------------------+
| Win32 System Tray (snow tray) |<----------->| Guided Web Onboarding Wizard     |
| - Memory RSS < 35 MB          |             | 1. Name Your Mesh Network        |
| - Live Daemon Status Tooltip  |             | 2. Scan QR / PIN on Android      |
| - HKCU Run Autostart Toggle   |             | 3. Connect AI Assistant via MCP  |
+-------------------------------+             +----------------------------------+
                                       |
                                       v
                       +----------------------------------+
                       | Optional Account Discovery       |
                       | - Strictly Opt-In (Off by default|
                       | - Zero Cloud Calls when disabled |
                       | - NEVER bypasses mTLS or Pairing |
                       +----------------------------------+
```

---

## 2. Windows Standalone Packaging Pipeline

The Windows distribution pipeline bundles the complete SNOW environment into a zero-prerequisite standalone Windows application.

### Pipeline Components

- **`packaging/windows/snow.spec`**:
  PyInstaller specification configuring binary inclusion, Web Dashboard static assets (`snow/web/static`), and runtime dependencies.
- **`packaging/windows/snow_setup.iss`**:
  Inno Setup 6 compilation script producing a clean, modern installer:
  - Installs to `%LOCALAPPDATA%\Programs\SNOW` (zero administrator privileges required).
  - Creates Start Menu shortcuts for the System Tray Companion and Web Dashboard.
  - Optional Desktop shortcut and "Start SNOW on Windows Login" checkbox.
  - Clean uninstaller ensuring registry keys and runtime caches are scrubbed.
- **`packaging/windows/build_release.py`**:
  Orchestration CLI coordinating PyInstaller and Inno Setup compilation.

### Building the Release

```powershell
# Preflight validation (Dry run)
py -3.13 packaging/windows/build_release.py --dry-run

# Full Standalone Bundle Compilation
py -3.13 packaging/windows/build_release.py

# Skip Inno Setup installer compilation (directory bundle only)
py -3.13 packaging/windows/build_release.py --skip-installer
```

Output:
- Directory bundle: `dist/snow/` (`snow.exe` console CLI/daemon, `snow-tray.exe` no-console system tray companion, and bundled dependencies)
- Windows installer: `packaging/output/SNOW-Setup-4.4.0.exe` (when Inno Setup 6 is installed)

---

## 3. Lightweight Win32 System Tray Companion

The SNOW System Tray Companion (`snow tray`, or standalone `snow-tray.exe`) provides an unobtrusive background notification icon with live daemon health monitoring and instant access to the dashboard. Under PyInstaller, a dedicated `snow-tray.exe` executable is built with `console=False` so no terminal/console window pops up when launched.

### Design Guarantees

1. **Ultra-Lean Footprint (< 35 MB RSS)**:
   Implemented using pure Python `ctypes` calling standard Windows Win32 APIs (`user32.dll`, `shell32.dll`, `kernel32.dll`, `advapi32.dll`). Avoids heavy UI frameworks (PyQt, wxPython, Electron).
2. **Live Tooltip Telemetry**:
   Dynamic tooltip reflecting Core daemon readiness (`Running (Port 8767)` or `Stopped`) and active paired device count.
3. **Context Menu Actions**:
   - **Open Dashboard**: Launches default browser to `http://127.0.0.1:8769`.
   - **Pair New Device (QR)**: Opens pairing workflow in dashboard.
   - **Start Core Daemon**: Launches background daemon asynchronously.
   - **Stop Core Daemon**: Gracefully terminates daemon process.
   - **Start on Windows Login**: Toggles HKCU `Software\Microsoft\Windows\CurrentVersion\Run` entry.
   - **Exit SNOW**: Cleans up Win32 tray resources and closes.
4. **Registry Safety**:
   Clean uninstaller cleanup via `snow.tray.autostart.remove_autostart()`.

### Running the Tray Companion

```powershell
# Standard invocation
snow tray

# Headless / Test mode
snow tray --headless --no-auto-start
```

---

## 4. Android Release Signing & Local APK Distribution

### Release Signing Configuration

The Android application build script (`android/app/build.gradle.kts`) dynamically configures release signing using environment variables:

| Environment Variable | Description |
|---|---|
| `SNOW_KEYSTORE_PATH` | Path to the release `.jks` or `.keystore` file |
| `SNOW_KEYSTORE_PASSWORD` | Keystore password |
| `SNOW_KEY_ALIAS` | Key alias |
| `SNOW_KEY_PASSWORD` | Key private password |

If environment variables are omitted, the build gracefully defaults to unsigned or standard debug compilation.

### Local APK Share Endpoint

The Web Dashboard hosts an authenticated, path-traversal-protected endpoint for direct local phone download:

`GET /api/install/android-apk`

- **Detection Order**:
  1. `SNOW_ANDROID_APK_PATH` environment variable.
  2. `android/app/build/outputs/apk/release/app-release.apk`
  3. `android/app/build/outputs/apk/release/app-release-unsigned.apk`
  4. `android/app/build/outputs/apk/debug/app-debug.apk`
- **Security Protections**:
  - Requires an active, authenticated dashboard session (`@require_auth` session cookie). Prevents unauthenticated network scraping or arbitrary binary harvesting across local LANs.
  - Strict path traversal defense (`os.path.realpath`, verification of `.apk` extension, and containment within the repository or designated APK directory).

---

## 5. Guided First-Run Consumer Onboarding Wizard

When a user launches the SNOW Web Dashboard for the first time, the 3-step onboarding wizard guides them through configuration:

1. **Step 1: Network Name**:
   Prompts the user to name their personal device mesh (e.g., "Home Mesh", "Ayush's Network"). Persisted in SQLite `app_settings` and `network_identity`.
2. **Step 2: Connect Phone (QR Pairing)**:
   Displays live pairing QR code, 6-digit PIN, direct APK download button, and real-time device connection detector.
3. **Step 3: Connect AI Assistant (Optional)**:
   Provides copyable CLI command (`snow setup`) to configure Claude Desktop, Gemini Antigravity, or Cursor with zero manual JSON editing.
4. **Completion & Bypassing**:
   - Marking completed saves `onboarding_completed: true` in `app_settings`.
   - Users may click "Skip Setup" at any time.
   - The wizard can be re-launched whenever needed via the **"🧙‍♂️ Setup Wizard"** button in the dashboard sidebar.

---

## 6. Optional Opt-In Account Discovery Layer

### Strict Security Boundaries

The account discovery layer (`snow.network.account_discovery.AccountDiscoveryService`) provides optional OIDC-based device location across subnets:

- **Strictly Opt-In**: Disabled by default in settings.
- **Zero Cloud Calls when Disabled**: When disabled, no network queries, HTTP requests, or DNS resolutions occur.
- **Zero Bypass of Device Security**:
  > Account identity NEVER replaces device certificates, mutual TLS (mTLS), or pairing tokens. Even if two devices share the same verified account ID, they MUST still complete cryptographic pairing and establish mTLS before executing any capability.

### OIDC Token Validation Contract

- Token structure: Exactly 3 segments (`header.payload.signature`).
- Algorithm enforcement: Rejection of `none` algorithm. Strict support for `RS256` and `ES256`.
- Claim validation:
  - `exp`: Expiration checking with clock skew.
  - `nbf`: Not-before timestamp verification.
  - `iss`: Issuer matching.
  - `aud`: Audience matching.
  - `sub`: Valid subject identifier (Account ID).
- Signature validation: Verifies RSA/ECDSA signature using PEM public keys.
