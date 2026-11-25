# SNOW AI Assistant Hosting & Integration Guide (v4.1.0)

**SNOW** provides a standardized Model Context Protocol (MCP) bridge exposing exactly **42 static capabilities** across Windows desktop and Android mobile devices to compatible AI assistant platforms.

This document details local stdio integration, remote Streamable HTTP gateway deployment, tunnel configuration, OAuth 2.1 authentication, and an empirical host compatibility matrix.

---

## 1. Architecture & Protocol Overview

SNOW supports two MCP transport modalities:

```
                      +---------------------------------------+
                      |       Compatible AI Host              |
                      | (Claude, Gemini, Cursor, ChatGPT, etc)|
                      +---------------------------------------+
                                  |                 |
                    Local stdio   |                 | Remote HTTP
                  (Process stdin) |                 | (SSE / HTTP POST)
                                  v                 v
                 +-----------------------+  +-----------------------+
                 | SNOW CLI / Binary     |  | SNOW Remote Gateway   |
                 | (snow.exe mcp)        |  | (port 8771)           |
                 +-----------------------+  +-----------------------+
                                  |                 |
                                  | Authenticated   | Authenticated
                                  | Loopback IPC    | Loopback IPC
                                  | (port 8767)     | (port 8767)
                                  v                 v
                      +---------------------------------------+
                      |         SNOW Desktop Core             |
                      |   (Headless asyncio Daemon :8765)     |
                      |        Principal: AI_MCP              |
                      +---------------------------------------+
                                  |
                                  | TLS WebSocket (Control :8765)
                                  | Authenticated HTTPS (Transfer :8766)
                                  v
                      +---------------------------------------+
                      |          Paired Android Phone         |
                      |    (Foreground Service Architecture)  |
                      +---------------------------------------+
```

### Security Boundaries
- **Principal Isolation**: Operations invoked by AI assistants run under `ExecutionPrincipal.AI_MCP`. They are constrained by strict allowlists and the `ApprovalPolicyEngine`.
- **Private Desktop Boundaries**:
  - Web Dashboard (`127.0.0.1:8769`) is strictly bound to loopback and DNS-rebinding protected.
  - Desktop Core IPC (`127.0.0.1:8767`) and TLS Control Plane (`:8765`) are never exposed through public tunnels.
- **Remote Gateway Isolation**: Only port `8771` (the Remote MCP Streamable HTTP Gateway) is ever permitted to be tunneled or exposed to external AI networks.

---

## 2. Host Compatibility Matrix

| AI Assistant Host | Integration Type | Transport | Auth Method | Tested Status | Notes / Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Claude Desktop** | Local | `stdio` | Subprocess IPC | **Fully Supported** | Auto-configured via `snow setup --host claude` or Web Dashboard. |
| **Cursor IDE** | Local | `stdio` | Subprocess IPC | **Fully Supported** | Configured in `~/.cursor/mcp.json` via `snow setup --host cursor`. |
| **Google Antigravity** | Local / Plugin | `stdio` | Subprocess IPC | **Fully Supported** | Configured in `~/.gemini/antigravity/mcp_config.json`. |
| **Gemini CLI** | Local | `stdio` | Subprocess IPC | **Fully Supported** | Configured in `~/.gemini/settings.json`. |
| **ChatGPT Developer**| Remote | `Streamable HTTP`| OAuth 2.1 PKCE | **Supported via Tunnel** | Requires public HTTPS endpoint (`cloudflared` or `tailscale`). |
| **Claude Web / Remote**| Remote | `Streamable HTTP`| OAuth 2.1 PKCE | **Supported via Tunnel** | Connects to `/mcp` with automatic RFC 7591 client registration. |
| **Generic MCP CLI** | Local / Stdio | `stdio` | Subprocess IPC | **Fully Supported** | Run `snow.exe mcp` directly from any MCP test harness. |

---

## 3. Local stdio Configuration

Local AI assistants launch SNOW directly as a child process using standard JSON-RPC over `stdio`.

### A. Packaged Distribution (`SNOW-Setup-4.1.0.exe` / `snow.exe`)
When installed via the Windows setup wizard, SNOW is located at:
`%LOCALAPPDATA%\Programs\SNOW\snow.exe`

Launch entry:
```json
{
  "mcpServers": {
    "snow": {
      "command": "C:\\Users\\<USER>\\AppData\\Local\\Programs\\SNOW\\snow.exe",
      "args": ["mcp"]
    }
  }
}
```

### B. Developer / Source Installation
When running in a Python virtual environment:
```json
{
  "mcpServers": {
    "snow": {
      "command": "D:\\Codes 2\\Snow\\.venv\\Scripts\\python.exe",
      "args": ["-m", "snow.mcp"]
    }
  }
}
```

### Verification & Handshake Test
To verify that stdio MCP integration works without manual configuration:
1. Open the SNOW Web Dashboard at `http://127.0.0.1:8769`.
2. Navigate to **Connect Your AI & Remote MCP Platform**.
3. Click **⚡ Test Local MCP (stdio)**.
4. The system executes a live JSON-RPC handshake (`initialize` -> `notifications/initialized` -> `tools/list`), verifying all 42 tools and reporting round-trip latency.

---

## 4. Remote Streamable HTTP Gateway & Public Tunnels

For cloud-based AI platforms (such as ChatGPT Custom GPTs or remote agents) that cannot execute local binaries, SNOW provides an authenticated Streamable HTTP Gateway on port `8771`.

### A. Starting the Gateway
In the Web Dashboard, click **Toggle Gateway**, or run via terminal:
```powershell
.\.venv\Scripts\python.exe -m snow.cli mcp-gateway
```
The gateway listens locally on `http://127.0.0.1:8771/mcp` and provides RFC 8414 discovery:
- Protected Resource Metadata: `http://127.0.0.1:8771/.well-known/oauth-protected-resource`
- Authorization Server Metadata: `http://127.0.0.1:8771/.well-known/oauth-authorization-server`

### B. Exposing Port 8771 via Cloudflare Tunnel
1. Ensure `cloudflared` is installed.
2. In the Web Dashboard, click **🌐 Start Cloudflare Tunnel**.
3. SNOW spawns `cloudflared tunnel --url http://127.0.0.1:8771 --no-autoupdate` as a managed child process.
4. The generated URL (e.g., `https://xyz-abc.trycloudflare.com`) is displayed on the dashboard.
5. Point your cloud AI client to: `https://xyz-abc.trycloudflare.com/mcp`

### C. Exposing via Tailscale Funnel
```powershell
tailscale funnel 8771
```

---

## 5. Owner-Friendly OAuth 2.1 Approval Queue

SNOW Remote Gateway enforces OAuth 2.1 with PKCE (S256), token hashing, and single-use authorization code invalidation.

To protect the owner from complex manual secret copying, SNOW features a **1-Click Approval Queue**:

1. When an AI client initiates authorization, it redirects the browser to `http://127.0.0.1:8771/oauth/authorize` (or via the public tunnel).
2. The authorization request is registered in the Web Dashboard's pending queue.
3. The owner visits the SNOW Web Dashboard (`http://127.0.0.1:8769`) where an alert appears under **OAuth 2.1 Authorization Queue**:
   ```
   Application: ChatGPT MCP Connector
   Requested Scopes: snow:mcp
   [Approve] [Reject]
   ```
4. Clicking **Approve** issues a cryptographically bound authorization code and automatically redirects the waiting authorization window to the AI host's callback URL.
5. Tokens are persisted using SHA-256 hashes in SQLite Schema v7; raw tokens are never logged or stored.

---

## 6. Static MCP Tool Inventory (42 Tools)

SNOW guarantees exactly 42 static FastMCP tools (38 V4 baseline + 4 V5.0.0 additions):

### Windows Desktop Capabilities (19)
1. `snow_windows_system_info` — Host telemetry, CPU, RAM, OS details.
2. `snow_windows_battery` — Windows battery status, power line status.
3. `snow_windows_volume_get` — Audio master volume and mute state.
4. `snow_windows_volume_set` — Adjust master volume.
5. `snow_windows_media_play_pause` — Toggle media playback.
6. `snow_windows_media_next` — Skip to next media track.
7. `snow_windows_media_previous` — Return to previous media track.
8. `snow_windows_lock` — Lock Windows workstation.
9. `snow_windows_screenshot` — Capture screen PNG to storage and clipboard buffer.
10. `snow_windows_notification` — Toast notification on desktop.
11. `snow_windows_app_launch` — Launch approved desktop application.
12. `snow_windows_app_list` — List installed approved desktop applications.
13. `snow_windows_file_read` — Read scoped file from approved desktop directory.
14. `snow_windows_file_write` — Write scoped file to approved desktop directory.
15. `snow_windows_file_list` — List files in approved desktop directory.
16. `snow_windows_file_search` — Search approved desktop directory.
17. `snow_windows_open_url` — Open URL in default Windows web browser.
18. `snow_windows_clipboard_get` — Get current desktop clipboard text.
19. `snow_windows_clipboard_set` — Set desktop clipboard text and update buffer.

### Android Mobile Capabilities (19)
20. `snow_android_device_info` — Android model, OS build, screen dimensions.
21. `snow_android_battery` — Android battery level, charging state, temperature.
22. `snow_android_volume_get` — Android media, ring, and notification volume.
23. `snow_android_volume_set` — Set Android stream volume.
24. `snow_android_media_play_pause` — Remote control media playback on phone.
25. `snow_android_media_next` — Remote control next media track on phone.
26. `snow_android_media_previous` — Remote control previous media track on phone.
27. `snow_android_lock` — Trigger screen lock on phone (if permission granted).
28. `snow_android_screenshot` — Request phone screen capture via HTTPS transfer plane.
29. `snow_android_notification` — Post persistent Android notification.
30. `snow_android_app_launch` — Launch approved Android application package.
31. `snow_android_app_list` — Query list of approved launcher apps on phone.
32. `snow_android_file_read` — Stream file from Android SAF storage.
33. `snow_android_file_write` — Write file into Android SAF scoped tree.
34. `snow_android_file_list` — List files in approved Android SAF directory.
35. `snow_android_file_search` — Search SAF storage tree on phone.
36. `snow_android_open_url` — Open URL on Android phone browser.
37. `snow_android_clipboard_get` — Pull current Android clipboard content.
38. `snow_android_clipboard_set` — Push content into Android clipboard and sync.
39. `snow_mesh_health_summary` — Summarize SNOW mesh health, node counts, transports, and core reachability.
40. `snow_windows_active_window` — Query the active foreground window title and owning process name on Windows.
41. `snow_windows_notify` — Display a bounded native Windows desktop toast notification.
42. `snow_windows_lock_screen` — Lock the Windows workstation (owner direct / AI approval-gated).
