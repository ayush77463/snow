# SNOW Remote MCP Platform: 24/7 Public Hosting Guide

**Execution Date:** 2026-11-22  
**Platform:** SNOW V4 (`v4/product-evolution`)  

---

## 1. Architectural Overview

SNOW allows remote AI assistants (Claude Web/Desktop, ChatGPT, Gemini) to access local and cross-device capabilities without exposing raw internal ports or compromising device security.

```text
Remote AI Client (Claude / ChatGPT / Gemini)
         ↓  (HTTPS + OAuth 2.1 + PKCE S256)
Public Internet (Domain: mcp.yourdomain.com)
         ↓  (Port 80/443)
Caddy Reverse Proxy (Automatic TLS 1.3 via Let's Encrypt)
         ↓  (Internal Docker Network, Port 8771)
SNOW Remote MCP Gateway
         ↓  (Local IPC / Authenticated Session)
ExecutionPrincipal.AI_MCP
         ↓
CapabilityEngine & ApprovalPolicyEngine
         ↓
Local Windows / Connected Android Mesh Operations
```

---

## 2. Deployment Architecture: Cloud VPS vs. Laptop Tunnel

It is vital to understand the difference between permanent 24/7 hosting and ephemeral local tunnels:

| Property | Cloud VPS Deployment (`deploy/docker-compose.yml`) | Ephemeral Laptop Tunnel (`snow expose`) |
|---|---|---|
| **Availability** | 24/7 continuous uptime | Only when laptop is awake and tunnel running |
| **Network IP** | Static public IPv4/IPv6 | Dynamic tunnel egress |
| **TLS Certificates** | Managed Let's Encrypt / ZeroSSL on custom domain | Cloudflare / Tailscale edge certificates |
| **Ideal For** | Always-on MCP Hub coordinating multi-device mesh | Quick testing, demos, and ad-hoc AI sessions |
| **Device Execution** | Coordinates paired devices via Relay Mesh | Directly executes local Windows + paired Android |

---

## 3. Deployment Instructions (Cloud VPS)

### Prerequisites
- Docker Engine 24+ and Docker Compose v2.
- A registered domain or subdomain (e.g. `mcp.example.com`) with DNS `A`/`AAAA` records pointed to the VPS IP.
- Inbound ports `80` and `443` open on VPS firewall.

### Step-by-Step Setup

1. **Clone repository and enter deployment directory:**
   ```bash
   cd deploy
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   nano .env
   ```
   Set:
   ```env
   SNOW_DOMAIN=mcp.yourdomain.com
   CADDY_ACME_EMAIL=your-email@example.com
   SNOW_MCP_PUBLIC_URL=https://mcp.yourdomain.com
   ```

3. **Launch the stack:**
   ```bash
   docker compose up -d
   ```

4. **Verify container health and TLS issuance:**
   ```bash
   docker compose ps
   docker compose logs caddy
   curl -I https://mcp.yourdomain.com/health
   ```
   Expected response: `HTTP/2 200` with `status: healthy`.

5. **Verify OAuth Discovery Endpoints:**
   ```bash
   curl https://mcp.yourdomain.com/.well-known/oauth-protected-resource
   curl https://mcp.yourdomain.com/.well-known/oauth-authorization-server
   ```

---

## 4. Connecting Your AI Client

### Claude Desktop / Claude Web
1. Provide the Streamable HTTP endpoint:
   `https://mcp.yourdomain.com/mcp`
2. Authentication will automatically initiate via OAuth 2.1 PKCE authorization code flow.

### ChatGPT (Developer Mode / Custom Connector)
1. Add custom connector pointing to:
   `https://mcp.yourdomain.com/mcp`
2. Configure OAuth 2.1 Authorization Code Flow with PKCE S256.

---

## 5. Security & Operational Hardening

- **Non-Root Execution:** The Docker container runs as UID `10001` (`snow`).
- **Internal Only Gateway:** Port `8771` is NOT published to the host; only Caddy communicates with the gateway over `snow_net`.
- **SSRF & DNS-Rebinding Defense:** Client ID Metadata Documents (CIMD) validate resolved IP addresses and pin connections to prevent attacker pivoting into private networks.
- **Strict Execution Principal:** All remote operations run as `ExecutionPrincipal.AI_MCP`. Sensitive operations require user consent via the approval policy engine.
- **Backup & Recovery:**
  To back up paired device database and state:
  ```bash
  docker compose exec snow-mcp-gateway tar czf /tmp/backup.tar.gz -C /home/snow/.snow .
  docker cp $(docker compose ps -q snow-mcp-gateway):/tmp/backup.tar.gz ./backup.tar.gz
  ```
