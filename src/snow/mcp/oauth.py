"""OAuth 2.1 + PKCE Authorization Server and Token Lifecycle for SNOW Remote MCP Gateway.

Implements RFC 6749, RFC 7636 (PKCE), RFC 7591 (Dynamic Client Registration),
and RFC 7009 (Token Revocation). Ensures strict least-privilege token issuance,
cryptographic binding, refresh token rotation with replay detection, and
single-use authorization code invalidation.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import hashlib
import http.client
import ipaddress
import json
import logging
import secrets
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse

from snow.security.db import DatabaseManager, hash_token

logger = logging.getLogger(__name__)

DEFAULT_AUTH_CODE_TTL_SECONDS: float = 600.0  # 10 minutes
DEFAULT_ACCESS_TOKEN_TTL_SECONDS: float = 3600.0  # 1 hour
DEFAULT_REFRESH_TOKEN_TTL_SECONDS: float = 86400.0 * 30.0  # 30 days
DEFAULT_CIMD_CACHE_TTL_SECONDS: float = 600.0  # 10 minutes
DEFAULT_CIMD_MAX_CACHE_SIZE: int = 500
MAX_CIMD_BODY_SIZE_BYTES: int = 65536  # 64 KB

# Cloud metadata and link-local service IPs strictly forbidden for CIMD resolution
RESTRICTED_METADATA_IPS: set[str] = {
    "169.254.169.254",  # AWS/GCP/Azure/OpenStack IMDS
    "169.254.170.2",    # AWS ECS task metadata
    "fd00:ec2::254",    # AWS IMDS IPv6
}


class PinnedIPHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that connects directly to a pre-validated IP while preserving SNI."""

    def __init__(
        self,
        pinned_ip: str,
        sni_hostname: str,
        port: int = 443,
        context: Optional[ssl.SSLContext] = None,
        timeout: float = 5.0,
    ) -> None:
        super().__init__(pinned_ip, port=port, context=context, timeout=timeout)
        self.sni_hostname = sni_hostname

    def connect(self) -> None:
        super(http.client.HTTPSConnection, self).connect()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.sni_hostname)


def is_ip_restricted(ip_str: str) -> bool:
    """Return True if an IP address belongs to any private, loopback, link-local,
    multicast, reserved, unspecified, or cloud metadata range.
    """
    clean_ip = ip_str.strip()
    if clean_ip in RESTRICTED_METADATA_IPS:
        return True
    try:
        ip = ipaddress.ip_address(clean_ip)
        # Check IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return is_ip_restricted(str(ip.ipv4_mapped))
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return True


@dataclass
class OAuthClient:
    """Registered OAuth client application."""

    client_id: str
    client_secret: Optional[str]
    client_name: str
    redirect_uris: list[str]
    scope: str
    created_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not self.client_secret:
            data.pop("client_secret", None)
        return data


@dataclass
class AuthorizationCode:
    """Single-use authorization code with PKCE binding."""

    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    scope: str
    expires_at: float
    used: bool = False


@dataclass
class TokenRecord:
    """Active OAuth access and refresh token record."""

    access_token: str
    refresh_token: str
    client_id: str
    scope: str
    expires_at: float
    refresh_expires_at: float
    family_id: str
    revoked: bool = False


class OAuthServer:
    """OAuth 2.1 Authorization and Token Management Server with SQLite persistence."""

    def __init__(
        self,
        issuer: str = "http://127.0.0.1:8771",
        db_manager: Optional[DatabaseManager] = None,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.db_manager = db_manager or DatabaseManager()
        # In-memory transient cache for fetched Client ID Metadata Documents (CIMD): client_id_url -> (OAuthClient, timestamp)
        self._cimd_cache: dict[str, tuple[OAuthClient, float]] = {}

    def fetch_cimd_document(
        self, client_id_url: str, max_redirects: int = 2
    ) -> tuple[bool, dict[str, Any] | dict[str, str]]:
        """Securely fetch and validate a Client ID Metadata Document (CIMD) over HTTPS.

        Enforces strict SSRF defense:
        - HTTPS scheme only (rejects http, ftp, file, etc.).
        - Strict DNS resolution check: rejects private, loopback, link-local, multicast,
          reserved, unspecified, and cloud metadata (IMDS) IP ranges.
        - DNS Rebinding Defense: Pins the validated IP address directly on the connection
          socket while preserving TLS SNI and Host header.
        - Strict JSON parsing, max 64 KB response size, and redirect target validation.
        """
        if not isinstance(client_id_url, str) or not client_id_url.startswith("https://"):
            return False, {
                "error": "invalid_client",
                "error_description": "CIMD client_id must be a valid HTTPS URL",
            }

        parsed = urllib.parse.urlparse(client_id_url)
        hostname = parsed.hostname
        if not hostname:
            return False, {
                "error": "invalid_client",
                "error_description": "CIMD URL missing valid hostname",
            }

        port = parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # 1. Resolve hostname and validate every returned IP address (SSRF Defense)
        try:
            addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except Exception as exc:
            logger.warning("DNS resolution failed for CIMD host '%s': %s", hostname, exc)
            return False, {
                "error": "invalid_client",
                "error_description": f"DNS resolution failed for '{hostname}': {exc}",
            }

        if not addr_info:
            return False, {
                "error": "invalid_client",
                "error_description": f"No IP addresses resolved for '{hostname}'",
            }

        validated_ips: list[str] = []
        for entry in addr_info:
            sockaddr = entry[4]
            ip_str = sockaddr[0]
            if is_ip_restricted(ip_str):
                logger.warning(
                    "CIMD SSRF attempt blocked: host '%s' resolves to restricted IP [%s]",
                    hostname,
                    ip_str,
                )
                return False, {
                    "error": "invalid_client",
                    "error_description": f"SSRF blocked: host '{hostname}' resolves to restricted IP: {ip_str}",
                }
            validated_ips.append(ip_str)

        # 2. Pin connection to first validated IP to prevent DNS rebinding
        pinned_ip = validated_ips[0]
        try:
            ssl_ctx = ssl.create_default_context()
            conn = PinnedIPHTTPSConnection(
                pinned_ip=pinned_ip,
                sni_hostname=hostname,
                port=port,
                context=ssl_ctx,
                timeout=5.0,
            )
            req_headers = {
                "Host": f"{hostname}:{port}" if parsed.port and parsed.port != 443 else hostname,
                "Accept": "application/json",
                "User-Agent": "SNOW-CIMD/1.0",
            }
            conn.request("GET", path, headers=req_headers)
            resp = conn.getresponse()

            # Handle Redirects safely
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.getheader("Location")
                conn.close()
                if not location:
                    return False, {
                        "error": "invalid_client",
                        "error_description": "Redirect missing Location header",
                    }
                if max_redirects <= 0:
                    return False, {
                        "error": "invalid_client",
                        "error_description": "Exceeded maximum allowed redirects for CIMD",
                    }
                redirect_url = urllib.parse.urljoin(client_id_url, location)
                if not redirect_url.startswith("https://"):
                    return False, {
                        "error": "invalid_client",
                        "error_description": f"Insecure redirect to non-HTTPS URL: {redirect_url}",
                    }
                logger.info("Following CIMD redirect to: %s", redirect_url)
                return self.fetch_cimd_document(redirect_url, max_redirects=max_redirects - 1)

            if resp.status != 200:
                conn.close()
                return False, {
                    "error": "invalid_client",
                    "error_description": f"CIMD endpoint returned HTTP {resp.status}",
                }

            content_type = resp.getheader("Content-Type", "")
            if "json" not in content_type.lower():
                conn.close()
                return False, {
                    "error": "invalid_client",
                    "error_description": f"Invalid Content-Type for CIMD: expected JSON, got '{content_type}'",
                }

            body_bytes = resp.read(MAX_CIMD_BODY_SIZE_BYTES + 1)
            conn.close()

            if len(body_bytes) > MAX_CIMD_BODY_SIZE_BYTES:
                return False, {
                    "error": "invalid_client",
                    "error_description": f"CIMD response exceeds maximum permitted size of {MAX_CIMD_BODY_SIZE_BYTES} bytes",
                }

            doc = json.loads(body_bytes.decode("utf-8"))
            if not isinstance(doc, dict):
                return False, {
                    "error": "invalid_client",
                    "error_description": "CIMD document must be a JSON object",
                }

            # Exact Client Identity Matching: client_id in document MUST match requested URL
            doc_client_id = doc.get("client_id")
            if doc_client_id != client_id_url:
                return False, {
                    "error": "invalid_client",
                    "error_description": f"CIMD client_id '{doc_client_id}' does not match requested URL '{client_id_url}'",
                }

            # Redirect URIs validation
            redirect_uris = doc.get("redirect_uris")
            if not isinstance(redirect_uris, list) or not redirect_uris:
                return False, {
                    "error": "invalid_client",
                    "error_description": "CIMD document must specify non-empty redirect_uris array",
                }

            for uri in redirect_uris:
                if not isinstance(uri, str) or not uri.strip():
                    return False, {
                        "error": "invalid_client",
                        "error_description": "CIMD document contains empty or invalid redirect_uri",
                    }

            return True, doc

        except Exception as exc:
            logger.warning("Failed fetching CIMD from '%s': %s", client_id_url, exc)
            return False, {
                "error": "invalid_client",
                "error_description": f"Failed fetching CIMD: {exc}",
            }

    def register_client(
        self,
        client_name: str,
        redirect_uris: Optional[list[str]] = None,
        scope: str = "snow:mcp",
        is_confidential: bool = False,
        owner_snow_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Perform Dynamic Client Registration (RFC 7591) with SQLite persistence."""
        client_id = f"snow_client_{secrets.token_hex(12)}"
        client_secret = secrets.token_urlsafe(32) if is_confidential else None
        client_secret_hash = hash_token(client_secret) if client_secret else None
        now = time.time()
        uris = redirect_uris or ["http://localhost", "http://127.0.0.1", "urn:ietf:wg:oauth:2.0:oob"]
        resolved_owner = (owner_snow_id or "").strip().upper() or None
        if not resolved_owner:
            try:
                from snow.security.identity import resolve_canonical_device_snow_id
                resolved_owner, _ = resolve_canonical_device_snow_id()
            except Exception:
                resolved_owner = None

        self.db_manager.save_oauth_client(
            client_id=client_id,
            client_name=client_name or "AI Assistant Client",
            redirect_uris=uris,
            scope=scope,
            client_secret_hash=client_secret_hash,
            is_confidential=is_confidential,
            created_at=now,
            owner_snow_id=resolved_owner,
        )
        logger.info("Registered dynamic OAuth client: %s (%s)", client_name, client_id)

        res = {
            "client_id": client_id,
            "client_name": client_name or "AI Assistant Client",
            "redirect_uris": uris,
            "scope": scope,
            "token_endpoint_auth_method": "client_secret_post" if is_confidential else "none",
        }
        if client_secret:
            res["client_secret"] = client_secret
        return res

    def get_client(self, client_id: str) -> Optional[OAuthClient]:
        """Retrieve registered client metadata from SQLite DCR registry or CIMD cache/URL."""
        if not client_id:
            return None

        # 1. Check SQLite database
        row = self.db_manager.get_oauth_client(client_id)
        if row:
            return OAuthClient(
                client_id=row["client_id"],
                client_secret=row["client_secret_hash"],
                client_name=row["client_name"],
                redirect_uris=row["redirect_uris"],
                scope=row["scope"],
                created_at=row["created_at"],
            )

        # 2. Check CIMD cache
        now = time.time()
        if client_id in self._cimd_cache:
            client, cached_at = self._cimd_cache[client_id]
            if now - cached_at < DEFAULT_CIMD_CACHE_TTL_SECONDS:
                return client
            self._cimd_cache.pop(client_id, None)

        # 3. If client_id is an HTTPS URL, fetch Client ID Metadata Document (CIMD)
        if client_id.startswith("https://"):
            ok, doc_or_err = self.fetch_cimd_document(client_id)
            if ok and isinstance(doc_or_err, dict):
                parsed = urllib.parse.urlparse(client_id)
                client_name = str(doc_or_err.get("client_name") or parsed.hostname or "CIMD Client")
                redirect_uris = [str(u) for u in doc_or_err.get("redirect_uris", [])]
                scope = str(doc_or_err.get("scope") or "snow:mcp")
                client = OAuthClient(
                    client_id=client_id,
                    client_secret=None,
                    client_name=client_name,
                    redirect_uris=redirect_uris,
                    scope=scope,
                    created_at=now,
                )
                if len(self._cimd_cache) >= DEFAULT_CIMD_MAX_CACHE_SIZE:
                    oldest_key = min(self._cimd_cache.keys(), key=lambda k: self._cimd_cache[k][1])
                    self._cimd_cache.pop(oldest_key, None)
                self._cimd_cache[client_id] = (client, now)
                logger.info("Validated and cached CIMD client: %s (%s)", client.client_name, client_id)
                return client

        return None

    def create_authorization_code(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        scope: str = "snow:mcp",
    ) -> tuple[bool, str | dict[str, str]]:
        """Validate request and issue single-use authorization code with PKCE."""
        client = self.get_client(client_id)
        if not client:
            return False, {"error": "unauthorized_client", "error_description": "Unknown client_id"}

        # Strict exact redirect URI matching against registered metadata
        if redirect_uri not in client.redirect_uris:
            return False, {
                "error": "invalid_request",
                "error_description": f"Redirect URI '{redirect_uri}' is not registered for client '{client_id}'",
            }

        if code_challenge_method != "S256":
            return False, {
                "error": "invalid_request",
                "error_description": "Only 'S256' code_challenge_method is supported under OAuth 2.1",
            }

        if not code_challenge:
            return False, {
                "error": "invalid_request",
                "error_description": "Missing PKCE code_challenge",
            }

        code = f"snow_code_{secrets.token_urlsafe(32)}"
        code_h = hash_token(code)
        now = time.time()
        expires_at = now + DEFAULT_AUTH_CODE_TTL_SECONDS

        self.db_manager.save_oauth_auth_code(
            code_hash=code_h,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            expires_at=expires_at,
            created_at=now,
        )
        logger.info("Issued authorization code for client [%s]", client_id)
        return True, code

    def exchange_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
        client_secret: Optional[str] = None,
    ) -> tuple[bool, dict[str, Any]]:
        """Validate authorization code, verify PKCE S256 challenge, and issue tokens."""
        code_h = hash_token(code)
        auth_code_row = self.db_manager.consume_oauth_auth_code(code_h)
        if not auth_code_row:
            return False, {"error": "invalid_grant", "error_description": "Invalid, expired, or already used authorization code"}

        if auth_code_row["client_id"] != client_id:
            return False, {"error": "invalid_grant", "error_description": "Client ID mismatch"}

        if redirect_uri != auth_code_row["redirect_uri"]:
            return False, {"error": "invalid_grant", "error_description": "Redirect URI mismatch"}

        # Validate client credentials if client is confidential
        client = self.get_client(client_id)
        if client and client.client_secret:
            if not client_secret or not secrets.compare_digest(client.client_secret, hash_token(client_secret)):
                return False, {"error": "invalid_client", "error_description": "Client secret authentication failed"}

        # PKCE S256 Verification: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
        if not code_verifier:
            return False, {"error": "invalid_grant", "error_description": "Missing code_verifier"}

        try:
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            computed_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
            expected_challenge = auth_code_row["code_challenge"].rstrip("=")
            if not secrets.compare_digest(computed_challenge, expected_challenge):
                return False, {"error": "invalid_grant", "error_description": "PKCE code_verifier verification failed"}
        except Exception as exc:
            return False, {"error": "invalid_grant", "error_description": f"PKCE validation error: {exc}"}

        # Issue tokens and persist in SQLite
        return True, self._issue_token_pair(client_id, auth_code_row["scope"])

    def refresh_access_token(
        self,
        refresh_token: str,
        client_id: str,
        client_secret: Optional[str] = None,
    ) -> tuple[bool, dict[str, Any]]:
        """Rotate refresh token, enforce single-use replay protection, and issue new token pair."""
        rt_hash = hash_token(refresh_token)
        row = self.db_manager.get_oauth_refresh_token(rt_hash)
        if not row:
            return False, {"error": "invalid_grant", "error_description": "Invalid refresh token"}

        # Client Binding: Enforce that refresh token was issued to this client
        if row["client_id"] != client_id:
            logger.warning("Refresh token client mismatch: issued to '%s', requested by '%s'", row["client_id"], client_id)
            return False, {"error": "invalid_grant", "error_description": "Refresh token was not issued to this client"}

        client = self.get_client(client_id)
        if client and client.client_secret:
            if not client_secret or not secrets.compare_digest(client.client_secret, hash_token(client_secret)):
                return False, {"error": "invalid_client", "error_description": "Client secret authentication failed"}

        # Token Replay Detection: If token is revoked or already used, revoke whole family
        now = time.time()
        if bool(row["revoked"]) or now > float(row["refresh_expires_at"]):
            self.db_manager.revoke_oauth_family(row["family_id"])
            logger.warning("Compromised OAuth token family [%s] invalidated.", row["family_id"])
            return False, {
                "error": "invalid_grant",
                "error_description": "Refresh token replay detected. Token family invalidated for security.",
            }

        # Issue new token pair preserving family_id
        new_access_tok = f"snow_at_{secrets.token_urlsafe(32)}"
        new_refresh_tok = f"snow_rt_{secrets.token_urlsafe(32)}"
        new_at_hash = hash_token(new_access_tok)
        new_rt_hash = hash_token(new_refresh_tok)
        fam_id = row["family_id"]
        exp = now + DEFAULT_ACCESS_TOKEN_TTL_SECONDS
        ref_exp = now + DEFAULT_REFRESH_TOKEN_TTL_SECONDS

        self.db_manager.rotate_oauth_refresh_token(
            old_refresh_token_hash=rt_hash,
            new_access_token_hash=new_at_hash,
            new_refresh_token_hash=new_rt_hash,
            client_id=client_id,
            scope=row["scope"],
            family_id=fam_id,
            expires_at=exp,
            refresh_expires_at=ref_exp,
        )

        return True, {
            "access_token": new_access_tok,
            "token_type": "Bearer",
            "expires_in": int(DEFAULT_ACCESS_TOKEN_TTL_SECONDS),
            "refresh_token": new_refresh_tok,
            "scope": row["scope"],
        }

    def revoke_token(self, token: str) -> bool:
        """Revoke an access token or refresh token (RFC 7009)."""
        if not token:
            return False
        tok_hash = hash_token(token)
        return self.db_manager.revoke_oauth_token(tok_hash)

    def list_clients(self, owner_snow_id: Optional[str] = None) -> list[dict[str, Any]]:
        """List registered OAuth 2.1 AI clients bound to this device identity."""
        return self.db_manager.list_oauth_clients(owner_snow_id=owner_snow_id)

    def revoke_client(self, client_id: str, owner_snow_id: Optional[str] = None) -> dict[str, Any]:
        """Revoke a specific OAuth client and invalidate all of its tokens and families."""
        self._cimd_cache.pop(client_id, None)
        return self.db_manager.revoke_oauth_client(client_id, owner_snow_id=owner_snow_id)

    def revoke_all_on_recovery(self) -> dict[str, int]:
        """Wipe all OAuth clients, tokens, auth codes, and cached CIMD state during identity recovery."""
        self._cimd_cache.clear()
        summary = self.db_manager.revoke_all_oauth_sessions()
        logger.warning("Revoked all OAuth clients and token families on device identity recovery: %s", summary)
        return summary

    def validate_access_token(self, access_token: str) -> Optional[TokenRecord]:
        """Validate bearer access token, checking revocation and expiration."""
        if not access_token:
            return None
        at_hash = hash_token(access_token)
        row = self.db_manager.get_oauth_access_token(at_hash)
        if not row:
            return None
        return TokenRecord(
            access_token=access_token,
            refresh_token="",
            client_id=row["client_id"],
            scope=row["scope"],
            expires_at=float(row["expires_at"]),
            refresh_expires_at=float(row["refresh_expires_at"]),
            family_id=row["family_id"],
            revoked=bool(row["revoked"]),
        )

    def _issue_token_pair(
        self, client_id: str, scope: str, family_id: Optional[str] = None
    ) -> dict[str, Any]:
        now = time.time()
        access_tok = f"snow_at_{secrets.token_urlsafe(32)}"
        refresh_tok = f"snow_rt_{secrets.token_urlsafe(32)}"
        fam_id = family_id or f"fam_{secrets.token_hex(8)}"

        at_hash = hash_token(access_tok)
        rt_hash = hash_token(refresh_tok)
        exp = now + DEFAULT_ACCESS_TOKEN_TTL_SECONDS
        ref_exp = now + DEFAULT_REFRESH_TOKEN_TTL_SECONDS

        self.db_manager.save_oauth_token_record(
            access_token_hash=at_hash,
            refresh_token_hash=rt_hash,
            client_id=client_id,
            scope=scope,
            family_id=fam_id,
            expires_at=exp,
            refresh_expires_at=ref_exp,
            created_at=now,
        )

        return {
            "access_token": access_tok,
            "token_type": "Bearer",
            "expires_in": int(DEFAULT_ACCESS_TOKEN_TTL_SECONDS),
            "refresh_token": refresh_tok,
            "scope": scope,
        }

    def _revoke_family(self, family_id: str) -> None:
        """Invalidate all tokens associated with a compromised token family."""
        self.db_manager.revoke_oauth_family(family_id)
        logger.warning("Compromised OAuth token family [%s] invalidated.", family_id)

    def get_protected_resource_metadata(self) -> dict[str, Any]:
        """Return RFC 9207 / RFC 8414 Resource Server metadata."""
        return {
            "resource": f"{self.issuer}/mcp",
            "authorization_servers": [self.issuer],
            "scopes_supported": ["snow:mcp", "read", "write"],
            "bearer_methods_supported": ["header"],
            "logo_uri": f"{self.issuer}/snow_logo.png",
        }

    def get_authorization_server_metadata(self) -> dict[str, Any]:
        """Return RFC 8414 Authorization Server metadata."""
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/oauth/authorize",
            "token_endpoint": f"{self.issuer}/oauth/token",
            "registration_endpoint": f"{self.issuer}/oauth/register",
            "revocation_endpoint": f"{self.issuer}/oauth/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "client_id_metadata_document_supported": True,
            "scopes_supported": ["snow:mcp", "read", "write"],
            "logo_uri": f"{self.issuer}/snow_logo.png",
        }
