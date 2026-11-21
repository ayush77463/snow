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
import logging
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_AUTH_CODE_TTL_SECONDS: float = 600.0  # 10 minutes
DEFAULT_ACCESS_TOKEN_TTL_SECONDS: float = 3600.0  # 1 hour
DEFAULT_REFRESH_TOKEN_TTL_SECONDS: float = 86400.0 * 30.0  # 30 days


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
    """In-memory OAuth 2.1 Authorization and Token Management Server."""

    def __init__(self, issuer: str = "http://127.0.0.1:8771") -> None:
        self.issuer = issuer.rstrip("/")
        self._clients: dict[str, OAuthClient] = {}
        self._auth_codes: dict[str, AuthorizationCode] = {}
        # access_token -> TokenRecord
        self._access_tokens: dict[str, TokenRecord] = {}
        # refresh_token -> TokenRecord
        self._refresh_tokens: dict[str, TokenRecord] = {}
        # family_id -> set of refresh_tokens
        self._token_families: dict[str, set[str]] = {}

    def register_client(
        self,
        client_name: str,
        redirect_uris: Optional[list[str]] = None,
        scope: str = "snow:mcp",
        is_confidential: bool = False,
    ) -> dict[str, Any]:
        """Perform Dynamic Client Registration (RFC 7591)."""
        client_id = f"snow_client_{secrets.token_hex(12)}"
        client_secret = secrets.token_urlsafe(32) if is_confidential else None

        client = OAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            client_name=client_name or "AI Assistant Client",
            redirect_uris=redirect_uris or ["http://localhost", "http://127.0.0.1"],
            scope=scope,
            created_at=time.time(),
        )
        self._clients[client_id] = client
        logger.info("Registered dynamic OAuth client: %s (%s)", client.client_name, client_id)

        res = {
            "client_id": client_id,
            "client_name": client.client_name,
            "redirect_uris": client.redirect_uris,
            "scope": client.scope,
            "token_endpoint_auth_method": "client_secret_post" if is_confidential else "none",
        }
        if client_secret:
            res["client_secret"] = client_secret
        return res

    def get_client(self, client_id: str) -> Optional[OAuthClient]:
        """Retrieve registered client metadata."""
        return self._clients.get(client_id)

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
        now = time.time()
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            expires_at=now + DEFAULT_AUTH_CODE_TTL_SECONDS,
            used=False,
        )
        self._auth_codes[code] = auth_code
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
        auth_code = self._auth_codes.get(code)
        if not auth_code:
            return False, {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}

        # Immediate single-use consumption: revoke code regardless of outcome
        self._auth_codes.pop(code, None)

        if auth_code.used or time.time() > auth_code.expires_at:
            return False, {"error": "invalid_grant", "error_description": "Authorization code expired or already used"}

        if auth_code.client_id != client_id:
            return False, {"error": "invalid_grant", "error_description": "Client ID mismatch"}

        # Validate client credentials if client is confidential
        client = self.get_client(client_id)
        if client and client.client_secret:
            if not client_secret or not secrets.compare_digest(client.client_secret, client_secret):
                return False, {"error": "invalid_client", "error_description": "Client secret authentication failed"}

        # PKCE S256 Verification: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
        if not code_verifier:
            return False, {"error": "invalid_grant", "error_description": "Missing code_verifier"}

        try:
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            computed_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
            expected_challenge = auth_code.code_challenge.rstrip("=")
            if not secrets.compare_digest(computed_challenge, expected_challenge):
                return False, {"error": "invalid_grant", "error_description": "PKCE code_verifier verification failed"}
        except Exception as exc:
            return False, {"error": "invalid_grant", "error_description": f"PKCE validation error: {exc}"}

        # Issue tokens
        auth_code.used = True
        return True, self._issue_token_pair(client_id, auth_code.scope)

    def refresh_access_token(
        self,
        refresh_token: str,
        client_id: str,
        client_secret: Optional[str] = None,
    ) -> tuple[bool, dict[str, Any]]:
        """Rotate refresh token, enforce single-use replay protection, and issue new token pair."""
        token_record = self._refresh_tokens.get(refresh_token)
        if not token_record:
            return False, {"error": "invalid_grant", "error_description": "Invalid refresh token"}

        client = self.get_client(client_id)
        if client and client.client_secret:
            if not client_secret or not secrets.compare_digest(client.client_secret, client_secret):
                return False, {"error": "invalid_client", "error_description": "Client secret authentication failed"}

        # Token Replay Detection: If token is revoked or already used, revoke whole family
        if token_record.revoked or time.time() > token_record.refresh_expires_at:
            self._revoke_family(token_record.family_id)
            return False, {
                "error": "invalid_grant",
                "error_description": "Refresh token replay detected. Token family invalidated for security.",
            }

        # Invalidate old refresh token immediately (rotation)
        token_record.revoked = True
        self._access_tokens.pop(token_record.access_token, None)

        # Issue new token pair preserving family_id
        new_pair = self._issue_token_pair(client_id, token_record.scope, family_id=token_record.family_id)
        return True, new_pair

    def revoke_token(self, token: str) -> bool:
        """Revoke an access token or refresh token (RFC 7009)."""
        found = False
        if token in self._access_tokens:
            rec = self._access_tokens.pop(token)
            rec.revoked = True
            found = True
        if token in self._refresh_tokens:
            rec = self._refresh_tokens.pop(token)
            rec.revoked = True
            found = True
        return found

    def validate_access_token(self, access_token: str) -> Optional[TokenRecord]:
        """Validate bearer access token, checking revocation and expiration."""
        if not access_token:
            return None
        rec = self._access_tokens.get(access_token)
        if not rec or rec.revoked:
            return None
        if time.time() > rec.expires_at:
            self._access_tokens.pop(access_token, None)
            return None
        return rec

    def _issue_token_pair(
        self, client_id: str, scope: str, family_id: Optional[str] = None
    ) -> dict[str, Any]:
        now = time.time()
        access_tok = f"snow_at_{secrets.token_urlsafe(32)}"
        refresh_tok = f"snow_rt_{secrets.token_urlsafe(32)}"
        fam_id = family_id or f"fam_{secrets.token_hex(8)}"

        record = TokenRecord(
            access_token=access_tok,
            refresh_token=refresh_tok,
            client_id=client_id,
            scope=scope,
            expires_at=now + DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
            refresh_expires_at=now + DEFAULT_REFRESH_TOKEN_TTL_SECONDS,
            family_id=fam_id,
            revoked=False,
        )

        self._access_tokens[access_tok] = record
        self._refresh_tokens[refresh_tok] = record
        self._token_families.setdefault(fam_id, set()).add(refresh_tok)

        return {
            "access_token": access_tok,
            "token_type": "Bearer",
            "expires_in": int(DEFAULT_ACCESS_TOKEN_TTL_SECONDS),
            "refresh_token": refresh_tok,
            "scope": scope,
        }

    def _revoke_family(self, family_id: str) -> None:
        """Invalidate all tokens associated with a compromised token family."""
        tokens = self._token_families.pop(family_id, set())
        for tok in tokens:
            rec = self._refresh_tokens.pop(tok, None)
            if rec:
                rec.revoked = True
                self._access_tokens.pop(rec.access_token, None)
        logger.warning("Compromised OAuth token family [%s] invalidated.", family_id)

    def get_protected_resource_metadata(self) -> dict[str, Any]:
        """Return RFC 9207 / RFC 8414 Resource Server metadata."""
        return {
            "resource": f"{self.issuer}/mcp",
            "authorization_servers": [self.issuer],
            "scopes_supported": ["snow:mcp", "read", "write"],
            "bearer_methods_supported": ["header"],
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
            "scopes_supported": ["snow:mcp", "read", "write"],
        }
