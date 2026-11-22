"""Optional, strictly opt-in account discovery layer for SNOW.

Allows users to optionally link multi-device SNOW instances under an OpenID Connect
(OIDC) identity provider to facilitate cross-subnet peer location.

ARCHITECTURAL SAFEGUARDS & PRIME DIRECTIVES:
1. STRICTLY OPT-IN: Disabled by default.
2. ZERO CLOUD CALLS WHEN DISABLED: When disabled, absolutely no network calls,
   DNS lookups, or cloud queries are executed.
3. ZERO BYPASS OF DEVICE SECURITY: Account identity NEVER replaces device
   certificates, mutual TLS (mTLS), or pairing tokens. Even if two devices
   present the same verified account ID, they MUST still complete cryptographic
   pairing and establish mTLS before executing any capability.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any, Optional
import urllib.parse
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from snow.mcp.oauth import is_ip_restricted
from snow.security.db import DatabaseManager

logger = logging.getLogger(__name__)

SETTING_ENABLED = "account_discovery_enabled"
SETTING_ISSUER = "account_discovery_issuer"
SETTING_AUDIENCE = "account_discovery_audience"
SETTING_ACCOUNT_ID = "account_discovery_account_id"


def _b64url_decode(segment: str) -> bytes:
    """Decode URL-safe base64 string with appropriate padding."""
    rem = len(segment) % 4
    if rem > 0:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment.encode("ascii"))


class AccountDiscoveryService:
    """Manages optional OIDC-based cross-subnet account discovery."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None) -> None:
        self.db_manager = db_manager or DatabaseManager()
        self._jwks_cache: dict[str, dict[str, Any]] = {}
        self._jwks_cache_ttl = 3600.0  # 1 hour

    def is_enabled(self) -> bool:
        """Check whether account discovery is currently enabled."""
        val = self.db_manager.get_setting(SETTING_ENABLED, "false")
        return str(val).strip().lower() in ("true", "1", "yes")

    def get_status(self) -> dict[str, Any]:
        """Return current configuration and status."""
        enabled = self.is_enabled()
        if not enabled:
            return {
                "enabled": False,
                "status": "DISABLED",
                "issuer": None,
                "account_id": None,
                "message": "Account discovery is disabled. Zero external network calls are performed.",
            }

        issuer = self.db_manager.get_setting(SETTING_ISSUER)
        account_id = self.db_manager.get_setting(SETTING_ACCOUNT_ID)
        return {
            "enabled": True,
            "status": "CONFIGURED" if (issuer and account_id) else "ENABLED_UNCONFIGURED",
            "issuer": issuer,
            "account_id": account_id,
            "message": "Account discovery active for cross-subnet rendezvous. Device pairing and mTLS remain strictly enforced.",
        }

    def set_enabled(self, enabled: bool) -> None:
        """Toggle account discovery on or off."""
        self.db_manager.set_setting(SETTING_ENABLED, "true" if enabled else "false")
        if not enabled:
            logger.info("Account discovery disabled. All cloud/OIDC lookups halted.")
        else:
            logger.info("Account discovery enabled by user.")

    def configure(
        self,
        issuer: str,
        audience: str,
        account_id: Optional[str] = None,
    ) -> None:
        """Update discovery provider parameters."""
        self.db_manager.set_setting(SETTING_ISSUER, issuer.strip())
        self.db_manager.set_setting(SETTING_AUDIENCE, audience.strip())
        if account_id:
            self.db_manager.set_setting(SETTING_ACCOUNT_ID, account_id.strip())

    def verify_oidc_token(
        self,
        token: str,
        expected_issuer: Optional[str] = None,
        expected_audience: Optional[str] = None,
        public_key_pem: Optional[str] = None,
        current_time: Optional[float] = None,
        clock_skew: float = 60.0,
    ) -> tuple[bool, Optional[dict[str, Any]], Optional[str]]:
        """Validate an OIDC ID token following the OIDC Core specification.

        Verifies:
        1. Token structure (header, payload, signature).
        2. Non-none algorithm (RS256, ES256).
        3. Expiration (exp) and Not-Before (nbf) timestamps with clock skew.
        4. Issuer matching (iss).
        5. Audience matching (aud).
        6. Cryptographic signature (if public key provided).

        Returns:
            (valid, claims_dict, error_message)
        """
        if not token or not isinstance(token, str):
            return False, None, "Token must be a non-empty string"

        parts = token.strip().split(".")
        if len(parts) != 3:
            return False, None, "Invalid JWT format: expected exactly 3 dot-separated segments"

        header_b64, payload_b64, sig_b64 = parts

        try:
            header_json = _b64url_decode(header_b64).decode("utf-8")
            header = json.loads(header_json)
        except Exception as exc:
            return False, None, f"Malformed JWT header: {exc}"

        try:
            payload_json = _b64url_decode(payload_b64).decode("utf-8")
            payload = json.loads(payload_json)
        except Exception as exc:
            return False, None, f"Malformed JWT payload: {exc}"

        alg = header.get("alg")
        if not alg or alg.lower() == "none":
            return False, None, "Algorithm 'none' is strictly rejected"

        if alg not in ("RS256", "ES256"):
            return False, None, f"Unsupported signing algorithm: '{alg}' (only RS256 and ES256 permitted)"

        now = time.time() if current_time is None else current_time

        # 1. Expiration check
        exp = payload.get("exp")
        if exp is None or not isinstance(exp, (int, float)):
            return False, None, "Missing or invalid 'exp' claim in token"
        if now > (exp + clock_skew):
            return False, None, f"Token has expired (exp={exp}, now={now})"

        # 2. Not-Before check
        nbf = payload.get("nbf")
        if nbf is not None and isinstance(nbf, (int, float)):
            if now < (nbf - clock_skew):
                return False, None, f"Token not yet valid (nbf={nbf}, now={now})"

        # 3. Issuer check
        if expected_issuer:
            iss = payload.get("iss")
            if iss != expected_issuer:
                return False, None, f"Issuer mismatch: expected '{expected_issuer}', got '{iss}'"

        # 4. Audience check
        if expected_audience:
            aud = payload.get("aud")
            aud_list = [aud] if isinstance(aud, str) else (aud if isinstance(aud, list) else [])
            if expected_audience not in aud_list:
                return False, None, f"Audience mismatch: expected '{expected_audience}', got '{aud}'"

        # 5. Subject check
        sub = payload.get("sub")
        if not sub or not isinstance(sub, str):
            return False, None, "Missing or invalid 'sub' claim in token"

        # 6. Public key enforcement - MUST FAIL CLOSED if missing
        if not public_key_pem or not str(public_key_pem).strip():
            return False, None, "Missing public key for cryptographic signature verification"

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        try:
            sig_bytes = _b64url_decode(sig_b64)
            pub_key = load_pem_public_key(public_key_pem.encode("utf-8"))

            if alg == "RS256":
                pub_key.verify(
                    sig_bytes,
                    signing_input,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            elif alg == "ES256":
                # JWT ES256 signatures are 64-byte IEEE P1363 (r || s), convert to ASN.1 DER for cryptography
                if len(sig_bytes) == 64:
                    r = int.from_bytes(sig_bytes[:32], "big")
                    s = int.from_bytes(sig_bytes[32:], "big")
                    try:
                        der_sig = encode_dss_signature(r, s)
                    except Exception as ex:
                        return False, None, f"Invalid ECDSA P1363 coordinates: {ex}"
                elif sig_bytes.startswith(b"\x30"):
                    # Already ASN.1 DER encoded
                    der_sig = sig_bytes
                else:
                    return False, None, f"Invalid ES256 signature length ({len(sig_bytes)} bytes, expected 64-byte P1363)"

                pub_key.verify(
                    der_sig,
                    signing_input,
                    ec.ECDSA(hashes.SHA256()),
                )
        except InvalidSignature:
            return False, None, "Cryptographic signature verification failed"
        except Exception as exc:
            return False, None, f"Signature verification error: {exc}"

        return True, payload, None
