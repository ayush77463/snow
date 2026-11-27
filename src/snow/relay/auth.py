"""Authentication and cryptographic ticket validation for the SNOW Relay."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any, Optional, Tuple


SNOW_ID_REGEX = re.compile(r"^SNW-[A-Z0-9]{4}-[A-Z0-9]{4}$")
NETWORK_ID_REGEX = re.compile(r"^SNW-NET-[A-F0-9]{8}$")


def generate_canonical_network_id() -> str:
    """Generate a new canonical network identifier in ^SNW-NET-[A-F0-9]{8}$ format."""
    return f"SNW-NET-{secrets.token_hex(4).upper()}"


def _get_ed25519_types():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return Ed25519PublicKey, Encoding, PublicFormat


def is_valid_snow_id(val: Any) -> bool:
    """Validate whether a value conforms to the canonical SNOW ID format (^SNW-[A-Z0-9]{4}-[A-Z0-9]{4}$)."""
    if not isinstance(val, str) or not val.strip():
        return False
    return bool(SNOW_ID_REGEX.match(val.strip().upper()))


def is_valid_network_id(val: Any) -> bool:
    """Validate canonical permanent network ID format (^SNW-NET-[A-F0-9]{8}$)."""
    if not isinstance(val, str) or not val.strip():
        return False
    return bool(NETWORK_ID_REGEX.match(val.strip().upper()))


def encode_ed25519_pubkey(raw_bytes: bytes) -> str:
    """Encode raw 32-byte Ed25519 public key into canonical unpadded URL-safe Base64."""
    if not isinstance(raw_bytes, (bytes, bytearray)) or len(raw_bytes) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 raw bytes.")
    raw = bytes(raw_bytes)
    Ed25519PublicKey, _, _ = _get_ed25519_types()
    Ed25519PublicKey.from_public_bytes(raw)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_ed25519_pubkey(pubkey: str | bytes) -> bytes:
    """Decode and validate an Ed25519 public key into canonical 32 raw bytes.

    Canonical wire format is unpadded URL-safe Base64 of the raw 32-byte key.
    """
    if isinstance(pubkey, (bytes, bytearray)):
        raw = bytes(pubkey)
    elif isinstance(pubkey, str):
        clean = pubkey.strip()
        if not clean or len(clean) > 64:
            raise ValueError("Malformed Ed25519 public key string.")
        padding = "=" * ((4 - len(clean) % 4) % 4)
        try:
            raw = base64.urlsafe_b64decode(clean + padding)
        except Exception as exc:
            raise ValueError(f"Invalid Base64 public key: {exc}") from exc
    else:
        raise ValueError("Public key must be bytes or URL-safe Base64 string.")

    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must decode to exactly 32 bytes, got {len(raw)}.")
    try:
        Ed25519PublicKey, Encoding, PublicFormat = _get_ed25519_types()
        key_obj = Ed25519PublicKey.from_public_bytes(raw)
        return key_obj.public_bytes(Encoding.Raw, PublicFormat.Raw)
    except Exception as exc:
        raise ValueError(f"Invalid Ed25519 public key bytes: {exc}") from exc


def derive_network_id_from_pubkey(pubkey: str | bytes) -> str:
    """Derive canonical permanent network ID: SNW-NET-<sha256(raw_pubkey)[:8]> (uppercase hex)."""
    raw = decode_ed25519_pubkey(pubkey)
    digest_prefix = hashlib.sha256(raw).hexdigest()[:8].upper()
    return f"SNW-NET-{digest_prefix}"


def derive_device_snow_id_from_pubkey(pubkey: str | bytes) -> str:
    """Derive canonical permanent per-device SNOW ID from a raw 32-byte Ed25519 public key.

    Formula: "SNW-" + SHA256(raw_32_byte_ed25519_public_key).hexdigest()[:8].upper()
    formatted canonically as SNW-XXXX-XXXX.

    Security Note: An 8-hex-character (32-bit) digest prefix provides a concise address,
    NOT full 256-bit collision resistance. Render Hub and peers MUST verify public key
    ownership and reject any conflicting registration for an existing snow_id.
    """
    raw = decode_ed25519_pubkey(pubkey)
    digest_prefix = hashlib.sha256(raw).hexdigest()[:8].upper()
    return f"SNW-{digest_prefix[:4]}-{digest_prefix[4:]}"


def canonical_hub_challenge_message(
    challenge_id: str,
    network_id: str,
    nonce: str,
    expires_at: int,
    device_id: str = "",
) -> bytes:
    """Canonical challenge payload signed by host Ed25519 key during hub authentication."""
    clean_cid = str(challenge_id or "").strip()
    clean_nid = str(network_id or "").strip().upper()
    clean_nonce = str(nonce or "").strip()
    clean_dev = str(device_id or "").strip()
    return f"snow-hub-v1|{clean_cid}|{clean_nid}|{clean_nonce}|{int(expires_at)}|{clean_dev}".encode("utf-8")


def canonical_device_hub_challenge_message(
    *,
    challenge_id: str,
    nonce: str,
    expires_at: int,
    snow_id: str,
    public_key_b64: str,
    device_id: str,
    network_id: str = "",
    audience: str = "render-hub-tunnel",
) -> bytes:
    """Canonical domain-separated challenge payload signed by a device's permanent Ed25519 key."""
    canonical_pub = encode_ed25519_pubkey(decode_ed25519_pubkey(public_key_b64))
    clean_snow_id = str(snow_id or "").strip().upper()
    fields = [
        "snow-device-hub-v1",
        str(challenge_id or "").strip(),
        str(nonce or "").strip(),
        str(int(expires_at)),
        clean_snow_id,
        canonical_pub,
        str(device_id or "").strip(),
        str(network_id or "").strip().upper(),
        str(audience or "render-hub-tunnel").strip(),
    ]
    for f in fields:
        if "|" in f or "\n" in f or "\r" in f or "\x00" in f:
            raise ValueError("Challenge message field contains prohibited control or delimiter characters.")
    return "|".join(fields).encode("utf-8")


def verify_ed25519_signature(pubkey: str | bytes, message: bytes, signature_b64: str) -> bool:
    """Verify an Ed25519 signature encoded as unpadded URL-safe Base64 over message bytes."""
    if not isinstance(signature_b64, str) or not signature_b64.strip() or not isinstance(message, (bytes, bytearray)):
        return False
    clean_sig = signature_b64.strip()
    if len(clean_sig) > 128:
        return False
    padding = "=" * ((4 - len(clean_sig) % 4) % 4)
    try:
        sig_bytes = base64.urlsafe_b64decode(clean_sig + padding)
        if len(sig_bytes) != 64:
            return False
        raw_pub = decode_ed25519_pubkey(pubkey)
        Ed25519PublicKey, _, _ = _get_ed25519_types()
        pub_obj = Ed25519PublicKey.from_public_bytes(raw_pub)
        pub_obj.verify(sig_bytes, bytes(message))
        return True
    except Exception:
        return False


def create_relay_ticket(
    device_id: str,
    group_id: str,
    secret: str,
    ttl_seconds: int = 3600,
    snow_id: Optional[str] = None,
) -> str:
    """Generate a signed, short-lived authentication ticket for relay session registration.

    Ticket format: base64(payload_json).base64(hmac_sha256)
    """
    if not isinstance(secret, str) or not secret.strip():
        raise ValueError("Relay shared secret must be non-empty to sign a relay ticket.")
    if not str(device_id or "").strip() or not str(group_id or "").strip():
        raise ValueError("device_id and group_id are required to sign a relay ticket.")
    now = int(time.time())
    payload = {
        "device_id": device_id,
        "group_id": group_id,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    if snow_id:
        payload["snow_id"] = str(snow_id).strip().upper()
    payload_raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_raw).decode("ascii").rstrip("=")

    signature = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")

    return f"{payload_b64}.{sig_b64}"


def extract_ticket_claims(
    ticket: str,
    secret: str,
) -> Tuple[bool, dict, Optional[str]]:
    """Validate and decode all signed claims inside a relay ticket."""
    if not secret or not ticket or "." not in ticket:
        return False, {}, "Invalid ticket or relay secret not configured."

    parts = ticket.strip().split(".")
    if len(parts) != 2:
        return False, {}, "Invalid ticket component count."

    payload_b64, sig_b64 = parts[0], parts[1]
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode("ascii").rstrip("=")

    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        return False, {}, "Invalid cryptographic signature."

    try:
        padding = "=" * ((4 - len(payload_b64) % 4) % 4)
        raw_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        return False, {}, f"Failed decoding ticket payload: {exc}"

    now = time.time()
    exp = payload.get("exp", 0)
    if now > exp:
        return False, {}, f"Ticket expired {int(now - exp)}s ago."

    device_id = payload.get("device_id")
    group_id = payload.get("group_id")
    if not device_id or not group_id:
        return False, {}, "Ticket missing required device_id or group_id."

    return True, payload, None


def verify_relay_ticket(
    ticket: str,
    secret: str,
) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """Validate a relay session authentication ticket.

    Returns:
        (is_valid, device_id, group_id, error_message)
    """
    if not isinstance(secret, str) or not secret.strip():
        return False, None, None, "Relay secret not configured."
    if not ticket or "." not in ticket:
        return False, None, None, "Malformed ticket format."

    parts = ticket.strip().split(".")
    if len(parts) != 2:
        return False, None, None, "Invalid ticket component count."

    payload_b64, sig_b64 = parts[0], parts[1]

    # Recompute expected signature
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode("ascii").rstrip("=")

    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        return False, None, None, "Invalid cryptographic signature."

    # Decode payload
    try:
        padding = "=" * ((4 - len(payload_b64) % 4) % 4)
        raw_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        return False, None, None, f"Failed decoding ticket payload: {e}"

    now = time.time()
    exp = payload.get("exp", 0)
    if now > exp:
        return False, None, None, f"Ticket expired {int(now - exp)}s ago."

    device_id = payload.get("device_id")
    group_id = payload.get("group_id")
    if not device_id or not group_id:
        return False, None, None, "Ticket missing required device_id or group_id."

    return True, device_id, group_id, None
