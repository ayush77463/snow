"""Authentication and cryptographic ticket validation for the SNOW Relay."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Optional, Tuple


def create_relay_ticket(
    device_id: str,
    group_id: str,
    secret: str,
    ttl_seconds: int = 3600,
) -> str:
    """Generate a signed, short-lived authentication ticket for relay session registration.

    Ticket format: base64(payload_json).base64(hmac_sha256)
    """
    now = int(time.time())
    payload = {
        "device_id": device_id,
        "group_id": group_id,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    payload_raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_raw).decode("ascii").rstrip("=")

    signature = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")

    return f"{payload_b64}.{sig_b64}"


def verify_relay_ticket(
    ticket: str,
    secret: str,
) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """Validate a relay session authentication ticket.

    Returns:
        (is_valid, device_id, group_id, error_message)
    """
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
