"""Device identity management and persistence for SNOW Desktop Core."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import base64
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import secrets
import socket
import threading
from typing import Any, Dict, Optional, Tuple, Union
import uuid

from snow.relay.auth import (
    NETWORK_ID_REGEX,
    SNOW_ID_REGEX,
    canonical_hub_challenge_message,
    decode_ed25519_pubkey,
    derive_network_id_from_pubkey,
    encode_ed25519_pubkey,
    is_valid_network_id,
    is_valid_snow_id,
    verify_ed25519_signature,
)


def _get_ed25519_signing_types():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    return Ed25519PrivateKey, Encoding, NoEncryption, PrivateFormat, PublicFormat

logger = logging.getLogger(__name__)


class NetworkIdentityError(ValueError):
    """Raised when persistent Ed25519 network identity key material is corrupted or invalid."""


_NETWORK_KEY_LOCKS: Dict[str, threading.Lock] = {}
_NETWORK_KEY_LOCKS_GUARD = threading.Lock()


def _get_key_path_lock(path: Path) -> threading.Lock:
    key = str(path.resolve())
    with _NETWORK_KEY_LOCKS_GUARD:
        lock = _NETWORK_KEY_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _NETWORK_KEY_LOCKS[key] = lock
        return lock


def is_valid_uuidv4(val: Any) -> bool:
    """Validate whether a value is a valid RFC 4122 UUID version 4 string."""
    if not isinstance(val, str) or not val.strip():
        return False
    try:
        parsed = uuid.UUID(val.strip())
        return parsed.version == 4
    except (ValueError, TypeError, AttributeError):
        return False


def is_valid_snow_id(val: Any) -> bool:
    """Validate whether a value conforms to the canonical SNOW ID format (^SNW-[A-Z0-9]{4}-[A-Z0-9]{4}$)."""
    if not isinstance(val, str) or not val.strip():
        return False
    return bool(SNOW_ID_REGEX.match(val.strip().upper()))


def generate_snow_id(seed: Optional[str] = None) -> str:
    """Generate a canonical human-readable SNOW identifier in SNW-XXXX-XXXX format.

    If seed is provided, generates deterministically using SHA-256 digest.
    Otherwise, generates cryptographically random uppercase alphanumeric characters.
    """
    if seed:
        digest = hashlib.sha256(str(seed).encode("utf-8")).hexdigest().upper()
        p1 = digest[:4]
        p2 = digest[4:8]
        return f"SNW-{p1}-{p2}"
    else:
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        p1 = "".join(secrets.choice(alphabet) for _ in range(4))
        p2 = "".join(secrets.choice(alphabet) for _ in range(4))
        return f"SNW-{p1}-{p2}"


def get_default_device_name() -> str:
    """Generate a friendly default device name for the desktop host."""
    try:
        hostname = socket.gethostname()
        return f"SNOW Desktop ({hostname})"
    except Exception:
        return "SNOW Desktop Core"


@dataclass(frozen=True)
class DeviceIdentity:
    """Immutable representation of a persistent local device identity."""

    device_id: str
    device_name: str
    created_at: str
    snow_id: str = ""

    def __post_init__(self) -> None:
        """Validate device identity invariants."""
        if not is_valid_uuidv4(self.device_id):
            raise ValueError(f"Invalid device_id: must be a valid UUIDv4 string, got {self.device_id!r}")
        if not isinstance(self.device_name, str) or not self.device_name.strip():
            raise ValueError(f"Invalid device_name: must be a non-empty string, got {self.device_name!r}")
        if not isinstance(self.created_at, str) or not self.created_at.strip():
            raise ValueError(f"Invalid created_at: must be a non-empty string, got {self.created_at!r}")
        if not self.snow_id:
            object.__setattr__(self, "snow_id", generate_snow_id(seed=self.device_id))
        elif not is_valid_snow_id(self.snow_id):
            raise ValueError(f"Invalid snow_id: must match ^SNW-[A-Z0-9]{{4}}-[A-Z0-9]{{4}}$, got {self.snow_id!r}")

    def to_dict(self) -> Dict[str, str]:
        """Convert the identity to a dictionary representation."""
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "created_at": self.created_at,
            "snow_id": self.snow_id,
        }

    def to_json(self) -> str:
        """Serialize the identity to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=2)


def get_default_data_dir() -> Path:
    """Resolve the default persistent application data directory for SNOW.

    Checks SNOW_DATA_DIR environment variable first; defaults to ~/.snow.
    """
    env_dir = os.getenv("SNOW_DATA_DIR")
    if env_dir and env_dir.strip():
        return Path(env_dir.strip())
    return Path.home() / ".snow"


def load_or_create_device_identity(
    data_dir: Optional[Union[str, Path]] = None,
    file_name: str = "device_identity.json",
    device_name: Optional[str] = None,
) -> DeviceIdentity:
    """Load an existing persistent DeviceIdentity, or generate and store a new one.

    If the identity file exists but is corrupted, missing required fields, or contains
    an invalid UUIDv4, a warning is logged to sys.stderr, a fresh identity is generated,
    and the file is safely overwritten.

    Args:
        data_dir: Directory containing identity file (defaults to SNOW_DATA_DIR or ~/.snow).
        file_name: Name of the identity JSON file.
        device_name: Optional override for device name when generating a new identity.

    Returns:
        A validated, immutable DeviceIdentity with persistent SNOW ID.
    """
    target_dir = Path(data_dir) if data_dir is not None else get_default_data_dir()
    identity_path = target_dir / file_name

    if identity_path.is_file():
        try:
            with open(identity_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)

            if isinstance(raw_data, dict):
                dev_id = raw_data.get("device_id")
                dev_name = raw_data.get("device_name") or (device_name or get_default_device_name())
                created = raw_data.get("created_at") or datetime.now(timezone.utc).isoformat()
                snow_id = raw_data.get("snow_id") or ""

                if is_valid_uuidv4(dev_id):
                    if not is_valid_snow_id(snow_id):
                        snow_id = generate_snow_id(seed=str(dev_id))
                    identity = DeviceIdentity(
                        device_id=str(dev_id),
                        device_name=str(dev_name),
                        created_at=str(created),
                        snow_id=str(snow_id),
                    )
                    # Persist snow_id if previously absent in file
                    if "snow_id" not in raw_data:
                        try:
                            temp_path = target_dir / f".{file_name}.tmp_{uuid.uuid4().hex[:8]}"
                            with open(temp_path, "w", encoding="utf-8") as f:
                                f.write(identity.to_json() + "\n")
                            temp_path.replace(identity_path)
                        except Exception:
                            pass
                    logger.debug("Loaded existing device identity [%s] (SNOW ID: %s) from %s", dev_id, identity.snow_id, identity_path)
                    return identity

            logger.warning(
                "Identity file '%s' contained invalid or non-UUIDv4 data. Regenerating identity.",
                identity_path,
            )
        except Exception as exc:
            logger.warning(
                "Failed to parse identity file '%s' (%s). Regenerating fresh identity.",
                identity_path,
                exc,
            )

    # Generate a new persistent UUIDv4 identity
    new_id = str(uuid.uuid4())
    name = device_name or get_default_device_name()
    created_at = datetime.now(timezone.utc).isoformat()
    new_snow_id = generate_snow_id(seed=new_id)
    identity = DeviceIdentity(
        device_id=new_id,
        device_name=name,
        created_at=created_at,
        snow_id=new_snow_id,
    )

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        # Atomic file write via temporary file
        temp_path = target_dir / f".{file_name}.tmp_{uuid.uuid4().hex[:8]}"
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(identity.to_json() + "\n")
        temp_path.replace(identity_path)
        logger.info("Generated new device identity [%s] and saved to %s", new_id, identity_path)
    except Exception as exc:
        logger.error("Failed to persist device identity to '%s': %s", identity_path, exc)

    return identity


@dataclass(frozen=True)
class NetworkKeyIdentity:
    """Persistent Ed25519 cryptographic identity for a SNOW network host.

    Canonical public key serialization:
    - 32 raw Ed25519 public key bytes encoded in unpadded URL-safe Base64 (`public_key_b64`).
    - `network_id` = `SNW-NET-<sha256(raw_32_byte_pubkey)[:8]>` (uppercase hex).
    """

    network_id: str
    public_key_b64: str
    created_at: str
    _private_key_bytes: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not is_valid_network_id(self.network_id):
            raise NetworkIdentityError(f"Invalid network_id format: {self.network_id!r}")
        raw_pub = decode_ed25519_pubkey(self.public_key_b64)
        derived_id = derive_network_id_from_pubkey(raw_pub)
        if derived_id != self.network_id:
            raise NetworkIdentityError(
                f"Network ID '{self.network_id}' does not match Ed25519 public key digest '{derived_id}'."
            )
        if not isinstance(self._private_key_bytes, bytes) or len(self._private_key_bytes) != 32:
            raise NetworkIdentityError("Ed25519 private key must be exactly 32 raw bytes.")
        Ed25519PrivateKey, Encoding, _, _, PublicFormat = _get_ed25519_signing_types()
        priv_obj = Ed25519PrivateKey.from_private_bytes(self._private_key_bytes)
        derived_pub = priv_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if derived_pub != raw_pub:
            raise NetworkIdentityError("Ed25519 private key does not match public key.")

    def to_public_dict(self) -> Dict[str, str]:
        """Serialize ONLY public network metadata (never includes private key bytes)."""
        return {
            "network_id": self.network_id,
            "public_key_b64": self.public_key_b64,
            "created_at": self.created_at,
        }

    def to_dict(self) -> Dict[str, str]:
        """Default public-safe dictionary (never leaks private key)."""
        return self.to_public_dict()

    def sign_message(self, message: bytes) -> str:
        """Sign raw message bytes using Ed25519 private key; return unpadded URL-safe Base64 signature."""
        if not isinstance(message, (bytes, bytearray)):
            raise ValueError("Message to sign must be bytes.")
        Ed25519PrivateKey, _, _, _, _ = _get_ed25519_signing_types()
        priv_obj = Ed25519PrivateKey.from_private_bytes(self._private_key_bytes)
        sig = priv_obj.sign(bytes(message))
        return base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")

    def sign_hub_challenge(self, challenge: Dict[str, Any], device_id: str = "") -> str:
        """Sign a hub challenge response payload deterministically."""
        msg = canonical_hub_challenge_message(
            challenge_id=str(challenge.get("challenge_id") or ""),
            network_id=str(challenge.get("network_id") or self.network_id),
            nonce=str(challenge.get("nonce") or ""),
            expires_at=int(challenge.get("expires_at") or 0),
            device_id=device_id,
        )
        return self.sign_message(msg)


def _apply_restrictive_permissions(path: Path) -> None:
    """Apply owner-only file permissions where supported."""
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _parse_network_key_file(key_path: Path) -> NetworkKeyIdentity:
    """Read and strictly validate persisted Ed25519 key JSON; raise NetworkIdentityError if invalid."""
    try:
        raw_text = key_path.read_text(encoding="utf-8")
        raw = json.loads(raw_text)
    except Exception as exc:
        raise NetworkIdentityError(
            f"Corrupted Ed25519 network key file '{key_path}': {exc}. "
            "Use explicit recovery rather than silent regeneration to avoid orphaning your network."
        ) from exc

    if not isinstance(raw, dict):
        raise NetworkIdentityError(f"Network key file '{key_path}' must contain a JSON object.")

    if raw.get("version") != 1 or raw.get("algorithm") != "Ed25519":
        raise NetworkIdentityError(
            f"Network key file '{key_path}' has unsupported version or algorithm."
        )

    priv_b64 = raw.get("private_key_b64")
    pub_b64 = raw.get("public_key_b64")
    net_id = str(raw.get("network_id") or "").strip().upper()
    created_at = str(raw.get("created_at") or "").strip()

    if not isinstance(priv_b64, str) or not priv_b64.strip() or not isinstance(pub_b64, str) or not pub_b64.strip():
        raise NetworkIdentityError(f"Network key file '{key_path}' missing key material.")
    if not created_at:
        raise NetworkIdentityError(f"Network key file '{key_path}' missing created_at timestamp.")

    clean_priv = priv_b64.strip()
    padding = "=" * ((4 - len(clean_priv) % 4) % 4)
    try:
        priv_bytes = base64.urlsafe_b64decode(clean_priv + padding)
    except Exception as exc:
        raise NetworkIdentityError(f"Invalid Base64 private key in '{key_path}': {exc}") from exc

    if len(priv_bytes) != 32:
        raise NetworkIdentityError(f"Private key in '{key_path}' must decode to 32 bytes, got {len(priv_bytes)}.")

    _apply_restrictive_permissions(key_path)
    return NetworkKeyIdentity(
        network_id=net_id,
        public_key_b64=pub_b64.strip(),
        created_at=created_at,
        _private_key_bytes=priv_bytes,
    )


def load_or_create_network_key_identity(
    data_dir: Optional[Union[str, Path]] = None,
    file_name: str = "network_key.json",
) -> NetworkKeyIdentity:
    """Load persistent Ed25519 network identity or atomically generate a new one.

    Fail-closed on corruption: if `network_key.json` exists but is malformed or invalid,
    raises `NetworkIdentityError` instead of silently regenerating (which would orphan
    an existing network and public MCP URL).
    """
    target_dir = Path(data_dir) if data_dir is not None else get_default_data_dir()
    key_path = target_dir / file_name
    path_lock = _get_key_path_lock(key_path)

    with path_lock:
        if key_path.exists():
            if not key_path.is_file():
                raise NetworkIdentityError(f"Network key path '{key_path}' exists and is not a regular file.")
            return _parse_network_key_file(key_path)

        target_dir.mkdir(parents=True, exist_ok=True)
        Ed25519PrivateKey, Encoding, NoEncryption, PrivateFormat, PublicFormat = _get_ed25519_signing_types()
        priv_obj = Ed25519PrivateKey.generate()
        priv_bytes = priv_obj.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = priv_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        priv_b64 = base64.urlsafe_b64encode(priv_bytes).decode("ascii").rstrip("=")
        pub_b64 = encode_ed25519_pubkey(pub_bytes)
        net_id = derive_network_id_from_pubkey(pub_bytes)
        created_at = datetime.now(timezone.utc).isoformat()

        doc = {
            "version": 1,
            "algorithm": "Ed25519",
            "network_id": net_id,
            "public_key_b64": pub_b64,
            "private_key_b64": priv_b64,
            "created_at": created_at,
        }

        temp_path = target_dir / f".{file_name}.tmp_{uuid.uuid4().hex}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(str(temp_path), flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            _apply_restrictive_permissions(temp_path)
            # Atomic non-overwriting publish to prevent cross-process race clobbering
            try:
                os.link(str(temp_path), str(key_path))
                temp_path.unlink(missing_ok=True)
            except FileExistsError:
                temp_path.unlink(missing_ok=True)
                return _parse_network_key_file(key_path)
            except OSError:
                # Fallback if hardlink unsupported on filesystem
                if key_path.exists():
                    temp_path.unlink(missing_ok=True)
                    return _parse_network_key_file(key_path)
                temp_path.replace(key_path)
            _apply_restrictive_permissions(key_path)
        except Exception:
            temp_path.unlink(missing_ok=True)
            if key_path.exists():
                return _parse_network_key_file(key_path)
            raise

        logger.info("Generated persistent Ed25519 network identity [%s] at %s", net_id, key_path)
        return NetworkKeyIdentity(
            network_id=net_id,
            public_key_b64=pub_b64,
            created_at=created_at,
            _private_key_bytes=priv_bytes,
        )


def recover_network_identity(
    data_dir: Optional[Union[str, Path]] = None,
    file_name: str = "network_key.json",
) -> Tuple[NetworkKeyIdentity, Optional[Path]]:
    """Explicit recovery path: archive any corrupted key file and generate a fresh Ed25519 identity."""
    target_dir = Path(data_dir) if data_dir is not None else get_default_data_dir()
    key_path = target_dir / file_name
    path_lock = _get_key_path_lock(key_path)
    backup_path: Optional[Path] = None

    with path_lock:
        if key_path.exists():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup_path = target_dir / f"{file_name}.corrupted.{stamp}"
            key_path.replace(backup_path)
            _apply_restrictive_permissions(backup_path)
            logger.warning("Archived corrupted network key '%s' to '%s' for recovery.", key_path, backup_path)

    ident = load_or_create_network_key_identity(data_dir=target_dir, file_name=file_name)
    return ident, backup_path
