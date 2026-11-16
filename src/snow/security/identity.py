"""Device identity management and persistence for SNOW Desktop Core."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import socket
from typing import Any, Dict, Optional, Union
import uuid

logger = logging.getLogger(__name__)


def is_valid_uuidv4(val: Any) -> bool:
    """Validate whether a value is a valid RFC 4122 UUID version 4 string."""
    if not isinstance(val, str) or not val.strip():
        return False
    try:
        parsed = uuid.UUID(val.strip())
        return parsed.version == 4
    except (ValueError, TypeError, AttributeError):
        return False


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

    def __post_init__(self) -> None:
        """Validate device identity invariants."""
        if not is_valid_uuidv4(self.device_id):
            raise ValueError(f"Invalid device_id: must be a valid UUIDv4 string, got {self.device_id!r}")
        if not isinstance(self.device_name, str) or not self.device_name.strip():
            raise ValueError(f"Invalid device_name: must be a non-empty string, got {self.device_name!r}")
        if not isinstance(self.created_at, str) or not self.created_at.strip():
            raise ValueError(f"Invalid created_at: must be a non-empty string, got {self.created_at!r}")

    def to_dict(self) -> Dict[str, str]:
        """Convert the identity to a dictionary representation."""
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "created_at": self.created_at,
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
        A validated, immutable DeviceIdentity.
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

                if is_valid_uuidv4(dev_id):
                    logger.debug("Loaded existing device identity [%s] from %s", dev_id, identity_path)
                    return DeviceIdentity(
                        device_id=str(dev_id),
                        device_name=str(dev_name),
                        created_at=str(created),
                    )

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
    identity = DeviceIdentity(device_id=new_id, device_name=name, created_at=created_at)

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
