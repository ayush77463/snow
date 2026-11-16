"""Centralized configuration for SNOW Desktop Core.

Configuration Error-Handling Policy:
-------------------------------------
1. Strict Validation: Configuration values provided via environment variables
   are strictly validated to prevent invalid, out-of-range, or corrupted settings
   from silently degrading system behavior.
2. No Silent Fallbacks for Invalid Inputs: If an environment variable is explicitly
   set but contains an invalid value (e.g. non-integer port, out-of-range port,
   non-positive timeout, empty bind host, or unrecognized log level), a descriptive
   ValueError is raised immediately at startup so the user can correct it.
3. Preserved Documented Defaults: When an environment variable is absent or unset,
   the frozen architectural defaults (bind_host='0.0.0.0', port=8765, log_level='INFO',
   shutdown_timeout=5.0, max_message_size=65536, heartbeat_timeout=45.0,
   heartbeat_interval=15.0) are preserved.
"""

from dataclasses import dataclass
import math
import os
from typing import FrozenSet

VALID_LOG_LEVELS: FrozenSet[str] = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)


@dataclass(frozen=True)
class CoreConfig:
    """Core configuration parameters for SNOW.

    Centralized and decoupled from protocol and networking logic.
    """

    app_name: str = "SNOW Desktop Core"
    version: str = "0.1.0"
    bind_host: str = "0.0.0.0"
    port: int = 8765
    log_level: str = "INFO"
    shutdown_timeout: float = 5.0
    max_message_size: int = 65536
    heartbeat_timeout: float = 45.0
    heartbeat_interval: float = 15.0
    tls_enabled: bool = True
    auth_timeout: float = 30.0
    auth_required: bool = True
    transfer_port: int = 8766
    transfer_root: str | None = None
    tls_cert_path: str | None = None
    tls_key_path: str | None = None
    ipc_host: str = "127.0.0.1"
    ipc_port: int = 8767
    ipc_secret_path: str | None = None

    def __post_init__(self) -> None:
        """Validate configuration invariants upon instantiation."""
        # Validate port range (1 - 65535)
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise ValueError(f"Port must be an integer, got {type(self.port).__name__}: {self.port!r}")
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Port must be in range 1-65535, got {self.port}")

        # Validate shutdown timeout (> 0.0, finite)
        if not isinstance(self.shutdown_timeout, (int, float)) or isinstance(self.shutdown_timeout, bool):
            raise ValueError(f"Shutdown timeout must be numeric, got {type(self.shutdown_timeout).__name__}")
        if not math.isfinite(self.shutdown_timeout) or self.shutdown_timeout <= 0:
            raise ValueError(f"Shutdown timeout must be a finite positive number (> 0), got {self.shutdown_timeout}")

        # Validate bind host (non-empty string)
        if not isinstance(self.bind_host, str) or not self.bind_host.strip():
            raise ValueError(f"Bind host must be a non-empty string, got {self.bind_host!r}")

        # Validate log level
        if not isinstance(self.log_level, str) or self.log_level.upper() not in VALID_LOG_LEVELS:
            raise ValueError(
                f"Log level must be one of {sorted(VALID_LOG_LEVELS)}, got {self.log_level!r}"
            )

        # Validate max message size (integer >= 1024 bytes)
        if not isinstance(self.max_message_size, int) or isinstance(self.max_message_size, bool):
            raise ValueError(f"Max message size must be an integer, got {type(self.max_message_size).__name__}")
        if self.max_message_size < 1024 or self.max_message_size > 10485760:
            raise ValueError(f"Max message size must be between 1024 and 10485760 bytes, got {self.max_message_size}")

        # Validate heartbeat timeout (> 0.0, finite)
        if not isinstance(self.heartbeat_timeout, (int, float)) or isinstance(self.heartbeat_timeout, bool):
            raise ValueError(f"Heartbeat timeout must be numeric, got {type(self.heartbeat_timeout).__name__}")
        if not math.isfinite(self.heartbeat_timeout) or self.heartbeat_timeout <= 0:
            raise ValueError(f"Heartbeat timeout must be a finite positive number (> 0), got {self.heartbeat_timeout}")

        # Validate heartbeat interval (> 0.0, finite)
        if not isinstance(self.heartbeat_interval, (int, float)) or isinstance(self.heartbeat_interval, bool):
            raise ValueError(f"Heartbeat interval must be numeric, got {type(self.heartbeat_interval).__name__}")
        if not math.isfinite(self.heartbeat_interval) or self.heartbeat_interval <= 0:
            raise ValueError(f"Heartbeat interval must be a finite positive number (> 0), got {self.heartbeat_interval}")

        # Validate tls_enabled (boolean)
        if not isinstance(self.tls_enabled, bool):
            raise ValueError(f"tls_enabled must be a boolean, got {type(self.tls_enabled).__name__}")

        # Validate auth timeout (> 0.0, finite)
        if not isinstance(self.auth_timeout, (int, float)) or isinstance(self.auth_timeout, bool):
            raise ValueError(f"auth_timeout must be numeric, got {type(self.auth_timeout).__name__}")
        if not math.isfinite(self.auth_timeout) or self.auth_timeout <= 0:
            raise ValueError(f"auth_timeout must be a finite positive number (> 0), got {self.auth_timeout}")

        # Validate auth_required (boolean)
        if not isinstance(self.auth_required, bool):
            raise ValueError(f"auth_required must be a boolean, got {type(self.auth_required).__name__}")

        # Validate transfer port range (0 - 65535, 0 permitted for ephemeral test ports)
        if not isinstance(self.transfer_port, int) or isinstance(self.transfer_port, bool):
            raise ValueError(
                f"transfer_port must be an integer, got {type(self.transfer_port).__name__}: {self.transfer_port!r}"
            )
        if not (0 <= self.transfer_port <= 65535):
            raise ValueError(f"transfer_port must be in range 0-65535, got {self.transfer_port}")

        # Validate transfer root path if provided
        if self.transfer_root is not None:
            if not isinstance(self.transfer_root, str) or not self.transfer_root.strip():
                raise ValueError("transfer_root must be a non-empty string or None")

        # Validate TLS cert/key paths if provided
        if self.tls_cert_path is not None:
            if not isinstance(self.tls_cert_path, str) or not self.tls_cert_path.strip():
                raise ValueError("tls_cert_path must be a non-empty string or None")
        if self.tls_key_path is not None:
            if not isinstance(self.tls_key_path, str) or not self.tls_key_path.strip():
                raise ValueError("tls_key_path must be a non-empty string or None")

        # Validate IPC host (must be loopback)
        if not isinstance(self.ipc_host, str) or not self.ipc_host.strip():
            raise ValueError("ipc_host must be a non-empty string")
        norm_ipc_host = self.ipc_host.strip().lower()
        if norm_ipc_host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError(f"ipc_host must be a loopback address ('127.0.0.1' or 'localhost'), got {self.ipc_host!r}")

        # Validate IPC port (0 permitted for ephemeral test ports)
        if not isinstance(self.ipc_port, int) or isinstance(self.ipc_port, bool):
            raise ValueError(f"ipc_port must be an integer, got {type(self.ipc_port).__name__}: {self.ipc_port!r}")
        if not (0 <= self.ipc_port <= 65535):
            raise ValueError(f"ipc_port must be in range 0-65535, got {self.ipc_port}")

        # Validate IPC secret path if provided
        if self.ipc_secret_path is not None:
            if not isinstance(self.ipc_secret_path, str) or not self.ipc_secret_path.strip():
                raise ValueError("ipc_secret_path must be a non-empty string or None")

    @classmethod
    def from_env(cls) -> "CoreConfig":
        """Load configuration from environment variables with strict validation.

        Raises:
            ValueError: If any provided environment variable contains an invalid,
                out-of-range, or malformed value.
        """
        app_name = os.getenv("SNOW_APP_NAME", "SNOW Desktop Core")

        # Parse and validate SNOW_BIND_HOST
        raw_bind = os.getenv("SNOW_BIND_HOST")
        if raw_bind is not None:
            if not raw_bind.strip():
                raise ValueError("Invalid SNOW_BIND_HOST: bind host cannot be empty or whitespace.")
            bind_host = raw_bind.strip()
        else:
            bind_host = "0.0.0.0"

        # Parse and validate SNOW_PORT
        raw_port = os.getenv("SNOW_PORT")
        if raw_port is not None:
            try:
                port = int(raw_port)
            except (ValueError, TypeError):
                raise ValueError(
                    f"Invalid SNOW_PORT '{raw_port}': port must be a valid integer between 1 and 65535."
                ) from None
            if not (1 <= port <= 65535):
                raise ValueError(
                    f"Invalid SNOW_PORT '{raw_port}': port must be between 1 and 65535, got {port}."
                )
        else:
            port = 8765

        # Parse and validate SNOW_LOG_LEVEL
        raw_log_level = os.getenv("SNOW_LOG_LEVEL")
        if raw_log_level is not None:
            log_level = raw_log_level.strip().upper()
            if log_level not in VALID_LOG_LEVELS:
                raise ValueError(
                    f"Invalid SNOW_LOG_LEVEL '{raw_log_level}': supported levels are {sorted(VALID_LOG_LEVELS)}."
                )
        else:
            log_level = "INFO"

        # Parse and validate SNOW_SHUTDOWN_TIMEOUT
        raw_timeout = os.getenv("SNOW_SHUTDOWN_TIMEOUT")
        if raw_timeout is not None:
            try:
                timeout = float(raw_timeout)
            except (ValueError, TypeError):
                raise ValueError(
                    f"Invalid SNOW_SHUTDOWN_TIMEOUT '{raw_timeout}': must be a finite positive number."
                ) from None
            if not math.isfinite(timeout) or timeout <= 0:
                raise ValueError(
                    f"Invalid SNOW_SHUTDOWN_TIMEOUT '{raw_timeout}': must be a finite positive number (> 0)."
                )
        else:
            timeout = 5.0

        # Parse and validate SNOW_MAX_MESSAGE_SIZE
        raw_max_size = os.getenv("SNOW_MAX_MESSAGE_SIZE")
        if raw_max_size is not None:
            try:
                max_message_size = int(raw_max_size)
            except (ValueError, TypeError):
                raise ValueError(
                    f"Invalid SNOW_MAX_MESSAGE_SIZE '{raw_max_size}': must be an integer."
                ) from None
            if max_message_size < 1024 or max_message_size > 10485760:
                raise ValueError(
                    f"Invalid SNOW_MAX_MESSAGE_SIZE '{raw_max_size}': must be between 1024 and 10485760 bytes."
                )
        else:
            max_message_size = 65536

        # Parse and validate SNOW_HEARTBEAT_TIMEOUT
        raw_hb_timeout = os.getenv("SNOW_HEARTBEAT_TIMEOUT")
        if raw_hb_timeout is not None:
            try:
                hb_timeout = float(raw_hb_timeout)
            except (ValueError, TypeError):
                raise ValueError(
                    f"Invalid SNOW_HEARTBEAT_TIMEOUT '{raw_hb_timeout}': must be a finite positive number."
                ) from None
            if not math.isfinite(hb_timeout) or hb_timeout <= 0:
                raise ValueError(
                    f"Invalid SNOW_HEARTBEAT_TIMEOUT '{raw_hb_timeout}': must be a finite positive number (> 0)."
                )
        else:
            heartbeat_timeout = 45.0

        # Parse and validate SNOW_HEARTBEAT_INTERVAL
        raw_hb_interval = os.getenv("SNOW_HEARTBEAT_INTERVAL")
        if raw_hb_interval is not None:
            try:
                hb_interval = float(raw_hb_interval)
            except (ValueError, TypeError):
                raise ValueError(
                    f"Invalid SNOW_HEARTBEAT_INTERVAL '{raw_hb_interval}': must be a finite positive number."
                ) from None
            if not math.isfinite(hb_interval) or hb_interval <= 0:
                raise ValueError(
                    f"Invalid SNOW_HEARTBEAT_INTERVAL '{raw_hb_interval}': must be a finite positive number (> 0)."
                )
        else:
            heartbeat_interval = 15.0

        # Parse and validate SNOW_TLS_ENABLED
        raw_tls = os.getenv("SNOW_TLS_ENABLED")
        if raw_tls is not None:
            norm_tls = raw_tls.strip().lower()
            if norm_tls in ("true", "1", "yes", "on"):
                tls_enabled = True
            elif norm_tls in ("false", "0", "no", "off"):
                tls_enabled = False
            else:
                raise ValueError(
                    f"Invalid SNOW_TLS_ENABLED '{raw_tls}': must be 'true' or 'false'."
                )
        else:
            tls_enabled = True

        # Parse and validate SNOW_AUTH_TIMEOUT
        raw_auth_timeout = os.getenv("SNOW_AUTH_TIMEOUT")
        if raw_auth_timeout is not None:
            try:
                auth_timeout = float(raw_auth_timeout)
            except (ValueError, TypeError):
                raise ValueError(
                    f"Invalid SNOW_AUTH_TIMEOUT '{raw_auth_timeout}': must be a finite positive number."
                ) from None
            if not math.isfinite(auth_timeout) or auth_timeout <= 0:
                raise ValueError(
                    f"Invalid SNOW_AUTH_TIMEOUT '{raw_auth_timeout}': must be a finite positive number (> 0)."
                )
        else:
            auth_timeout = 30.0

        # Parse and validate SNOW_AUTH_REQUIRED
        raw_auth_required = os.getenv("SNOW_AUTH_REQUIRED")
        if raw_auth_required is not None:
            norm_auth = raw_auth_required.strip().lower()
            if norm_auth in ("true", "1", "yes", "on"):
                auth_required = True
            elif norm_auth in ("false", "0", "no", "off"):
                auth_required = False
            else:
                raise ValueError(
                    f"Invalid SNOW_AUTH_REQUIRED '{raw_auth_required}': must be 'true' or 'false'."
                )
        else:
            auth_required = True

        # Parse and validate SNOW_TRANSFER_PORT
        raw_xfer_port = os.getenv("SNOW_TRANSFER_PORT")
        if raw_xfer_port is not None:
            try:
                transfer_port = int(raw_xfer_port)
            except (ValueError, TypeError):
                raise ValueError(
                    f"Invalid SNOW_TRANSFER_PORT '{raw_xfer_port}': must be an integer."
                ) from None
            if not (0 <= transfer_port <= 65535):
                raise ValueError(
                    f"Invalid SNOW_TRANSFER_PORT '{raw_xfer_port}': must be between 0 and 65535."
                )
        else:
            transfer_port = 8766

        # Parse SNOW_TRANSFER_ROOT
        raw_xfer_root = os.getenv("SNOW_TRANSFER_ROOT")
        transfer_root = raw_xfer_root.strip() if raw_xfer_root and raw_xfer_root.strip() else None

        # Parse SNOW_TLS_CERT_PATH and SNOW_TLS_KEY_PATH
        raw_cert_path = os.getenv("SNOW_TLS_CERT_PATH")
        tls_cert_path = raw_cert_path.strip() if raw_cert_path and raw_cert_path.strip() else None

        raw_key_path = os.getenv("SNOW_TLS_KEY_PATH")
        tls_key_path = raw_key_path.strip() if raw_key_path and raw_key_path.strip() else None

        # Parse SNOW_IPC_HOST
        raw_ipc_host = os.getenv("SNOW_IPC_HOST")
        ipc_host = raw_ipc_host.strip() if raw_ipc_host and raw_ipc_host.strip() else "127.0.0.1"

        # Parse SNOW_IPC_PORT
        raw_ipc_port = os.getenv("SNOW_IPC_PORT")
        if raw_ipc_port is not None:
            try:
                ipc_port = int(raw_ipc_port)
            except (ValueError, TypeError):
                raise ValueError(
                    f"Invalid SNOW_IPC_PORT '{raw_ipc_port}': must be an integer."
                ) from None
            if not (0 <= ipc_port <= 65535):
                raise ValueError(
                    f"Invalid SNOW_IPC_PORT '{raw_ipc_port}': must be between 0 and 65535."
                )
        else:
            ipc_port = 8767

        # Parse SNOW_IPC_SECRET_PATH
        raw_ipc_secret = os.getenv("SNOW_IPC_SECRET_PATH")
        ipc_secret_path = raw_ipc_secret.strip() if raw_ipc_secret and raw_ipc_secret.strip() else None

        return cls(
            app_name=app_name,
            version="0.1.0",
            bind_host=bind_host,
            port=port,
            log_level=log_level,
            shutdown_timeout=timeout,
            max_message_size=max_message_size,
            heartbeat_timeout=heartbeat_timeout,
            heartbeat_interval=heartbeat_interval,
            tls_enabled=tls_enabled,
            auth_timeout=auth_timeout,
            auth_required=auth_required,
            transfer_port=transfer_port,
            transfer_root=transfer_root,
            tls_cert_path=tls_cert_path,
            tls_key_path=tls_key_path,
            ipc_host=ipc_host,
            ipc_port=ipc_port,
            ipc_secret_path=ipc_secret_path,
        )
