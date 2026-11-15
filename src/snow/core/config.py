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
   shutdown_timeout=5.0) are preserved.
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

    This configuration is centralized and decoupled from core execution logic.
    Note: Defining bind_host and port here configures future network listeners;
    it does not open any network sockets in Milestone 1.1.
    """

    app_name: str = "SNOW Desktop Core"
    version: str = "0.1.0"
    bind_host: str = "0.0.0.0"
    port: int = 8765
    log_level: str = "INFO"
    shutdown_timeout: float = 5.0

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

        return cls(
            app_name=app_name,
            version="0.1.0",
            bind_host=bind_host,
            port=port,
            log_level=log_level,
            shutdown_timeout=timeout,
        )
