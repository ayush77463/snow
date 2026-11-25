"""Configuration parameters for the SNOW Remote Relay Service."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Optional


@dataclass
class RelayConfig:
    """Configuration for the self-hosted SNOW relay server."""

    host: str = "0.0.0.0"
    port: int = 8770
    shared_secret: str = ""
    max_frame_size: int = 25 * 1024 * 1024  # 25 MiB maximum single frame
    max_transfer_quota_bytes: int = 100 * 1024 * 1024  # 100 MiB bounded rolling quota
    max_connections_per_group: int = 10
    rate_limit_messages_per_sec: int = 50
    presence_stale_seconds: float = 120.0
    dormant_timeout_seconds: float = 300.0
    tls_cert_path: Optional[str] = None
    tls_key_path: Optional[str] = None
    enabled: bool = False
    default_snow_id: Optional[str] = None
    max_http_forward_bytes: int = 2 * 1024 * 1024
    http_forward_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls) -> RelayConfig:
        """Load relay configuration from environment variables."""
        raw_default_snow = os.getenv("SNOW_RELAY_DEFAULT_SNOW_ID", "").strip().upper() or None
        raw_port = os.getenv("PORT") or os.getenv("SNOW_RELAY_PORT", "8770")
        return cls(
            host=os.getenv("SNOW_RELAY_HOST", "0.0.0.0"),
            port=int(raw_port),
            shared_secret=os.getenv("SNOW_RELAY_SECRET", ""),
            max_frame_size=int(os.getenv("SNOW_RELAY_MAX_FRAME_SIZE", str(25 * 1024 * 1024))),
            max_transfer_quota_bytes=int(os.getenv("SNOW_RELAY_MAX_QUOTA", str(100 * 1024 * 1024))),
            max_connections_per_group=int(os.getenv("SNOW_RELAY_MAX_CONNS_PER_GROUP", "10")),
            rate_limit_messages_per_sec=int(os.getenv("SNOW_RELAY_RATE_LIMIT", "50")),
            presence_stale_seconds=float(os.getenv("SNOW_RELAY_STALE_SEC", "120.0")),
            dormant_timeout_seconds=float(os.getenv("SNOW_RELAY_DORMANT_SEC", "300.0")),
            tls_cert_path=os.getenv("SNOW_RELAY_TLS_CERT"),
            tls_key_path=os.getenv("SNOW_RELAY_TLS_KEY"),
            enabled=os.getenv("SNOW_RELAY_ENABLED", "0").lower() in ("1", "true", "yes"),
            default_snow_id=raw_default_snow,
            max_http_forward_bytes=int(os.getenv("SNOW_RELAY_MAX_HTTP_FORWARD_BYTES", str(2 * 1024 * 1024))),
            http_forward_timeout_seconds=float(os.getenv("SNOW_RELAY_HTTP_FORWARD_TIMEOUT_SEC", "30.0")),
        )
