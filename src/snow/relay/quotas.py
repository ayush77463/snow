"""Rate limiting, transfer quotas, and bounded queue backpressure for the SNOW Relay."""

from __future__ import annotations

import collections
import time
from typing import Dict, Tuple


class QuotaManager:
    """Manages rate limits, transfer quotas, and buffer safety on the relay."""

    def __init__(
        self,
        max_frame_size: int = 25 * 1024 * 1024,
        max_transfer_quota_bytes: int = 100 * 1024 * 1024,
        rate_limit_messages_per_sec: int = 50,
        quota_window_seconds: float = 3600.0,
    ) -> None:
        self.max_frame_size = max_frame_size
        self.max_transfer_quota_bytes = max_transfer_quota_bytes
        self.rate_limit_messages_per_sec = rate_limit_messages_per_sec
        self.quota_window_seconds = quota_window_seconds

        # device_id -> deque of (timestamp, byte_count)
        self._transfers: Dict[str, collections.deque[Tuple[float, int]]] = collections.defaultdict(collections.deque)
        # device_id -> deque of timestamps
        self._message_timestamps: Dict[str, collections.deque[float]] = collections.defaultdict(collections.deque)

    def check_frame_size(self, size_bytes: int) -> Tuple[bool, str]:
        """Validate an incoming frame size against the configured maximum."""
        if size_bytes > self.max_frame_size:
            return (
                False,
                f"Frame size {size_bytes} exceeds maximum permitted limit {self.max_frame_size} bytes (25 MiB).",
            )
        return True, ""

    def check_rate_limit(self, device_id: str) -> Tuple[bool, str]:
        """Check if device is exceeding rate limits (messages per second)."""
        now = time.time()
        window_start = now - 1.0
        queue = self._message_timestamps[device_id]

        while queue and queue[0] < window_start:
            queue.popleft()

        if len(queue) >= self.rate_limit_messages_per_sec:
            return (
                False,
                f"Message rate limit exceeded ({self.rate_limit_messages_per_sec} msg/sec).",
            )

        queue.append(now)
        return True, ""

    def check_and_record_transfer(self, device_id: str, size_bytes: int) -> Tuple[bool, str]:
        """Check if device transfer is within rolling quota and record byte count."""
        now = time.time()
        window_start = now - self.quota_window_seconds
        queue = self._transfers[device_id]

        while queue and queue[0][0] < window_start:
            queue.popleft()

        current_total = sum(b for _, b in queue)
        if current_total + size_bytes > self.max_transfer_quota_bytes:
            return (
                False,
                f"Transfer quota exceeded: {current_total + size_bytes} > {self.max_transfer_quota_bytes} bytes in {int(self.quota_window_seconds)}s window.",
            )

        queue.append((now, size_bytes))
        return True, ""

    def clear_device(self, device_id: str) -> None:
        """Reset quota trackers for a disconnected or revoked device."""
        self._transfers.pop(device_id, None)
        self._message_timestamps.pop(device_id, None)
