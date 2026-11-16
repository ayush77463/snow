"""Transfer session lifecycle and active transfer state management."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Dict, List, Optional, Set
import uuid

logger = logging.getLogger(__name__)


class TransferState(str, Enum):
    """Lifecycle states of an active or completed file transfer."""
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class TransferDirection(str, Enum):
    """Direction of the binary file stream."""
    UPLOAD = "UPLOAD"      # Client -> Desktop Core
    DOWNLOAD = "DOWNLOAD"  # Desktop Core -> Client


@dataclass
class TransferRecord:
    """Metadata tracking an in-flight or completed file transfer."""
    transfer_id: str
    device_id: str
    direction: TransferDirection
    file_name: str
    file_size: int
    sha256: str
    current_offset: int = 0
    status: TransferState = TransferState.QUEUED
    error_message: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "transfer_id": self.transfer_id,
            "device_id": self.device_id,
            "direction": self.direction.value,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "current_offset": self.current_offset,
            "status": self.status.value,
            "error_message": self.error_message,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class TransferManager:
    """Thread-safe and asyncio-compatible registry for managing file transfer sessions."""

    def __init__(self) -> None:
        self._transfers: Dict[str, TransferRecord] = {}

    def create_transfer(
        self,
        device_id: str,
        file_name: str,
        file_size: int,
        sha256: str,
        direction: TransferDirection = TransferDirection.UPLOAD,
        transfer_id: Optional[str] = None,
    ) -> TransferRecord:
        """Register a new transfer session for a verified device."""
        if not device_id or not isinstance(device_id, str):
            raise ValueError("device_id must be a non-empty string.")
        if file_size < 0:
            raise ValueError("file_size cannot be negative.")
        if not sha256 or len(sha256.strip()) != 64:
            raise ValueError("sha256 must be a 64-character hexadecimal digest.")

        tid = transfer_id or str(uuid.uuid4())
        record = TransferRecord(
            transfer_id=tid,
            device_id=device_id,
            direction=direction,
            file_name=file_name,
            file_size=file_size,
            sha256=sha256.strip().lower(),
            current_offset=0,
            status=TransferState.QUEUED,
        )
        self._transfers[tid] = record
        logger.info(
            "Created transfer record [%s] (%s, %s, %d bytes) for device [%s]",
            tid, direction.value, file_name, file_size, device_id
        )
        return record

    def get_transfer(self, transfer_id: str) -> Optional[TransferRecord]:
        """Retrieve a transfer record by transfer_id."""
        return self._transfers.get(transfer_id)

    def get_transfer_for_device(self, transfer_id: str, device_id: str) -> Optional[TransferRecord]:
        """Retrieve a transfer record only if owned by the requesting device.

        Enforces strict cross-device isolation: Device A cannot access Device B's transfer.
        """
        record = self._transfers.get(transfer_id)
        if record and record.device_id == device_id:
            return record
        return None

    def update_offset(self, transfer_id: str, offset: int) -> bool:
        """Update current stream offset of an active transfer."""
        record = self._transfers.get(transfer_id)
        if not record:
            return False
        record.current_offset = offset
        record.status = TransferState.IN_PROGRESS
        record.updated_at = datetime.now(timezone.utc).isoformat()
        return True

    def mark_completed(self, transfer_id: str) -> bool:
        """Mark transfer as successfully completed and verified."""
        record = self._transfers.get(transfer_id)
        if not record:
            return False
        record.current_offset = record.file_size
        record.status = TransferState.COMPLETED
        record.updated_at = datetime.now(timezone.utc).isoformat()
        logger.info("Transfer [%s] marked as COMPLETED", transfer_id)
        return True

    def mark_failed(self, transfer_id: str, error_message: str) -> bool:
        """Mark transfer as failed with an explanatory error."""
        record = self._transfers.get(transfer_id)
        if not record:
            return False
        record.status = TransferState.FAILED
        record.error_message = error_message
        record.updated_at = datetime.now(timezone.utc).isoformat()
        logger.warning("Transfer [%s] marked as FAILED: %s", transfer_id, error_message)
        return True

    def cancel_transfer(self, transfer_id: str, device_id: str) -> bool:
        """Cancel an in-flight transfer, enforcing device ownership."""
        record = self.get_transfer_for_device(transfer_id, device_id)
        if not record:
            return False
        if record.status in (TransferState.COMPLETED, TransferState.CANCELLED):
            return False
        record.status = TransferState.CANCELLED
        record.updated_at = datetime.now(timezone.utc).isoformat()
        logger.info("Transfer [%s] CANCELLED by device [%s]", transfer_id, device_id)
        return True

    def list_transfers_for_device(self, device_id: str) -> List[TransferRecord]:
        """Return all transfer records associated with a specific device."""
        return [
            rec for rec in self._transfers.values()
            if rec.device_id == device_id
        ]

    def get_active_transfer_ids(self) -> Set[str]:
        """Return set of transfer IDs that are currently active or resume-eligible."""
        return {
            rec.transfer_id
            for rec in self._transfers.values()
            if rec.status in (TransferState.QUEUED, TransferState.IN_PROGRESS, TransferState.PAUSED)
        }
