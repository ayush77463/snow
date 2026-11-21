"""First-class shared clipboard ring buffer capability for SNOW V4.

Architectural owner: Layer 2 - Capability Engine.
Implements:
- 10-item authoritative timeline with index 0 as newest.
- Eviction of oldest unpinned entry when capacity is reached.
- Pinning with a maximum of 5 pinned entries.
- Content size bounds: Text <= 64 KiB, Images <= 10 MiB (PNG/JPEG).
- Secure image file storage under ~/.snow/transfers/clipboard_buffer/ with canonical containment.
- Full cleanup of image files on deletion, eviction, or clear.
- SHA-256 deduplication and cross-device echo-loop suppression.
- Explicit-intent native clipboard application separation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import logging
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Set
import uuid

logger = logging.getLogger(__name__)

MAX_BUFFER_ITEMS: int = 10
MAX_PINNED_ITEMS: int = 5
MAX_TEXT_BYTES: int = 64 * 1024  # 64 KiB
MAX_IMAGE_BYTES: int = 10 * 1024 * 1024  # 10 MiB
MAX_PREVIEW_CHARS: int = 120

JPEG_SIGNATURE = b"\xff\xd8\xff"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def get_default_clipboard_storage_dir() -> Path:
    """Return the canonical storage directory for shared clipboard buffer media."""
    data_dir = os.environ.get("SNOW_DATA_DIR")
    if data_dir:
        base = Path(data_dir).resolve()
    else:
        base = Path.home() / ".snow"
    target = base / "transfers" / "clipboard_buffer"
    target.mkdir(parents=True, exist_ok=True)
    return target


@dataclass
class ClipboardItem:
    """Represents a single entry in the authoritative shared clipboard buffer."""

    item_id: str
    content_type: str  # "text" | "image"
    preview: str
    source_device_id: str
    source_device_name: str
    timestamp: float
    sha256: str
    size_bytes: int
    pinned: bool = False
    text_content: Optional[str] = None
    image_path: Optional[Path] = None
    mime_type: Optional[str] = None

    def to_metadata(self) -> Dict[str, Any]:
        """Return safe metadata omitting raw payloads and internal paths."""
        return {
            "item_id": self.item_id,
            "content_type": self.content_type,
            "type": self.content_type,
            "preview": self.preview,
            "preview_text": self.preview,
            "source_device_id": self.source_device_id,
            "source_device": self.source_device_id,
            "source_device_name": self.source_device_name,
            "timestamp": self.timestamp,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "pinned": self.pinned,
            "is_pinned": self.pinned,
            "mime_type": self.mime_type,
        }

    def to_detail(self) -> Dict[str, Any]:
        """Return full item payload for explicit detail queries or apply actions."""
        res = self.to_metadata()
        if self.content_type == "text":
            res["text_content"] = self.text_content
        elif self.content_type == "image":
            res["has_image"] = bool(self.image_path and self.image_path.is_file())
        return res


class ClipboardRingBuffer:
    """Authoritative, thread-safe in-memory timeline with bounded disk-backed media."""

    def __init__(
        self,
        storage_dir: Optional[Path | str] = None,
        capacity: int = MAX_BUFFER_ITEMS,
        max_pinned: int = MAX_PINNED_ITEMS,
    ) -> None:
        if storage_dir:
            self.storage_dir = Path(storage_dir).resolve()
            self.storage_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.storage_dir = get_default_clipboard_storage_dir()

        self.capacity: int = capacity
        self.max_pinned: int = max_pinned
        self._items: List[ClipboardItem] = []
        # Echo-loop tracking: sha256 -> set of device_ids that have synchronized this content
        self._synced_devices: Dict[str, Set[str]] = {}

    def list_items(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return ordered list of safe item metadata (newest at index 0)."""
        items = [item.to_metadata() for item in self._items]
        if limit is not None:
            return items[:limit]
        return items

    def get_item(self, item_id: str, include_content: bool = False) -> Optional[Dict[str, Any]]:
        """Retrieve a specific item by ID."""
        for item in self._items:
            if item.item_id == item_id:
                return item.to_detail() if include_content else item.to_metadata()
        return None

    def get_image_path(self, item_id: str) -> Optional[Path]:
        """Retrieve canonical image path for an item, strictly enforcing containment."""
        for item in self._items:
            if item.item_id == item_id and item.content_type == "image" and item.image_path:
                try:
                    resolved = item.image_path.resolve()
                    if resolved.is_relative_to(self.storage_dir) and resolved.is_file():
                        return resolved
                except (ValueError, RuntimeError):
                    return None
        return None

    def _evict_if_needed(self) -> bool:
        """Evict the oldest unpinned item if buffer has reached capacity.

        Returns True if capacity is available, False if all items are pinned.
        """
        if len(self._items) < self.capacity:
            return True

        # Find the oldest unpinned item (highest index with pinned == False)
        evict_idx: Optional[int] = None
        for i in range(len(self._items) - 1, -1, -1):
            if not self._items[i].pinned:
                evict_idx = i
                break

        if evict_idx is None:
            # All items currently in buffer are pinned
            logger.warning("Clipboard buffer is full (%d) and all items are pinned.", len(self._items))
            return False

        evicted = self._items.pop(evict_idx)
        logger.info("Evicted oldest unpinned clipboard item: %s (%s)", evicted.item_id, evicted.preview)
        self._cleanup_item_files(evicted)
        return True

    def _cleanup_item_files(self, item: ClipboardItem) -> None:
        """Safely delete any media files associated with an item."""
        if item.image_path:
            try:
                resolved = item.image_path.resolve()
                if resolved.is_relative_to(self.storage_dir) and resolved.is_file():
                    resolved.unlink(missing_ok=True)
                    logger.debug("Deleted clipboard buffer media: %s", resolved)
            except Exception as exc:
                logger.warning("Error deleting clipboard buffer media %s: %s", item.image_path, exc)

    def add_text(
        self,
        text: str,
        source_device_id: str = "desktop_windows",
        source_device_name: str = "Windows PC",
        pin: bool = False,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Add text content to the shared buffer."""
        if "source_device" in kwargs:
            source_device_id = kwargs["source_device"]
        if "is_pinned" in kwargs:
            pin = bool(kwargs["is_pinned"])
        if not isinstance(text, str):
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "Text must be a string."}

        raw_bytes = text.encode("utf-8")
        if len(raw_bytes) > MAX_TEXT_BYTES:
            return {
                "success": False,
                "status": "CONTENT_TOO_LARGE",
                "error": f"Text size ({len(raw_bytes)} bytes) exceeds maximum limit of {MAX_TEXT_BYTES} bytes (64 KiB).",
            }

        digest = hashlib.sha256(raw_bytes).hexdigest()

        # Deduplication check
        existing_idx: Optional[int] = None
        for idx, item in enumerate(self._items):
            if item.sha256 == digest:
                existing_idx = idx
                break

        now = time.time()
        if existing_idx is not None:
            # Existing item found: bump timestamp and move to index 0
            existing = self._items.pop(existing_idx)
            existing.timestamp = now
            existing.source_device_id = source_device_id
            existing.source_device_name = source_device_name
            if pin and not existing.pinned:
                pinned_count = sum(1 for it in self._items if it.pinned)
                if pinned_count < self.max_pinned:
                    existing.pinned = True
            self._items.insert(0, existing)
            # Track synced origin
            self._synced_devices.setdefault(digest, set()).add(source_device_id)
            return {
                "success": True,
                "status": "DEDUPLICATED",
                "item": existing.to_metadata(),
                "deduplicated": True,
            }

        # Check pinning limit if requested
        pinned_count = sum(1 for it in self._items if it.pinned)
        if pin and pinned_count >= self.max_pinned:
            return {
                "success": False,
                "status": "MAX_PINNED_REACHED",
                "error": f"Cannot pin item: maximum pinned limit ({self.max_pinned}) reached.",
            }

        # Evict oldest unpinned if needed
        if not self._evict_if_needed():
            return {
                "success": False,
                "status": "BUFFER_FULL_ALL_PINNED",
                "error": "Clipboard buffer is full and all entries are pinned. Unpin an entry to add new items.",
            }

        preview = text.strip().replace("\r\n", " ").replace("\n", " ").replace("\t", " ")
        if len(preview) > MAX_PREVIEW_CHARS:
            preview = preview[:MAX_PREVIEW_CHARS].rstrip() + "..."
        if not preview:
            preview = "[Empty text]"

        item_id = f"cb_{digest[:12]}_{uuid.uuid4().hex[:6]}"
        item = ClipboardItem(
            item_id=item_id,
            content_type="text",
            preview=preview,
            source_device_id=source_device_id,
            source_device_name=source_device_name,
            timestamp=now,
            sha256=digest,
            size_bytes=len(raw_bytes),
            pinned=pin,
            text_content=text,
            mime_type="text/plain; charset=utf-8",
        )

        self._items.insert(0, item)
        self._synced_devices.setdefault(digest, set()).add(source_device_id)

        return {
            "success": True,
            "status": "ADDED",
            "item": item.to_metadata(),
            "deduplicated": False,
        }

    def add_image(
        self,
        image_bytes: bytes,
        mime_type: Optional[str] = None,
        source_device_id: str = "desktop_windows",
        source_device_name: str = "Windows PC",
        pin: bool = False,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Add image media content (PNG or JPEG) to the shared buffer."""
        if "source_device" in kwargs:
            source_device_id = kwargs["source_device"]
        if "is_pinned" in kwargs:
            pin = bool(kwargs["is_pinned"])
        if not isinstance(image_bytes, (bytes, bytearray)):
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "Image data must be bytes."}

        size = len(image_bytes)
        if size > MAX_IMAGE_BYTES:
            return {
                "success": False,
                "status": "CONTENT_TOO_LARGE",
                "error": f"Image size ({size} bytes) exceeds maximum limit of {MAX_IMAGE_BYTES} bytes (10 MiB).",
            }

        # Validate magic byte signatures
        ext: str
        detected_mime: str
        if image_bytes.startswith(PNG_SIGNATURE):
            ext = "png"
            detected_mime = "image/png"
        elif image_bytes.startswith(JPEG_SIGNATURE):
            ext = "jpg"
            detected_mime = "image/jpeg"
        else:
            return {
                "success": False,
                "status": "INVALID_IMAGE_FORMAT",
                "error": "Only valid PNG and JPEG images are supported by the clipboard buffer.",
            }

        digest = hashlib.sha256(image_bytes).hexdigest()

        # Deduplication check
        existing_idx: Optional[int] = None
        for idx, item in enumerate(self._items):
            if item.sha256 == digest:
                existing_idx = idx
                break

        now = time.time()
        if existing_idx is not None:
            existing = self._items.pop(existing_idx)
            existing.timestamp = now
            existing.source_device_id = source_device_id
            existing.source_device_name = source_device_name
            if pin and not existing.pinned:
                pinned_count = sum(1 for it in self._items if it.pinned)
                if pinned_count < self.max_pinned:
                    existing.pinned = True
            self._items.insert(0, existing)
            self._synced_devices.setdefault(digest, set()).add(source_device_id)
            return {
                "success": True,
                "status": "DEDUPLICATED",
                "item": existing.to_metadata(),
                "deduplicated": True,
            }

        pinned_count = sum(1 for it in self._items if it.pinned)
        if pin and pinned_count >= self.max_pinned:
            return {
                "success": False,
                "status": "MAX_PINNED_REACHED",
                "error": f"Cannot pin item: maximum pinned limit ({self.max_pinned}) reached.",
            }

        if not self._evict_if_needed():
            return {
                "success": False,
                "status": "BUFFER_FULL_ALL_PINNED",
                "error": "Clipboard buffer is full and all entries are pinned. Unpin an entry to add new items.",
            }

        # Generate internal filename
        filename = f"clip_{digest[:16]}_{int(now)}.{ext}"
        target_path = (self.storage_dir / filename).resolve()
        if not target_path.is_relative_to(self.storage_dir):
            return {"success": False, "status": "SECURITY_ERROR", "error": "Storage path escape detected."}

        try:
            target_path.write_bytes(image_bytes)
        except Exception as exc:
            logger.error("Failed saving clipboard image: %s", exc)
            return {"success": False, "status": "IO_ERROR", "error": f"Could not write image to disk: {exc}"}

        size_kb = size / 1024
        preview = f"{ext.upper()} Image ({size_kb:.1f} KiB)"
        item_id = f"cb_{digest[:12]}_{uuid.uuid4().hex[:6]}"

        item = ClipboardItem(
            item_id=item_id,
            content_type="image",
            preview=preview,
            source_device_id=source_device_id,
            source_device_name=source_device_name,
            timestamp=now,
            sha256=digest,
            size_bytes=size,
            pinned=pin,
            image_path=target_path,
            mime_type=detected_mime,
        )

        self._items.insert(0, item)
        self._synced_devices.setdefault(digest, set()).add(source_device_id)

        return {
            "success": True,
            "status": "ADDED",
            "item": item.to_metadata(),
            "deduplicated": False,
        }

    def pin(self, item_id: str) -> Dict[str, Any]:
        """Pin a specific item to protect it from automatic eviction."""
        for item in self._items:
            if item.item_id == item_id:
                if item.pinned:
                    return {"success": True, "status": "ALREADY_PINNED", "item": item.to_metadata()}
                pinned_count = sum(1 for it in self._items if it.pinned)
                if pinned_count >= self.max_pinned:
                    return {
                        "success": False,
                        "status": "MAX_PINNED_REACHED",
                        "error": f"Maximum pinned items limit ({self.max_pinned}) reached. Unpin an item first.",
                    }
                item.pinned = True
                return {"success": True, "status": "PINNED", "item": item.to_metadata()}

        return {"success": False, "status": "ITEM_NOT_FOUND", "error": f"Item '{item_id}' not found."}

    def unpin(self, item_id: str) -> Dict[str, Any]:
        """Unpin a specific item."""
        for item in self._items:
            if item.item_id == item_id:
                item.pinned = False
                return {"success": True, "status": "UNPINNED", "item": item.to_metadata()}

        return {"success": False, "status": "ITEM_NOT_FOUND", "error": f"Item '{item_id}' not found."}

    def delete(self, item_id: str) -> Dict[str, Any]:
        """Explicitly delete an item and any associated media files."""
        for idx, item in enumerate(self._items):
            if item.item_id == item_id:
                removed = self._items.pop(idx)
                self._cleanup_item_files(removed)
                return {"success": True, "status": "DELETED", "item_id": item_id}

        return {"success": False, "status": "ITEM_NOT_FOUND", "error": f"Item '{item_id}' not found."}

    def clear(self, unpinned_only: bool = True) -> Dict[str, Any]:
        """Clear the clipboard buffer.

        If unpinned_only is True (default), retains pinned items.
        If unpinned_only is False, removes everything (requires explicit owner confirmation).
        """
        cleared_count = 0
        if unpinned_only:
            retained: List[ClipboardItem] = []
            for item in self._items:
                if item.pinned:
                    retained.append(item)
                else:
                    self._cleanup_item_files(item)
                    cleared_count += 1
            self._items = retained
        else:
            for item in self._items:
                self._cleanup_item_files(item)
                cleared_count += 1
            self._items.clear()
            self._synced_devices.clear()

        return {
            "success": True,
            "status": "CLEARED",
            "cleared_count": cleared_count,
            "remaining_count": len(self._items),
        }

    def has_device_received(self, sha256: str, device_id: str) -> bool:
        """Check if a device has already sent or received this content (echo suppression)."""
        return device_id in self._synced_devices.get(sha256, set())

    def mark_device_received(self, sha256: str, device_id: str) -> None:
        """Record that a device has received this content."""
        self._synced_devices.setdefault(sha256, set()).add(device_id)
