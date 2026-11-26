"""First-class shared clipboard ring buffer capability for SNOW V7.

Architectural owner: Layer 2 - Capability Engine.
Implements:
- 15-item authoritative thread-safe timeline with index 0 as newest and monotonic seq.
- Eviction of oldest unpinned entry when capacity or 100 MiB media budget is reached.
- Pinning with a maximum of 5 pinned entries.
- Content bounds: Text <= 64 KiB, Images <= 15 MiB (PNG/JPEG), Single file <= 15 MiB,
  Multi-file bundle <= 5 files and <= 15 MiB aggregate.
- Secure media storage under ~/.snow/transfers/clipboard_buffer/ with canonical containment.
- Ref-counted cleanup of unreferenced media files on deletion, eviction, or clear.
- Debounced SHA-256 deduplication and post-debounce distinct event_id/seq generation.
- Durable SQLite Schema v7 additive persistence and per-device ack tracking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import logging
import mimetypes
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Set
import uuid

logger = logging.getLogger(__name__)

MAX_BUFFER_ITEMS: int = 15
MAX_PINNED_ITEMS: int = 5
MAX_TEXT_BYTES: int = 64 * 1024  # 64 KiB
MAX_IMAGE_BYTES: int = 15 * 1024 * 1024  # 15 MiB
MAX_FILE_BYTES: int = 15 * 1024 * 1024  # 15 MiB
MAX_BUNDLE_BYTES: int = 15 * 1024 * 1024  # 15 MiB
MAX_BUNDLE_FILES: int = 5
MAX_BUFFER_MEDIA_BYTES: int = 100 * 1024 * 1024  # 100 MiB aggregate persisted media
DEFAULT_DEBOUNCE_SECONDS: float = 0.5
MAX_PREVIEW_CHARS: int = 120

VALID_CONTENT_TYPES = frozenset({"text", "image", "file", "file_bundle"})
JPEG_SIGNATURE = b"\xff\xd8\xff"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_EXT_RE = re.compile(r"^\.[a-z0-9]{1,15}$")
_MIME_TYPE_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+(?:\s*;.*)?$", re.IGNORECASE)


def get_default_clipboard_storage_dir() -> Path:
    """Return the canonical storage directory for shared clipboard buffer media."""
    data_dir = os.environ.get("SNOW_DATA_DIR")
    if data_dir:
        base = Path(data_dir).resolve()
    else:
        base = Path.home() / ".snow"
    target = base / "transfers" / "clipboard_buffer"
    target.mkdir(parents=True, exist_ok=True)
    return target.resolve()


def _is_reparse_or_symlink(path: Path) -> bool:
    """Return True if path itself is a symlink or Windows reparse point."""
    try:
        if path.is_symlink():
            return True
        st = os.lstat(path)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        file_attrs = getattr(st, "st_file_attributes", 0)
        if reparse_flag and (file_attrs & reparse_flag):
            return True
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return False


def is_contained_non_symlink(path: Path, root: Path) -> bool:
    """Verify path exists cleanly inside root without traversing symlinks/junctions."""
    try:
        resolved_root = root.resolve()
        if _is_reparse_or_symlink(resolved_root):
            return False
        # Walk raw parents up to root if raw path appears nested under root
        candidate = path
        if _is_reparse_or_symlink(candidate):
            return False
        for parent in candidate.parents:
            if parent == root or parent == resolved_root:
                break
            if str(parent).startswith(str(root)) and _is_reparse_or_symlink(parent):
                return False
        resolved = candidate.resolve()
        return resolved.is_relative_to(resolved_root) and resolved != resolved_root and resolved.is_file()
    except (OSError, ValueError, RuntimeError):
        return False


def sanitize_manifest_filename(name: Any) -> str:
    """Validate and return a safe single filename without path traversal or control chars."""
    if not isinstance(name, str):
        raise ValueError("Filename must be a string.")
    clean = name.strip()
    if not clean or len(clean) > 255:
        raise ValueError("Filename must be between 1 and 255 characters.")
    if clean in (".", "..") or ".." in clean:
        raise ValueError("Filename contains disallowed traversal sequence.")
    if any(ord(ch) < 32 or ch in ("/", "\\", ":", "\x00") for ch in clean):
        raise ValueError("Filename contains forbidden path separator or control characters.")
    if PurePosixPath(clean).name != clean or PureWindowsPath(clean).name != clean:
        raise ValueError("Filename must not contain directory components.")
    return clean


def _safe_extension(filename: str) -> str:
    """Extract a conservative ASCII extension (or empty string) from a validated filename."""
    ext = Path(filename).suffix.lower()
    return ext if _SAFE_EXT_RE.fullmatch(ext) else ""


def _validate_sha256_hex(digest: Any) -> str:
    if not isinstance(digest, str) or not _SHA256_HEX_RE.fullmatch(digest.strip()):
        raise ValueError("sha256 must be a valid 64-character hexadecimal string.")
    return digest.strip().lower()


def validate_file_manifest(
    manifest: Any,
    require_stored_filename: bool = False,
) -> List[Dict[str, Any]]:
    """Strictly validate a file/file_bundle manifest list."""
    if not isinstance(manifest, list) or not (1 <= len(manifest) <= MAX_BUNDLE_FILES):
        raise ValueError(f"file_manifest must be a list of 1 to {MAX_BUNDLE_FILES} entries.")

    validated: List[Dict[str, Any]] = []
    total_size = 0
    for idx, entry in enumerate(manifest):
        if not isinstance(entry, dict):
            raise ValueError(f"Manifest entry {idx} must be a dict.")
        safe_name = sanitize_manifest_filename(entry.get("name"))
        raw_size = entry.get("size_bytes")
        if isinstance(raw_size, bool) or not isinstance(raw_size, int) or raw_size < 0 or raw_size > MAX_FILE_BYTES:
            raise ValueError(f"Manifest entry '{safe_name}' size_bytes out of bounds.")
        total_size += raw_size
        if total_size > MAX_BUNDLE_BYTES:
            raise ValueError(f"Aggregate file bundle size exceeds {MAX_BUNDLE_BYTES} bytes (15 MiB).")

        raw_mime = entry.get("mime_type") or mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
        if not isinstance(raw_mime, str) or len(raw_mime.strip()) > 128 or not _MIME_TYPE_RE.fullmatch(raw_mime.strip()):
            raise ValueError(f"Manifest entry '{safe_name}' has invalid mime_type.")

        sha256_hex = _validate_sha256_hex(entry.get("sha256"))
        clean_entry: Dict[str, Any] = {
            "name": safe_name,
            "size_bytes": raw_size,
            "mime_type": raw_mime.strip(),
            "sha256": sha256_hex,
        }
        stored_name = entry.get("stored_filename")
        if require_stored_filename:
            clean_entry["stored_filename"] = sanitize_manifest_filename(stored_name)
        elif stored_name is not None:
            clean_entry["stored_filename"] = sanitize_manifest_filename(stored_name)
        validated.append(clean_entry)

    return validated


@dataclass
class ClipboardItem:
    """Represents a single entry in the authoritative shared clipboard buffer."""

    item_id: str
    content_type: str  # "text" | "image" | "file" | "file_bundle"
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
    canonical_sha256: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    seq: int = 0
    file_manifest: List[Dict[str, Any]] = field(default_factory=list)

    def media_bytes(self) -> int:
        """Return persisted storage bytes attributed to this entry."""
        if self.content_type == "image" and self.image_path is not None:
            return max(0, int(self.size_bytes))
        if self.content_type in ("file", "file_bundle") and self.file_manifest:
            return sum(max(0, int(entry.get("size_bytes", 0))) for entry in self.file_manifest)
        return 0

    def referenced_filenames(self) -> Set[str]:
        """Return all cache filenames under storage_dir referenced by this item."""
        names: Set[str] = set()
        if self.image_path is not None:
            names.add(self.image_path.name)
        for entry in self.file_manifest:
            stored = entry.get("stored_filename")
            if isinstance(stored, str) and stored:
                names.add(stored)
        return names

    def to_metadata(self) -> Dict[str, Any]:
        """Return safe metadata omitting raw text payloads and internal disk paths."""
        meta: Dict[str, Any] = {
            "item_id": self.item_id,
            "event_id": self.event_id,
            "seq": self.seq,
            "content_type": self.content_type,
            "type": self.content_type,
            "preview": self.preview,
            "preview_text": self.preview,
            "source_device_id": self.source_device_id,
            "source_device": self.source_device_id,
            "origin_device_id": self.source_device_id,
            "source_device_name": self.source_device_name,
            "timestamp": self.timestamp,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "pinned": self.pinned,
            "is_pinned": self.pinned,
            "mime_type": self.mime_type,
        }
        if self.canonical_sha256:
            meta["canonical_sha256"] = self.canonical_sha256
        if self.width is not None:
            meta["width"] = self.width
        if self.height is not None:
            meta["height"] = self.height
        if self.content_type in ("file", "file_bundle"):
            meta["file_manifest"] = [
                {
                    "index": idx,
                    "name": entry["name"],
                    "size_bytes": entry["size_bytes"],
                    "mime_type": entry["mime_type"],
                    "sha256": entry["sha256"],
                }
                for idx, entry in enumerate(self.file_manifest)
            ]
            meta["file_count"] = len(self.file_manifest)
        return meta

    def to_detail(self) -> Dict[str, Any]:
        """Return full item payload for explicit detail queries or apply actions."""
        res = self.to_metadata()
        if self.content_type == "text":
            res["text_content"] = self.text_content
        elif self.content_type == "image":
            res["has_image"] = bool(self.image_path and self.image_path.is_file())
        elif self.content_type in ("file", "file_bundle"):
            res["has_files"] = bool(self.file_manifest)
        return res


class ClipboardRingBuffer:
    """Authoritative, thread-safe in-memory timeline with bounded disk-backed media."""

    def __init__(
        self,
        storage_dir: Optional[Path | str] = None,
        capacity: int = MAX_BUFFER_ITEMS,
        max_pinned: int = MAX_PINNED_ITEMS,
        db_manager: Optional[Any] = None,
        max_media_bytes: int = MAX_BUFFER_MEDIA_BYTES,
        debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        if max_pinned < 0:
            raise ValueError("max_pinned must be >= 0")
        if max_media_bytes < 0:
            raise ValueError("max_media_bytes must be >= 0")
        if debounce_seconds < 0:
            raise ValueError("debounce_seconds must be >= 0")

        if storage_dir:
            self.storage_dir = Path(storage_dir).resolve()
            self.storage_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.storage_dir = get_default_clipboard_storage_dir()

        self.capacity: int = capacity
        self.max_pinned: int = max_pinned
        self.max_media_bytes: int = max_media_bytes
        self.debounce_seconds: float = debounce_seconds
        self.db_manager = db_manager
        self._lock = threading.RLock()
        self._items: List[ClipboardItem] = []
        self._seq_counter: int = 0
        # Echo-loop tracking: sha256 -> set of device_ids, and event_id -> set of device_ids
        self._synced_devices: Dict[str, Set[str]] = {}
        self._synced_events: Dict[str, Set[str]] = {}

        if self.db_manager is not None:
            self._reconcile_and_load_persisted()

    def _next_seq_locked(self) -> int:
        self._seq_counter += 1
        if self.db_manager and hasattr(self.db_manager, "set_setting"):
            try:
                self.db_manager.set_setting("clip_seq_counter", str(self._seq_counter))
            except Exception as e:
                logger.warning("Failed persisting clip_seq_counter: %s", e)
        return self._seq_counter

    def _resolve_stored_file_locked(self, filename: Optional[str]) -> Optional[Path]:
        if not filename:
            return None
        try:
            clean_name = sanitize_manifest_filename(filename)
        except ValueError:
            return None
        candidate = self.storage_dir / clean_name
        if is_contained_non_symlink(candidate, self.storage_dir):
            return candidate.resolve()
        return None

    def _persist_item_locked(self, item: ClipboardItem) -> None:
        if not self.db_manager or not hasattr(self.db_manager, "save_clipboard_item"):
            return
        try:
            rel_p = item.image_path.name if item.image_path else None
            self.db_manager.save_clipboard_item(
                item_id=item.item_id,
                content_type=item.content_type,
                preview=item.preview,
                source_device_id=item.source_device_id,
                source_device_name=item.source_device_name,
                timestamp=item.timestamp,
                sha256=item.sha256,
                size_bytes=item.size_bytes,
                pinned=item.pinned,
                text_content=item.text_content if item.content_type == "text" else None,
                image_rel_path=rel_p,
                mime_type=item.mime_type,
                event_id=item.event_id,
                seq=item.seq,
                file_manifest=item.file_manifest if item.content_type in ("file", "file_bundle") else [],
            )
        except Exception as e:
            logger.warning("Error persisting clipboard item %s to DB: %s", item.item_id, e)

    def _delete_from_db_locked(self, item_id: str) -> None:
        if self.db_manager and hasattr(self.db_manager, "delete_clipboard_item"):
            try:
                self.db_manager.delete_clipboard_item(item_id)
            except Exception as e:
                logger.warning("Error deleting item %s from DB: %s", item_id, e)

    def _collect_unreferenced_paths_locked(self, removed_items: Sequence[ClipboardItem]) -> List[Path]:
        """Collect disk files from removed_items that are NOT referenced by any live item."""
        still_referenced: Set[str] = set()
        for live in self._items:
            still_referenced.update(live.referenced_filenames())

        to_delete: List[Path] = []
        seen_names: Set[str] = set()
        for removed in removed_items:
            for fname in removed.referenced_filenames():
                if fname in still_referenced or fname in seen_names:
                    continue
                resolved = self._resolve_stored_file_locked(fname)
                if resolved is not None:
                    to_delete.append(resolved)
                    seen_names.add(fname)
        return to_delete

    def _unlink_paths(self, paths: Sequence[Path]) -> None:
        """Delete media files safely outside critical locks."""
        for path in paths:
            try:
                if is_contained_non_symlink(path, self.storage_dir):
                    path.unlink(missing_ok=True)
                    logger.debug("Deleted unreferenced clipboard buffer media: %s", path)
            except Exception as exc:
                logger.warning("Error deleting clipboard buffer media %s: %s", path, exc)

    def _plan_eviction_locked(
        self,
        new_media_bytes: int,
        adding_new_slot: bool = True,
    ) -> tuple[bool, str, List[int]]:
        """Compute oldest-unpinned eviction indices to fit capacity and media budget atomically."""
        if new_media_bytes > self.max_media_bytes:
            return (
                False,
                "CONTENT_TOO_LARGE",
                [],
            )

        current_count = len(self._items)
        current_media = sum(it.media_bytes() for it in self._items)
        evict_indices: List[int] = []
        evicted_media = 0

        def _fits() -> bool:
            remaining_count = current_count - len(evict_indices)
            count_ok = (remaining_count < self.capacity) if adding_new_slot else (remaining_count <= self.capacity)
            media_ok = (current_media - evicted_media + new_media_bytes) <= self.max_media_bytes
            return count_ok and media_ok

        for i in range(len(self._items) - 1, -1, -1):
            if _fits():
                break
            if self._items[i].pinned:
                continue
            evict_indices.append(i)
            evicted_media += self._items[i].media_bytes()

        if _fits():
            return True, "OK", evict_indices

        remaining_count = current_count - len(evict_indices)
        if adding_new_slot and remaining_count >= self.capacity:
            return False, "BUFFER_FULL_ALL_PINNED", []
        return False, "MEDIA_BUDGET_EXCEEDED", []

    def _commit_eviction_locked(self, evict_indices: Sequence[int]) -> List[ClipboardItem]:
        """Pop planned eviction indices (must be descending) and delete DB records."""
        removed: List[ClipboardItem] = []
        for idx in sorted(evict_indices, reverse=True):
            evicted = self._items.pop(idx)
            logger.info("Evicted oldest unpinned clipboard item: %s (%s)", evicted.item_id, evicted.preview)
            self._delete_from_db_locked(evicted.item_id)
            removed.append(evicted)
        return removed

    def _reconcile_and_load_persisted(self) -> None:
        """Reconcile SQLite persistence with disk storage on startup."""
        if not self.db_manager or not hasattr(self.db_manager, "load_all_clipboard_items"):
            return

        persisted_counter = 0
        if hasattr(self.db_manager, "get_setting"):
            try:
                raw_cnt = self.db_manager.get_setting("clip_seq_counter")
                if raw_cnt is not None:
                    persisted_counter = max(0, int(raw_cnt))
            except Exception:
                persisted_counter = 0

        if hasattr(self.db_manager, "list_clipboard_acks"):
            try:
                for ack in self.db_manager.list_clipboard_acks().values():
                    persisted_counter = max(persisted_counter, int(ack.get("last_acked_seq", 0)))
            except Exception:
                pass

        try:
            persisted = self.db_manager.load_all_clipboard_items()
        except Exception as e:
            logger.error("Failed loading persisted clipboard items from SQLite: %s", e)
            return

        loaded_items: List[ClipboardItem] = []
        for row in persisted:
            item_id = row.get("item_id")
            if not item_id:
                continue
            c_type = row.get("content_type", "text")
            if c_type not in VALID_CONTENT_TYPES:
                logger.warning("Pruning unknown clipboard content_type %r for item %s.", c_type, item_id)
                self._delete_from_db_locked(item_id)
                continue

            sha256 = row.get("sha256", "")
            pinned = bool(row.get("pinned", 0))
            event_id = row.get("event_id") or str(uuid.uuid4())
            seq = int(row.get("seq") or 0)
            persisted_counter = max(persisted_counter, seq)

            if c_type == "image":
                rel_path = row.get("image_rel_path")
                disk_file = self._resolve_stored_file_locked(rel_path)
                actual_size = disk_file.stat().st_size if disk_file else 0
                if disk_file and 0 < actual_size <= MAX_IMAGE_BYTES:
                    loaded_items.append(
                        ClipboardItem(
                            item_id=item_id,
                            content_type="image",
                            preview=row.get("preview") or "Image",
                            source_device_id=row.get("source_device_id") or "desktop_windows",
                            source_device_name=row.get("source_device_name") or "Windows PC",
                            timestamp=float(row.get("timestamp", 0.0)),
                            sha256=sha256,
                            size_bytes=actual_size,
                            pinned=pinned,
                            image_path=disk_file,
                            mime_type=row.get("mime_type") or "image/png",
                            event_id=event_id,
                            seq=seq,
                        )
                    )
                else:
                    logger.warning(
                        "Pruning clipboard record %s: referenced image file %s missing or invalid.",
                        item_id,
                        rel_path,
                    )
                    self._delete_from_db_locked(item_id)

            elif c_type in ("file", "file_bundle"):
                raw_manifest_json = row.get("file_manifest_json") or "[]"
                try:
                    parsed_manifest = json.loads(raw_manifest_json)
                    manifest = validate_file_manifest(parsed_manifest, require_stored_filename=True)
                    if c_type == "file" and len(manifest) != 1:
                        raise ValueError("Single file item must contain exactly 1 manifest entry.")
                    if c_type == "file_bundle" and not (2 <= len(manifest) <= MAX_BUNDLE_FILES):
                        raise ValueError("File bundle item must contain 2..5 manifest entries.")
                    for entry in manifest:
                        resolved_entry = self._resolve_stored_file_locked(entry["stored_filename"])
                        if not resolved_entry or resolved_entry.stat().st_size != entry["size_bytes"]:
                            raise ValueError(f"Stored file missing or size mismatch: {entry['stored_filename']}")
                except Exception as mf_err:
                    logger.warning(
                        "Pruning corrupt clipboard %s record %s: %s",
                        c_type,
                        item_id,
                        mf_err,
                    )
                    self._delete_from_db_locked(item_id)
                    continue

                total_bytes = sum(e["size_bytes"] for e in manifest)
                loaded_items.append(
                    ClipboardItem(
                        item_id=item_id,
                        content_type=c_type,
                        preview=row.get("preview") or manifest[0]["name"],
                        source_device_id=row.get("source_device_id") or "desktop_windows",
                        source_device_name=row.get("source_device_name") or "Windows PC",
                        timestamp=float(row.get("timestamp", 0.0)),
                        sha256=sha256,
                        size_bytes=total_bytes,
                        pinned=pinned,
                        mime_type=row.get("mime_type") or (manifest[0]["mime_type"] if len(manifest) == 1 else "application/x-snow-file-bundle"),
                        event_id=event_id,
                        seq=seq,
                        file_manifest=manifest,
                    )
                )

            else:
                loaded_items.append(
                    ClipboardItem(
                        item_id=item_id,
                        content_type="text",
                        preview=row.get("preview") or "[Empty text]",
                        source_device_id=row.get("source_device_id") or "desktop_windows",
                        source_device_name=row.get("source_device_name") or "Windows PC",
                        timestamp=float(row.get("timestamp", 0.0)),
                        sha256=sha256,
                        size_bytes=int(row.get("size_bytes", 0)),
                        pinned=pinned,
                        text_content=row.get("text_content"),
                        mime_type=row.get("mime_type") or "text/plain; charset=utf-8",
                        event_id=event_id,
                        seq=seq,
                    )
                )

        # Sort newest first: highest seq first, tie-break on timestamp
        loaded_items.sort(key=lambda x: (x.seq, x.timestamp), reverse=True)
        self._items = loaded_items

        # Enforce capacity and aggregate media budget on startup (preserving pinned items)
        ok, _, evict_indices = self._plan_eviction_locked(new_media_bytes=0, adding_new_slot=False)
        if evict_indices:
            self._commit_eviction_locked(evict_indices)
        # Hard tail clamp if pinned count itself exceeded capacity/budget via manual DB tampering
        while len(self._items) > self.capacity or sum(it.media_bytes() for it in self._items) > self.max_media_bytes:
            unpinned = [i for i in range(len(self._items) - 1, -1, -1) if not self._items[i].pinned]
            victim_idx = unpinned[0] if unpinned else len(self._items) - 1
            victim = self._items.pop(victim_idx)
            self._delete_from_db_locked(victim.item_id)

        referenced_disk_files: Set[str] = set()
        for live_item in self._items:
            referenced_disk_files.update(live_item.referenced_filenames())

        # Orphan disk cleanup: any cache file in storage_dir not referenced by a valid live record is pruned
        try:
            if self.storage_dir.is_dir():
                for disk_entry in self.storage_dir.iterdir():
                    if (
                        not _is_reparse_or_symlink(disk_entry)
                        and disk_entry.is_file()
                        and disk_entry.name not in referenced_disk_files
                        and (disk_entry.name.startswith("clip_") or disk_entry.name.startswith("clipfile_"))
                    ):
                        logger.info("Pruning orphaned clipboard media file: %s", disk_entry.name)
                        try:
                            disk_entry.unlink(missing_ok=True)
                        except Exception as u_err:
                            logger.warning("Could not delete orphaned file %s: %s", disk_entry.name, u_err)
        except Exception as o_err:
            logger.warning("Error during clipboard storage orphan reconciliation: %s", o_err)

        self._seq_counter = persisted_counter

    def list_items(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return ordered list of safe item metadata (newest at index 0)."""
        with self._lock:
            items = [item.to_metadata() for item in self._items]
            if limit is not None:
                if limit < 0:
                    return []
                return items[:limit]
            return items

    def get_item(self, item_id: str, include_content: bool = False) -> Optional[Dict[str, Any]]:
        """Retrieve a specific item by ID."""
        with self._lock:
            for item in self._items:
                if item.item_id == item_id:
                    return item.to_detail() if include_content else item.to_metadata()
            return None

    def get_image_path(self, item_id: str) -> Optional[Path]:
        """Retrieve canonical image path for an item, strictly enforcing non-symlink containment."""
        with self._lock:
            for item in self._items:
                if item.item_id == item_id and item.content_type == "image" and item.image_path:
                    if is_contained_non_symlink(item.image_path, self.storage_dir):
                        return item.image_path.resolve()
                    return None
            return None

    def get_file_entries(self, item_id: str) -> List[Dict[str, Any]]:
        """Return validated stored file paths + manifest metadata for an item."""
        with self._lock:
            for item in self._items:
                if item.item_id != item_id:
                    continue
                if item.content_type == "image" and item.image_path:
                    if is_contained_non_symlink(item.image_path, self.storage_dir):
                        resolved = item.image_path.resolve()
                        ext = resolved.suffix or (".png" if item.mime_type == "image/png" else ".jpg")
                        return [
                            {
                                "index": 0,
                                "name": f"clipboard_{item.item_id}{ext}",
                                "size_bytes": item.size_bytes,
                                "mime_type": item.mime_type or "image/png",
                                "sha256": item.sha256,
                                "path": resolved,
                            }
                        ]
                    return []
                if item.content_type in ("file", "file_bundle"):
                    entries: List[Dict[str, Any]] = []
                    for idx, entry in enumerate(item.file_manifest):
                        resolved = self._resolve_stored_file_locked(entry.get("stored_filename"))
                        if resolved is None:
                            return []
                        entries.append(
                            {
                                "index": idx,
                                "name": entry["name"],
                                "size_bytes": entry["size_bytes"],
                                "mime_type": entry["mime_type"],
                                "sha256": entry["sha256"],
                                "path": resolved,
                            }
                        )
                    return entries
            return []

    def get_persisted_media_bytes(self) -> int:
        """Return aggregate bytes of all currently retained persisted media items."""
        with self._lock:
            return sum(item.media_bytes() for item in self._items)

    def get_eligible_apply_item(
        self,
        peer_device_id: str,
        last_acked_seq: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Return ONLY the latest item if it is strictly newer than ack and not originated by peer."""
        with self._lock:
            if not self._items:
                return None
            latest = self._items[0]
            if latest.source_device_id == peer_device_id:
                return None
            if latest.event_id in self._synced_events and peer_device_id in self._synced_events[latest.event_id]:
                return None
            effective_ack = last_acked_seq
            if effective_ack is None and self.db_manager and hasattr(self.db_manager, "get_clipboard_ack"):
                ack_rec = self.db_manager.get_clipboard_ack(peer_device_id)
                if ack_rec is not None:
                    effective_ack = ack_rec["last_acked_seq"]
            baseline_ack = 0 if effective_ack is None else effective_ack
            if latest.seq <= baseline_ack:
                return None
            return latest.to_metadata()

    def _find_recent_duplicate_locked(
        self,
        content_type: str,
        digest: str,
        now: float,
        canonical_digest: Optional[str] = None,
    ) -> Optional[int]:
        """Find matching item within the debounce window (returns index or None)."""
        for idx, item in enumerate(self._items):
            if item.content_type != content_type:
                continue
            matched = item.sha256 == digest
            if not matched and content_type == "image" and canonical_digest:
                item_canonical = item.canonical_sha256
                if not item_canonical and item.image_path and is_contained_non_symlink(item.image_path, self.storage_dir):
                    try:
                        from snow.capabilities.windows.clipboard import compute_canonical_image_digest

                        item_canonical, _, _ = compute_canonical_image_digest(item.image_path.read_bytes())
                        item.canonical_sha256 = item_canonical
                    except Exception:
                        item_canonical = None
                if item_canonical and item_canonical == canonical_digest:
                    matched = True
            if matched:
                if (now - item.timestamp) <= self.debounce_seconds:
                    return idx
                return None
        return None

    def add_text(
        self,
        text: str,
        source_device_id: str = "desktop_windows",
        source_device_name: str = "Windows PC",
        pin: bool = False,
        event_id: Optional[str] = None,
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
        to_unlink: List[Path] = []

        with self._lock:
            now = time.time()
            existing_idx = self._find_recent_duplicate_locked("text", digest, now)
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
                self._synced_events.setdefault(existing.event_id, set()).add(source_device_id)
                self._persist_item_locked(existing)
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

            ok, status_code, evict_indices = self._plan_eviction_locked(new_media_bytes=0, adding_new_slot=True)
            if not ok:
                return {
                    "success": False,
                    "status": status_code,
                    "error": "Clipboard buffer is full and all entries are pinned. Unpin an entry to add new items.",
                }

            removed = self._commit_eviction_locked(evict_indices)
            preview = text.strip().replace("\r\n", " ").replace("\n", " ").replace("\t", " ")
            if len(preview) > MAX_PREVIEW_CHARS:
                preview = preview[:MAX_PREVIEW_CHARS].rstrip() + "..."
            if not preview:
                preview = "[Empty text]"

            item_id = f"cb_{digest[:12]}_{uuid.uuid4().hex[:6]}"
            resolved_event_id = str(event_id).strip() if event_id else str(uuid.uuid4())
            seq = self._next_seq_locked()

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
                event_id=resolved_event_id,
                seq=seq,
            )

            self._items.insert(0, item)
            self._synced_devices.setdefault(digest, set()).add(source_device_id)
            self._synced_events.setdefault(item.event_id, set()).add(source_device_id)
            self._persist_item_locked(item)
            to_unlink = self._collect_unreferenced_paths_locked(removed)
            meta = item.to_metadata()

        self._unlink_paths(to_unlink)
        return {
            "success": True,
            "status": "ADDED",
            "item": meta,
            "deduplicated": False,
        }

    def add_image(
        self,
        image_bytes: bytes,
        mime_type: Optional[str] = None,
        source_device_id: str = "desktop_windows",
        source_device_name: str = "Windows PC",
        pin: bool = False,
        event_id: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Add image media content (PNG or JPEG) to the shared buffer."""
        if "source_device" in kwargs:
            source_device_id = kwargs["source_device"]
        if "is_pinned" in kwargs:
            pin = bool(kwargs["is_pinned"])
        if not isinstance(image_bytes, (bytes, bytearray)):
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "Image data must be bytes."}

        raw = bytes(image_bytes)
        size = len(raw)
        if size <= 0:
            return {"success": False, "status": "INVALID_IMAGE_FORMAT", "error": "Image payload cannot be empty."}
        if size > MAX_IMAGE_BYTES:
            return {
                "success": False,
                "status": "CONTENT_TOO_LARGE",
                "error": f"Image size ({size} bytes) exceeds maximum limit of {MAX_IMAGE_BYTES} bytes (15 MiB).",
            }

        ext: str
        detected_mime: str
        if raw.startswith(PNG_SIGNATURE):
            ext = "png"
            detected_mime = "image/png"
        elif raw.startswith(JPEG_SIGNATURE):
            ext = "jpg"
            detected_mime = "image/jpeg"
        else:
            return {
                "success": False,
                "status": "INVALID_IMAGE_FORMAT",
                "error": "Only valid PNG and JPEG images are supported by the clipboard buffer.",
            }

        digest = hashlib.sha256(raw).hexdigest()
        from snow.capabilities.windows.clipboard import compute_canonical_image_digest

        canonical_digest, img_w, img_h = compute_canonical_image_digest(raw)
        to_unlink: List[Path] = []

        with self._lock:
            now = time.time()
            existing_idx = self._find_recent_duplicate_locked(
                "image",
                digest,
                now,
                canonical_digest=canonical_digest,
            )
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
                self._synced_events.setdefault(existing.event_id, set()).add(source_device_id)
                self._persist_item_locked(existing)
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

            ok, status_code, evict_indices = self._plan_eviction_locked(new_media_bytes=size, adding_new_slot=True)
            if not ok:
                err_msg = (
                    "Clipboard buffer is full and all entries are pinned. Unpin an entry to add new items."
                    if status_code == "BUFFER_FULL_ALL_PINNED"
                    else f"Cannot fit image within {self.max_media_bytes} byte persisted media budget while all blockers are pinned."
                )
                return {"success": False, "status": status_code, "error": err_msg}

            filename = f"clip_{digest[:16]}_{uuid.uuid4().hex[:8]}.{ext}"
            target_path = (self.storage_dir / filename).resolve()
            if not target_path.is_relative_to(self.storage_dir):
                return {"success": False, "status": "SECURITY_ERROR", "error": "Storage path escape detected."}

            try:
                target_path.write_bytes(raw)
            except Exception as exc:
                logger.error("Failed saving clipboard image: %s", exc)
                return {"success": False, "status": "IO_ERROR", "error": f"Could not write image to disk: {exc}"}

            removed = self._commit_eviction_locked(evict_indices)
            size_kb = size / 1024
            preview = f"{ext.upper()} Image ({size_kb:.1f} KiB)"
            item_id = f"cb_{digest[:12]}_{uuid.uuid4().hex[:6]}"
            resolved_event_id = str(event_id).strip() if event_id else str(uuid.uuid4())
            seq = self._next_seq_locked()

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
                canonical_sha256=canonical_digest,
                width=img_w,
                height=img_h,
                event_id=resolved_event_id,
                seq=seq,
            )

            self._items.insert(0, item)
            self._synced_devices.setdefault(digest, set()).add(source_device_id)
            self._synced_events.setdefault(item.event_id, set()).add(source_device_id)
            self._persist_item_locked(item)
            to_unlink = self._collect_unreferenced_paths_locked(removed)
            meta = item.to_metadata()

        self._unlink_paths(to_unlink)
        return {
            "success": True,
            "status": "ADDED",
            "item": meta,
            "deduplicated": False,
        }

    def add_files(
        self,
        files: Sequence[Dict[str, Any]],
        source_device_id: str = "desktop_windows",
        source_device_name: str = "Windows PC",
        pin: bool = False,
        event_id: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Add 1..5 regular files (<= 15 MiB total) to the shared buffer."""
        if "source_device" in kwargs:
            source_device_id = kwargs["source_device"]
        if "is_pinned" in kwargs:
            pin = bool(kwargs["is_pinned"])

        if not isinstance(files, Sequence) or isinstance(files, (str, bytes, bytearray)):
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "files must be a non-empty list."}
        if len(files) == 0:
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "At least one file is required."}
        if len(files) > MAX_BUNDLE_FILES:
            return {
                "success": False,
                "status": "TOO_MANY_FILES",
                "error": f"Clipboard file bundle supports at most {MAX_BUNDLE_FILES} files (got {len(files)}).",
            }

        staged_entries: List[Dict[str, Any]] = []
        total_size = 0

        for idx, spec in enumerate(files):
            if not isinstance(spec, dict):
                return {"success": False, "status": "INVALID_ARGUMENT", "error": f"File entry {idx} must be a dict."}

            src_path_raw = spec.get("source_path")
            raw_data = spec.get("data")
            raw_name = spec.get("name")

            if raw_name is None and src_path_raw is not None:
                raw_name = Path(src_path_raw).name

            try:
                safe_name = sanitize_manifest_filename(raw_name)
            except ValueError as name_err:
                return {"success": False, "status": "SECURITY_ERROR", "error": str(name_err)}

            if raw_data is not None:
                if not isinstance(raw_data, (bytes, bytearray)):
                    return {"success": False, "status": "INVALID_ARGUMENT", "error": "File data must be bytes."}
                file_bytes = bytes(raw_data)
            elif src_path_raw is not None:
                src_path = Path(src_path_raw)
                if _is_reparse_or_symlink(src_path):
                    return {
                        "success": False,
                        "status": "SECURITY_ERROR",
                        "error": f"Rejected symlink or junction path: {safe_name}",
                    }
                for p_ancestor in src_path.parents:
                    if p_ancestor != src_path.anchor and _is_reparse_or_symlink(p_ancestor):
                        return {
                            "success": False,
                            "status": "SECURITY_ERROR",
                            "error": f"Rejected path traversing symlink/junction: {safe_name}",
                        }
                try:
                    resolved_src = src_path.resolve(strict=True)
                except OSError:
                    return {"success": False, "status": "FILE_NOT_FOUND", "error": f"File not found: {safe_name}"}
                if resolved_src.is_dir() or not resolved_src.is_file():
                    return {
                        "success": False,
                        "status": "INVALID_FILE_TYPE",
                        "error": f"Directories and special files are not permitted: {safe_name}",
                    }
                try:
                    src_size = resolved_src.stat().st_size
                except OSError as st_err:
                    return {"success": False, "status": "IO_ERROR", "error": f"Cannot stat file {safe_name}: {st_err}"}
                if src_size > MAX_FILE_BYTES:
                    return {
                        "success": False,
                        "status": "CONTENT_TOO_LARGE",
                        "error": f"File '{safe_name}' exceeds {MAX_FILE_BYTES} bytes (15 MiB).",
                    }
                try:
                    file_bytes = resolved_src.read_bytes()
                except OSError as rd_err:
                    return {"success": False, "status": "IO_ERROR", "error": f"Cannot read file {safe_name}: {rd_err}"}
            else:
                return {
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": f"File entry '{safe_name}' requires 'data' or 'source_path'.",
                }

            file_size = len(file_bytes)
            if file_size > MAX_FILE_BYTES:
                return {
                    "success": False,
                    "status": "CONTENT_TOO_LARGE",
                    "error": f"File '{safe_name}' ({file_size} bytes) exceeds 15 MiB limit.",
                }
            total_size += file_size
            if total_size > MAX_BUNDLE_BYTES:
                return {
                    "success": False,
                    "status": "CONTENT_TOO_LARGE",
                    "error": f"Aggregate bundle size exceeds maximum limit of {MAX_BUNDLE_BYTES} bytes (15 MiB).",
                }

            file_mime = str(
                spec.get("mime_type") or mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
            ).strip()
            if not _MIME_TYPE_RE.fullmatch(file_mime):
                file_mime = "application/octet-stream"

            file_sha256 = hashlib.sha256(file_bytes).hexdigest()
            staged_entries.append(
                {
                    "name": safe_name,
                    "size_bytes": file_size,
                    "mime_type": file_mime,
                    "sha256": file_sha256,
                    "data": file_bytes,
                }
            )

        content_type = "file" if len(staged_entries) == 1 else "file_bundle"
        manifest_digest_payload = json.dumps(
            [[e["name"], e["size_bytes"], e["sha256"]] for e in staged_entries],
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(manifest_digest_payload).hexdigest()
        to_unlink: List[Path] = []

        with self._lock:
            now = time.time()
            existing_idx = self._find_recent_duplicate_locked(content_type, digest, now)
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
                self._synced_events.setdefault(existing.event_id, set()).add(source_device_id)
                self._persist_item_locked(existing)
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

            ok, status_code, evict_indices = self._plan_eviction_locked(new_media_bytes=total_size, adding_new_slot=True)
            if not ok:
                err_msg = (
                    "Clipboard buffer is full and all entries are pinned. Unpin an entry to add new items."
                    if status_code == "BUFFER_FULL_ALL_PINNED"
                    else f"Cannot fit files within {self.max_media_bytes} byte persisted media budget while all blockers are pinned."
                )
                return {"success": False, "status": status_code, "error": err_msg}

            written_paths: List[Path] = []
            stored_manifest: List[Dict[str, Any]] = []
            try:
                for e in staged_entries:
                    safe_ext = _safe_extension(e["name"])
                    stored_filename = f"clipfile_{e['sha256'][:16]}_{uuid.uuid4().hex[:8]}{safe_ext}"
                    target_path = (self.storage_dir / stored_filename).resolve()
                    if not target_path.is_relative_to(self.storage_dir):
                        raise ValueError("Storage path escape detected.")
                    target_path.write_bytes(e["data"])
                    written_paths.append(target_path)
                    stored_manifest.append(
                        {
                            "name": e["name"],
                            "size_bytes": e["size_bytes"],
                            "mime_type": e["mime_type"],
                            "sha256": e["sha256"],
                            "stored_filename": stored_filename,
                        }
                    )
            except Exception as exc:
                for p in written_paths:
                    try:
                        p.unlink(missing_ok=True)
                    except OSError:
                        pass
                logger.error("Failed persisting clipboard file bundle: %s", exc)
                return {"success": False, "status": "IO_ERROR", "error": f"Could not write clipboard files: {exc}"}

            removed = self._commit_eviction_locked(evict_indices)
            size_kb = total_size / 1024
            if content_type == "file":
                preview = f"{stored_manifest[0]['name']} ({size_kb:.1f} KiB)"
            else:
                names_summary = ", ".join(m["name"] for m in stored_manifest[:2])
                if len(stored_manifest) > 2:
                    names_summary += ", ..."
                preview = f"{len(stored_manifest)} files ({size_kb:.1f} KiB): {names_summary}"
            if len(preview) > MAX_PREVIEW_CHARS:
                preview = preview[:MAX_PREVIEW_CHARS].rstrip() + "..."

            item_id = f"cb_{digest[:12]}_{uuid.uuid4().hex[:6]}"
            resolved_event_id = str(event_id).strip() if event_id else str(uuid.uuid4())
            seq = self._next_seq_locked()

            item = ClipboardItem(
                item_id=item_id,
                content_type=content_type,
                preview=preview,
                source_device_id=source_device_id,
                source_device_name=source_device_name,
                timestamp=now,
                sha256=digest,
                size_bytes=total_size,
                pinned=pin,
                mime_type=stored_manifest[0]["mime_type"] if content_type == "file" else "application/x-snow-file-bundle",
                event_id=resolved_event_id,
                seq=seq,
                file_manifest=stored_manifest,
            )

            self._items.insert(0, item)
            self._synced_devices.setdefault(digest, set()).add(source_device_id)
            self._synced_events.setdefault(item.event_id, set()).add(source_device_id)
            self._persist_item_locked(item)
            to_unlink = self._collect_unreferenced_paths_locked(removed)
            meta = item.to_metadata()

        self._unlink_paths(to_unlink)
        return {
            "success": True,
            "status": "ADDED",
            "item": meta,
            "deduplicated": False,
        }

    def pin(self, item_id: str) -> Dict[str, Any]:
        """Pin a specific item to protect it from automatic eviction."""
        with self._lock:
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
                    if self.db_manager and hasattr(self.db_manager, "update_clipboard_pinned"):
                        try:
                            self.db_manager.update_clipboard_pinned(item_id, True)
                        except Exception as e:
                            logger.warning("Error updating pinned state in DB: %s", e)
                    return {"success": True, "status": "PINNED", "item": item.to_metadata()}

            return {"success": False, "status": "ITEM_NOT_FOUND", "error": f"Item '{item_id}' not found."}

    def unpin(self, item_id: str) -> Dict[str, Any]:
        """Unpin a specific item."""
        with self._lock:
            for item in self._items:
                if item.item_id == item_id:
                    item.pinned = False
                    if self.db_manager and hasattr(self.db_manager, "update_clipboard_pinned"):
                        try:
                            self.db_manager.update_clipboard_pinned(item_id, False)
                        except Exception as e:
                            logger.warning("Error updating pinned state in DB: %s", e)
                    return {"success": True, "status": "UNPINNED", "item": item.to_metadata()}

            return {"success": False, "status": "ITEM_NOT_FOUND", "error": f"Item '{item_id}' not found."}

    def delete(self, item_id: str) -> Dict[str, Any]:
        """Explicitly delete an item and any associated unreferenced media files."""
        to_unlink: List[Path] = []
        with self._lock:
            for idx, item in enumerate(self._items):
                if item.item_id == item_id:
                    removed = self._items.pop(idx)
                    self._delete_from_db_locked(item_id)
                    to_unlink = self._collect_unreferenced_paths_locked([removed])
                    break
            else:
                return {"success": False, "status": "ITEM_NOT_FOUND", "error": f"Item '{item_id}' not found."}

        self._unlink_paths(to_unlink)
        return {"success": True, "status": "DELETED", "item_id": item_id}

    def clear(self, unpinned_only: bool = True) -> Dict[str, Any]:
        """Clear the clipboard buffer.

        If unpinned_only is True (default), retains pinned items.
        If unpinned_only is False, removes everything (requires explicit owner confirmation).
        """
        to_unlink: List[Path] = []
        with self._lock:
            removed: List[ClipboardItem] = []
            if unpinned_only:
                retained: List[ClipboardItem] = []
                for item in self._items:
                    if item.pinned:
                        retained.append(item)
                    else:
                        removed.append(item)
                self._items = retained
            else:
                removed = list(self._items)
                self._items.clear()
                self._synced_devices.clear()
                self._synced_events.clear()

            if self.db_manager and hasattr(self.db_manager, "clear_clipboard_items"):
                try:
                    self.db_manager.clear_clipboard_items(unpinned_only=unpinned_only)
                except Exception as e:
                    logger.warning("Error clearing items from DB: %s", e)

            to_unlink = self._collect_unreferenced_paths_locked(removed)
            cleared_count = len(removed)
            remaining_count = len(self._items)

        self._unlink_paths(to_unlink)
        return {
            "success": True,
            "status": "CLEARED",
            "cleared_count": cleared_count,
            "remaining_count": remaining_count,
        }

    def has_device_received(self, sha256: str, device_id: str) -> bool:
        """Check if a device has already sent or received this content (echo suppression)."""
        with self._lock:
            return device_id in self._synced_devices.get(sha256, set())

    def mark_device_received(self, sha256: str, device_id: str) -> None:
        """Record that a device has received this content."""
        with self._lock:
            self._synced_devices.setdefault(sha256, set()).add(device_id)

    def has_device_received_event(self, event_id: str, device_id: str) -> bool:
        """Check if a device has already sent or received this specific clipboard event."""
        with self._lock:
            return device_id in self._synced_events.get(event_id, set())

    def mark_device_received_event(self, event_id: str, device_id: str) -> None:
        """Record that a device has received this specific clipboard event."""
        with self._lock:
            self._synced_events.setdefault(event_id, set()).add(device_id)

    def get_device_ack(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve durable per-device acknowledgement record."""
        if not self.db_manager or not hasattr(self.db_manager, "get_clipboard_ack"):
            return None
        with self._lock:
            return self.db_manager.get_clipboard_ack(device_id)

    def record_device_ack(self, device_id: str, last_acked_seq: int, last_acked_event_id: str = "") -> Dict[str, Any]:
        """Persist monotonic per-device acknowledgement and update in-memory event echo cache."""
        with self._lock:
            if last_acked_event_id:
                self._synced_events.setdefault(last_acked_event_id, set()).add(device_id)
            if not self.db_manager or not hasattr(self.db_manager, "save_clipboard_ack"):
                return {
                    "device_id": device_id,
                    "last_acked_seq": last_acked_seq,
                    "last_acked_event_id": last_acked_event_id,
                    "updated": True,
                }
            return self.db_manager.save_clipboard_ack(
                device_id=device_id,
                last_acked_seq=last_acked_seq,
                last_acked_event_id=last_acked_event_id,
            )
