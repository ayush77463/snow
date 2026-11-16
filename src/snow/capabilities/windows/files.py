"""Strictly scoped Windows filesystem capability for SNOW.

Enforces containment within approved root directories (default ~/.snow/transfers/),
forbids access to credentials, databases, TLS keys, and Windows system directories,
prevents symlink/junction escapes and path traversal, and enforces bounded 256 KiB
file read/write size limits.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger(__name__)

DEFAULT_MAX_FILE_BYTES: int = 256 * 1024  # 256 KiB
DEFAULT_LIST_LIMIT: int = 50
MAX_LIST_LIMIT: int = 200

# Forbidden sensitive filenames, extensions, and directory names
FORBIDDEN_NAME_PATTERNS = {
    "ipc.secret",
    "server.key",
    "server.crt",
    "snow_devices.db",
}

FORBIDDEN_EXTENSIONS = {
    ".secret",
    ".key",
    ".pem",
    ".crt",
    ".der",
    ".p12",
    ".pfx",
    ".db",
    ".db-wal",
    ".db-shm",
    ".sqlite",
    ".sqlite3",
}

FORBIDDEN_DIR_NAMES = {
    "tls",
    ".parts",
    "windows",
    "system32",
    "program files",
    "program files (x86)",
}

# Windows reserved DOS device names (e.g. CON, PRN, AUX, NUL, COM1..9, LPT1..9)
RESERVED_DEVICE_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    "com1",
    "com2",
    "com3",
    "com4",
    "com5",
    "com6",
    "com7",
    "com8",
    "com9",
    "lpt1",
    "lpt2",
    "lpt3",
    "lpt4",
    "lpt5",
    "lpt6",
    "lpt7",
    "lpt8",
    "lpt9",
}


class WindowsFileManager:
    """Manages strictly scoped, safe filesystem read, write, and list operations."""

    def __init__(self, allowed_roots: Optional[List[Path | str]] = None) -> None:
        valid_roots = [Path(r).resolve() for r in (allowed_roots or []) if r is not None]
        if valid_roots:
            self.allowed_roots = valid_roots
        else:
            default_root = (Path.home() / ".snow" / "transfers").resolve()
            default_root.mkdir(parents=True, exist_ok=True)
            self.allowed_roots = [default_root]

    def _is_forbidden_path(self, resolved: Path) -> bool:
        """Check whether a resolved path matches any forbidden location, name, or extension."""
        name_lower = resolved.name.lower()
        ext_lower = resolved.suffix.lower()

        # Check explicit forbidden filenames or extensions
        if name_lower in FORBIDDEN_NAME_PATTERNS:
            return True
        if ext_lower in FORBIDDEN_EXTENSIONS:
            return True

        # Check path parts for forbidden directory names
        for part in resolved.parts:
            part_lower = part.lower().strip()
            if part_lower in FORBIDDEN_DIR_NAMES:
                return True

        # Ensure path does not reside within ~/.snow/tls or point to ipc.secret
        home_snow = (Path.home() / ".snow").resolve()
        if (home_snow / "tls").resolve() in resolved.parents or resolved == (home_snow / "tls").resolve():
            return True
        if resolved == (home_snow / "ipc.secret").resolve():
            return True

        return False

    def resolve_safe_path(
        self, user_path: str, must_exist: bool = False
    ) -> tuple[Optional[Path], Optional[str]]:
        """Normalize, validate containment, and resolve a user-supplied path.

        Returns (resolved_path, None) on success, or (None, error_status) on violation.
        """
        if not user_path or not isinstance(user_path, str):
            # Treat empty string as default root directory
            return self.allowed_roots[0], None

        cleaned = user_path.strip().replace("/", "\\")

        # Reject alternate data streams, UNC paths, and device namespaces
        drive_stripped = re.sub(r"^[a-zA-Z]:", "", cleaned)
        if ":" in drive_stripped:
            return None, "PATH_NOT_ALLOWED"
        if cleaned.startswith("\\\\"):
            return None, "PATH_NOT_ALLOWED"
        if "\x00" in cleaned:
            return None, "PATH_NOT_ALLOWED"

        # Check against path traversal components and reserved DOS device names
        raw_parts = Path(cleaned).parts
        if ".." in raw_parts:
            return None, "PATH_NOT_ALLOWED"

        for part in raw_parts:
            stem = part.split(".")[0].lower().strip()
            if stem in RESERVED_DEVICE_NAMES:
                return None, "PATH_NOT_ALLOWED"

        # Attempt to resolve against each allowed root
        candidate: Optional[Path] = None
        for root in self.allowed_roots:
            try:
                # If user passed absolute path matching root, or relative path
                if Path(cleaned).is_absolute():
                    resolved = Path(cleaned).resolve()
                else:
                    resolved = (root / cleaned).resolve()

                # Verify strict containment inside root
                if resolved == root or resolved.is_relative_to(root):
                    # Check for symlink/junction escape
                    try:
                        real_target = resolved.resolve(strict=False)
                        if not real_target.is_relative_to(root):
                            return None, "PATH_NOT_ALLOWED"
                    except Exception:
                        return None, "PATH_NOT_ALLOWED"

                    candidate = resolved
                    break
            except Exception:
                continue

        if candidate is None:
            return None, "PATH_NOT_ALLOWED"

        # Check forbidden names, extensions, and directory rules
        if self._is_forbidden_path(candidate):
            return None, "PATH_NOT_ALLOWED"

        if must_exist and not candidate.exists():
            return None, "PATH_NOT_FOUND"

        return candidate, None

    def list_files_sync(
        self, directory_path: str = "", limit: int = DEFAULT_LIST_LIMIT
    ) -> dict[str, Any]:
        """Synchronously list immediate children of an approved directory."""
        if not isinstance(limit, int) or limit < 1:
            limit = DEFAULT_LIST_LIMIT
        limit = min(limit, MAX_LIST_LIMIT)

        safe_dir, err_status = self.resolve_safe_path(directory_path, must_exist=True)
        if err_status:
            return {
                "success": False,
                "status": err_status,
                "error": f"Directory access denied or not found: '{directory_path}' ({err_status}).",
            }

        if safe_dir is None or not safe_dir.is_dir():
            return {
                "success": False,
                "status": "NOT_A_DIRECTORY",
                "error": f"Path '{directory_path}' is not a directory.",
            }

        items: List[dict[str, Any]] = []
        try:
            for entry in safe_dir.iterdir():
                if len(items) >= limit:
                    break

                # Skip hidden/temporary items or forbidden names
                name_lower = entry.name.lower()
                if name_lower.startswith(".tmp_") or name_lower == ".parts":
                    continue
                if self._is_forbidden_path(entry):
                    continue

                try:
                    stat = entry.stat()
                    mod_iso = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                    items.append({
                        "name": entry.name,
                        "type": "directory" if entry.is_dir() else "file",
                        "size_bytes": stat.st_size if entry.is_file() else 0,
                        "modified_at": mod_iso,
                    })
                except (OSError, PermissionError):
                    continue

            return {
                "success": True,
                "status": "SUCCESS",
                "directory": str(safe_dir.name),
                "count": len(items),
                "items": items,
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "FILE_OPERATION_FAILED",
                "error": f"Failed listing directory: {exc}",
            }

    async def list_files(
        self, directory_path: str = "", limit: int = DEFAULT_LIST_LIMIT
    ) -> dict[str, Any]:
        """Asynchronously list directory contents on a worker thread."""
        return await asyncio.to_thread(self.list_files_sync, directory_path, limit)

    def read_file_sync(
        self, file_path: str, max_bytes: int = DEFAULT_MAX_FILE_BYTES
    ) -> dict[str, Any]:
        """Synchronously read a UTF-8 text file within approved roots."""
        safe_path, err_status = self.resolve_safe_path(file_path, must_exist=True)
        if err_status:
            return {
                "success": False,
                "status": err_status,
                "error": f"File access denied or not found: '{file_path}' ({err_status}).",
            }

        if safe_path is None or not safe_path.is_file():
            return {
                "success": False,
                "status": "NOT_A_FILE",
                "error": f"Path '{file_path}' is not a regular file.",
            }

        try:
            stat = safe_path.stat()
            if stat.st_size > max_bytes:
                return {
                    "success": False,
                    "status": "FILE_TOO_LARGE",
                    "error": (
                        f"File size ({stat.st_size} bytes) exceeds maximum "
                        f"allowed read size ({max_bytes} bytes)."
                    ),
                }

            content = safe_path.read_text(encoding="utf-8")
            return {
                "success": True,
                "status": "SUCCESS",
                "name": safe_path.name,
                "size_bytes": stat.st_size,
                "content": content,
            }
        except UnicodeDecodeError:
            return {
                "success": False,
                "status": "INVALID_ENCODING",
                "error": f"File '{safe_path.name}' is binary or not valid UTF-8 text.",
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "FILE_OPERATION_FAILED",
                "error": f"Failed reading file: {exc}",
            }

    async def read_file(
        self, file_path: str, max_bytes: int = DEFAULT_MAX_FILE_BYTES
    ) -> dict[str, Any]:
        """Asynchronously read file contents on a worker thread."""
        return await asyncio.to_thread(self.read_file_sync, file_path, max_bytes)

    def write_file_sync(
        self,
        file_path: str,
        content: str,
        overwrite: bool = False,
        max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    ) -> dict[str, Any]:
        """Synchronously write UTF-8 text content atomically within approved roots."""
        if not isinstance(content, str):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "File content must be a string.",
            }

        raw_bytes = content.encode("utf-8")
        if len(raw_bytes) > max_bytes:
            return {
                "success": False,
                "status": "FILE_TOO_LARGE",
                "error": f"Content size ({len(raw_bytes)} bytes) exceeds maximum limit ({max_bytes} bytes).",
            }

        safe_path, err_status = self.resolve_safe_path(file_path, must_exist=False)
        if err_status:
            return {
                "success": False,
                "status": err_status,
                "error": f"Target path denied: '{file_path}' ({err_status}).",
            }

        if safe_path is None:
            return {
                "success": False,
                "status": "PATH_NOT_ALLOWED",
                "error": "Unable to resolve a safe target path.",
            }

        if safe_path.exists() and not overwrite:
            return {
                "success": False,
                "status": "FILE_ALREADY_EXISTS",
                "error": f"File '{safe_path.name}' already exists. Pass overwrite=True to replace.",
            }

        # Atomic write pattern: write to .tmp_<uuid> and atomic rename
        tmp_name = f".tmp_{uuid.uuid4().hex}_{safe_path.name}"
        tmp_path = safe_path.parent / tmp_name

        try:
            safe_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.write_bytes(raw_bytes)
            os.replace(tmp_path, safe_path)
            return {
                "success": True,
                "status": "SUCCESS",
                "name": safe_path.name,
                "bytes_written": len(raw_bytes),
                "message": f"Successfully wrote {len(raw_bytes)} bytes to '{safe_path.name}'.",
            }
        except Exception as exc:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass
            return {
                "success": False,
                "status": "FILE_OPERATION_FAILED",
                "error": f"Failed writing file: {exc}",
            }

    async def write_file(
        self,
        file_path: str,
        content: str,
        overwrite: bool = False,
        max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    ) -> dict[str, Any]:
        """Asynchronously write file contents on a worker thread."""
        return await asyncio.to_thread(self.write_file_sync, file_path, content, overwrite, max_bytes)
