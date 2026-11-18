"""Strictly scoped Windows filesystem capability for SNOW.

Enforces containment within approved root directories (default user home and user folders),
forbids access to credentials, databases, TLS keys, the entire ~/.snow/ state directory,
and Windows system directories, prevents symlink/junction escapes and path traversal,
and enforces bounded file read/write size limits.
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

from snow.security.context import ExecutionContext, ExecutionPrincipal

logger = logging.getLogger(__name__)

DEFAULT_MAX_FILE_BYTES: int = 256 * 1024  # 256 KiB
DEFAULT_LIST_LIMIT: int = 50
MAX_LIST_LIMIT: int = 200
DEFAULT_SEARCH_LIMIT: int = 50
MAX_SEARCH_LIMIT: int = 200
MAX_SEARCH_SCAN_ENTRIES: int = 10000  # Cap directory entries scanned to prevent DoS

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
    ".snow",
    "tls",
    ".parts",
    "windows",
    "system32",
    "program files",
    "program files (x86)",
    "config",
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


def get_default_allowed_roots() -> list[Path]:
    """Resolve default authorized roots for practical user filesystem access.

    Includes the user's home directory and prominent standard user folders
    (Desktop, Documents, Downloads), plus any configured workspace directory.
    """
    home = Path.home().resolve()
    candidates = [
        home,
        (home / "Desktop").resolve(),
        (home / "Documents").resolve(),
        (home / "Downloads").resolve(),
    ]
    roots: list[Path] = []
    for c in candidates:
        if c.exists() and c not in roots:
            roots.append(c)
    if not roots:
        roots.append(home)
    return roots


def get_available_drives() -> list[dict[str, Any]]:
    """Enumerate accessible local filesystem drives and their storage metrics."""
    drives: list[dict[str, Any]] = []
    try:
        import psutil
        for p in psutil.disk_partitions(all=False):
            mount = p.mountpoint
            if not mount.endswith("\\") and sys.platform == "win32":
                mount += "\\"
            drive_info: dict[str, Any] = {"drive": mount}
            try:
                usage = psutil.disk_usage(p.mountpoint)
                drive_info["total_bytes"] = usage.total
                drive_info["free_bytes"] = usage.free
                drive_info["percent_used"] = usage.percent
            except Exception:
                pass
            drives.append(drive_info)
    except Exception:
        # Fallback if psutil fails or on non-Windows test hosts
        for letter in ("C", "D", "E", "F"):
            root = Path(f"{letter}:\\")
            if root.exists():
                drives.append({"drive": f"{letter}:\\"})
    return drives


class WindowsFileManager:
    """Manages strictly scoped, safe filesystem read, write, list, and search operations."""

    def __init__(
        self,
        allowed_roots: Optional[List[Path | str]] = None,
        additional_roots: Optional[List[Path | str]] = None,
    ) -> None:
        valid_roots: list[Path] = []
        if allowed_roots:
            valid_roots.extend([Path(r).resolve() for r in allowed_roots if r is not None])
        else:
            valid_roots.extend(get_default_allowed_roots())

        if additional_roots:
            for extra in additional_roots:
                if extra is not None:
                    p = Path(extra).resolve()
                    if p.exists() and p not in valid_roots:
                        valid_roots.append(p)

        self.allowed_roots = valid_roots

    def _is_forbidden_path(self, resolved: Path) -> bool:
        """Check whether a resolved path matches any forbidden location, name, or extension."""
        name_lower = resolved.name.lower()
        ext_lower = resolved.suffix.lower()

        # Check explicit forbidden filenames or extensions
        if name_lower in FORBIDDEN_NAME_PATTERNS:
            return True
        if ext_lower in FORBIDDEN_EXTENSIONS:
            return True

        # Check path parts for forbidden directory names (including .snow, windows, system32, config)
        for part in resolved.parts:
            part_lower = part.lower().strip()
            if part_lower in FORBIDDEN_DIR_NAMES:
                return True

        # Ensure path does not reside within ~/.snow directory or point to ipc.secret
        home_snow = (Path.home() / ".snow").resolve()
        try:
            if resolved == home_snow or resolved.is_relative_to(home_snow):
                return True
        except Exception:
            pass

        return False

    def _is_private_security_material(self, resolved: Path) -> bool:
        """Check whether a resolved path points to private TLS key or IPC secret.

        CRITICAL SECURITY INVARIANT:
        Private keys and IPC authentication secrets must NEVER be accessible for download
        or reading under ANY circumstance, even for OWNER_MANUAL!
        """
        name_lower = resolved.name.lower()
        if name_lower in ("server.key", "ipc.secret"):
            return True
        home_snow = (Path.home() / ".snow").resolve()
        try:
            if (
                resolved == (home_snow / "tls" / "server.key")
                or resolved == (home_snow / "ipc.secret")
                or resolved == (home_snow / "tls")
            ):
                return True
        except Exception:
            pass
        return False

    def resolve_safe_path(
        self,
        user_path: str,
        must_exist: bool = False,
        ctx: Optional[ExecutionContext] = None,
    ) -> tuple[Optional[Path], Optional[str]]:
        r"""Normalize, validate containment, and resolve a user-supplied path.

        Rules:
        - OWNER_MANUAL: May address any drive root (C:\, D:\, etc.), enter subdirectories,
          move to parent directories, and browse accessible host locations. Private security
          material (server.key, ipc.secret) is strictly blocked.
        - AI_MCP: Strictly constrained to allowed_roots (Home, Desktop, Documents, Downloads),
          rejects path traversal ('..'), and forbids system/configuration directories.

        Returns (resolved_path, None) on success, or (None, error_status) on violation.
        """
        ctx = ctx or ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="default")

        if not user_path or not isinstance(user_path, str) or not user_path.strip():
            # For OWNER_MANUAL default to user home; for AI_MCP default to allowed_roots[0]
            default_root = Path.home().resolve() if ctx.principal == ExecutionPrincipal.OWNER_MANUAL else self.allowed_roots[0]
            return default_root, None

        cleaned = user_path.strip().replace("/", "\\")
        # Normalize bare drive letter specifications (e.g. 'C:' -> 'C:\')
        if re.match(r"^[a-zA-Z]:$", cleaned):
            cleaned = cleaned + "\\"

        # Reject alternate data streams, UNC paths, and device namespaces
        drive_stripped = re.sub(r"^[a-zA-Z]:", "", cleaned)
        if ":" in drive_stripped:
            return None, "PATH_NOT_ALLOWED"
        if cleaned.startswith("\\\\"):
            return None, "PATH_NOT_ALLOWED"
        if "\x00" in cleaned:
            return None, "PATH_NOT_ALLOWED"

        # Check against reserved DOS device names
        raw_parts = Path(cleaned).parts
        for part in raw_parts:
            stem = part.split(".")[0].lower().strip()
            if stem in RESERVED_DEVICE_NAMES:
                return None, "PATH_NOT_ALLOWED"

        # OWNER_MANUAL execution path: unrestricted host access with private credential protection
        if ctx.principal == ExecutionPrincipal.OWNER_MANUAL:
            try:
                if Path(cleaned).is_absolute() or re.match(r"^[a-zA-Z]:", cleaned):
                    candidate = Path(cleaned).resolve()
                else:
                    candidate = (Path.home() / cleaned).resolve()
            except Exception as exc:
                return None, f"INVALID_PATH: {exc}"

            # Invariant: Never expose private cryptographic keys or IPC authentication secrets
            if self._is_private_security_material(candidate):
                logger.warning("Blocked attempt to access private security material: %s", candidate)
                return None, "PATH_NOT_ALLOWED"

            if must_exist and not candidate.exists():
                return None, "PATH_NOT_FOUND"

            return candidate, None

        # AI_MCP execution path: strict sandbox containment
        if ".." in raw_parts:
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
        self,
        directory_path: str = "",
        limit: int = DEFAULT_LIST_LIMIT,
        ctx: Optional[ExecutionContext] = None,
    ) -> dict[str, Any]:
        """Synchronously list immediate children of an approved directory."""
        if not isinstance(limit, int) or limit < 1:
            limit = DEFAULT_LIST_LIMIT
        limit = min(limit, MAX_LIST_LIMIT)

        safe_dir, err_status = self.resolve_safe_path(directory_path, must_exist=True, ctx=ctx)
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
                # For AI_MCP, apply forbidden name filter; for OWNER_MANUAL, protect private keys/secrets
                if ctx and ctx.principal == ExecutionPrincipal.OWNER_MANUAL:
                    if self._is_private_security_material(entry):
                        continue
                else:
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

            # Sort items: directories first (alphabetical by name), then files (alphabetical by name)
            items.sort(key=lambda x: (0 if x["type"] == "directory" else 1, x["name"].lower()))

            is_drive_root = (safe_dir.parent == safe_dir)
            parent_dir = None if is_drive_root else str(safe_dir.parent)
            drives = get_available_drives()

            return {
                "success": True,
                "status": "SUCCESS",
                "directory": str(safe_dir),
                "parent": parent_dir,
                "drives": drives,
                "count": len(items),
                "items": items,
            }
        except (PermissionError, OSError) as exc:
            is_perm = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5
            status = "OS_PERMISSION_DENIED" if is_perm else "FILE_OPERATION_FAILED"
            return {
                "success": False,
                "status": status,
                "error": f"OS permission denied: {exc}" if is_perm else f"Failed listing directory: {exc}",
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "FILE_OPERATION_FAILED",
                "error": f"Failed listing directory: {exc}",
            }

    async def list_files(
        self,
        directory_path: str = "",
        limit: int = DEFAULT_LIST_LIMIT,
        ctx: Optional[ExecutionContext] = None,
    ) -> dict[str, Any]:
        """Asynchronously list directory contents on a worker thread."""
        return await asyncio.to_thread(self.list_files_sync, directory_path, limit, ctx)

    def read_file_sync(
        self,
        file_path: str,
        max_bytes: int = DEFAULT_MAX_FILE_BYTES,
        ctx: Optional[ExecutionContext] = None,
    ) -> dict[str, Any]:
        """Synchronously read a UTF-8 text file within approved roots."""
        safe_path, err_status = self.resolve_safe_path(file_path, must_exist=True, ctx=ctx)
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
        except (PermissionError, OSError) as exc:
            is_perm = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5
            status = "OS_PERMISSION_DENIED" if is_perm else "FILE_OPERATION_FAILED"
            return {
                "success": False,
                "status": status,
                "error": f"OS permission denied: {exc}" if is_perm else f"Failed reading file: {exc}",
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "FILE_OPERATION_FAILED",
                "error": f"Failed reading file: {exc}",
            }

    async def read_file(
        self,
        file_path: str,
        max_bytes: int = DEFAULT_MAX_FILE_BYTES,
        ctx: Optional[ExecutionContext] = None,
    ) -> dict[str, Any]:
        """Asynchronously read file contents on a worker thread."""
        return await asyncio.to_thread(self.read_file_sync, file_path, max_bytes, ctx)

    def write_file_sync(
        self,
        file_path: str,
        content: str,
        overwrite: bool = False,
        max_bytes: int = DEFAULT_MAX_FILE_BYTES,
        ctx: Optional[ExecutionContext] = None,
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

        safe_path, err_status = self.resolve_safe_path(file_path, must_exist=False, ctx=ctx)
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
        except (PermissionError, OSError) as exc:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass
            is_perm = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5
            status = "OS_PERMISSION_DENIED" if is_perm else "FILE_OPERATION_FAILED"
            return {
                "success": False,
                "status": status,
                "error": f"OS permission denied: {exc}" if is_perm else f"Failed writing file: {exc}",
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
        ctx: Optional[ExecutionContext] = None,
    ) -> dict[str, Any]:
        """Asynchronously write file contents on a worker thread."""
        return await asyncio.to_thread(self.write_file_sync, file_path, content, overwrite, max_bytes, ctx)

    def search_files_sync(
        self,
        query: str,
        root_path: str = "",
        limit: int = DEFAULT_SEARCH_LIMIT,
        ctx: Optional[ExecutionContext] = None,
    ) -> dict[str, Any]:
        """Synchronously search files recursively matching a query string or pattern."""
        if not query or not isinstance(query, str) or not query.strip():
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Search query must be a non-empty string.",
                "matches": [],
            }

        if not isinstance(limit, int) or limit < 1:
            limit = DEFAULT_SEARCH_LIMIT
        limit = min(limit, MAX_SEARCH_LIMIT)

        safe_root, err_status = self.resolve_safe_path(root_path, must_exist=True, ctx=ctx)
        if err_status or safe_root is None:
            return {
                "success": False,
                "status": err_status or "PATH_NOT_ALLOWED",
                "error": f"Search root denied or not found: '{root_path}' ({err_status}).",
                "matches": [],
            }

        if not safe_root.is_dir():
            return {
                "success": False,
                "status": "NOT_A_DIRECTORY",
                "error": f"Search root '{root_path}' is not a directory.",
                "matches": [],
            }

        normalized_query = query.strip().lower()
        matches: List[dict[str, Any]] = []
        scanned_count = 0

        try:
            for dirpath, dirnames, filenames in os.walk(safe_root, topdown=True):
                # Prune forbidden directories from traversal in-place
                dirnames[:] = [
                    d for d in dirnames
                    if not d.startswith(".tmp_")
                    and not d.startswith(".")
                    and (
                        not self._is_private_security_material(Path(dirpath) / d)
                        if ctx and ctx.principal == ExecutionPrincipal.OWNER_MANUAL
                        else not self._is_forbidden_path(Path(dirpath) / d)
                    )
                ]

                for fname in filenames:
                    scanned_count += 1
                    if scanned_count > MAX_SEARCH_SCAN_ENTRIES:
                        break

                    if normalized_query in fname.lower():
                        file_path = Path(dirpath) / fname
                        if ctx and ctx.principal == ExecutionPrincipal.OWNER_MANUAL:
                            if self._is_private_security_material(file_path):
                                continue
                        else:
                            if self._is_forbidden_path(file_path):
                                continue

                        try:
                            stat = file_path.stat()
                            mod_iso = datetime.fromtimestamp(
                                stat.st_mtime, tz=timezone.utc
                            ).isoformat()
                            rel_path = str(file_path.relative_to(safe_root))
                            matches.append({
                                "name": fname,
                                "path": rel_path,
                                "full_path": str(file_path),
                                "size_bytes": stat.st_size,
                                "modified_at": mod_iso,
                            })
                            if len(matches) >= limit:
                                break
                        except (OSError, PermissionError):
                            continue

                if len(matches) >= limit or scanned_count > MAX_SEARCH_SCAN_ENTRIES:
                    break

            return {
                "success": True,
                "status": "SUCCESS",
                "query": query,
                "root": str(safe_root),
                "count": len(matches),
                "matches": matches,
            }
        except (PermissionError, OSError) as exc:
            is_perm = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5
            status = "OS_PERMISSION_DENIED" if is_perm else "FILE_OPERATION_FAILED"
            return {
                "success": False,
                "status": status,
                "error": f"OS permission denied: {exc}" if is_perm else f"Error during file search: {exc}",
                "matches": [],
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "FILE_OPERATION_FAILED",
                "error": f"Error during file search: {exc}",
                "matches": [],
            }

    async def search_files(
        self,
        query: str,
        root_path: str = "",
        limit: int = DEFAULT_SEARCH_LIMIT,
        ctx: Optional[ExecutionContext] = None,
    ) -> dict[str, Any]:
        """Asynchronously search files recursively on a worker thread."""
        return await asyncio.to_thread(self.search_files_sync, query, root_path, limit, ctx)
