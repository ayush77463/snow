"""Transfer storage management, safe path resolution, and streaming SHA-256 integrity."""

from __future__ import annotations

import errno
import hashlib
import hmac
import logging
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple
import uuid

logger = logging.getLogger(__name__)

# Bounded chunk size for streaming I/O and digest computation (64 KiB)
CHUNK_SIZE: int = 64 * 1024

FORBIDDEN_TRANSFER_FILENAMES = {"con", "prn", "aux", "nul"}


def get_default_pc_transfer_dir() -> Path:
    """Return the default user-facing destination directory for incoming PC transfers."""
    return (Path.home() / "Downloads" / "SNOW").resolve()


def validate_pc_transfer_dir(path_value: Path | str) -> Path:
    """Validate, create, and verify write access for a configurable PC transfer folder."""
    if not path_value or not isinstance(path_value, (str, Path)):
        raise ValueError("Transfer directory path must be a non-empty string or Path.")

    raw_text = str(path_value).strip()
    if not raw_text:
        raise ValueError("Transfer directory path must not be blank.")

    resolved = Path(raw_text).expanduser().resolve()
    snow_state_dir = (Path.home() / ".snow").resolve()

    # Forbid sensitive internal state directories (clipboard buffer, keys, SQLite DB)
    if resolved == snow_state_dir or (
        resolved.is_relative_to(snow_state_dir)
        and resolved != (snow_state_dir / "transfers").resolve()
    ):
        raise ValueError(f"Cannot set PC transfers directory inside protected state folder '{snow_state_dir}'.")

    # Forbid OS system locations on Windows and POSIX
    forbidden_prefixes = [
        Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve(),
        Path(r"C:\Program Files").resolve(),
        Path(r"C:\Program Files (x86)").resolve(),
    ]
    if sys.platform != "win32":
        forbidden_prefixes.extend([Path("/bin"), Path("/sbin"), Path("/usr"), Path("/etc"), Path("/System")])

    for prefix in forbidden_prefixes:
        if resolved == prefix or resolved.is_relative_to(prefix):
            raise ValueError(f"System directory '{resolved}' is not permitted as a transfer destination.")

    if resolved.exists() and not resolved.is_dir():
        raise ValueError(f"Path '{resolved}' exists and is not a directory.")

    resolved.mkdir(parents=True, exist_ok=True)
    probe = resolved / f".snow_write_probe_{os.getpid()}"
    try:
        probe.write_bytes(b"snow")
        probe.unlink(missing_ok=True)
    except Exception as exc:
        raise PermissionError(f"Transfer directory '{resolved}' is not writable: {exc}") from exc

    return resolved


def resolve_configured_pc_transfer_dir(
    db_manager: Optional[Any] = None,
    explicit_root: Optional[Path | str] = None,
) -> Path:
    """Resolve the active PC transfers directory from config override, SQLite, or ~/Downloads/SNOW."""
    if explicit_root is not None and str(explicit_root).strip():
        return Path(explicit_root).expanduser().resolve()

    if db_manager is not None and hasattr(db_manager, "get_setting"):
        try:
            saved = db_manager.get_setting("pc_transfer_dir", None)
            if isinstance(saved, str) and saved.strip():
                return Path(saved.strip()).expanduser().resolve()
        except Exception as exc:
            logger.debug("Failed reading pc_transfer_dir setting from SQLite: %s", exc)

    return get_default_pc_transfer_dir()


def sanitize_filename(filename: str) -> str:
    """Sanitize a client-supplied filename to prevent path traversal or unsafe characters.

    Strips directory separators, invalid characters, leading/trailing whitespace and dots.
    Raises ValueError if filename is empty, contains only dots, or is invalid.
    """
    if not filename or not isinstance(filename, str):
        raise ValueError("Filename must be a non-empty string.")

    # Remove any directory paths (take basename only)
    base = os.path.basename(filename.replace("\\", "/"))

    # Strip dangerous characters: control characters, null bytes, Windows forbidden chars
    cleaned = re.sub(r'[\x00-\x1f\x7f\\/*?:"<>|]', "", base).strip(". ")
    if not cleaned:
        raise ValueError(f"Filename '{filename}' is invalid or empty after sanitization.")

    # Disallow reserved names or dot traversals
    if cleaned in (".", "..") or cleaned.upper() in (
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
        "LPT1", "LPT2", "LPT3", "LPT4"
    ):
        raise ValueError(f"Filename '{filename}' resolves to a reserved name '{cleaned}'.")

    return cleaned


def compute_stream_sha256(file_path: Path, chunk_size: int = CHUNK_SIZE) -> str:
    """Compute the SHA-256 hexadecimal digest of a file in bounded streaming chunks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def check_free_space(target_dir: Path, required_bytes: int) -> tuple[bool, int]:
    """Check whether target_dir filesystem has at least required_bytes free."""
    if required_bytes <= 0:
        return True, 0
    probe = target_dir
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    usage = shutil.disk_usage(probe)
    return usage.free >= required_bytes, usage.free


def stream_copy_file(
    src_path: Path,
    dest_path: Path,
    chunk_size: int = CHUNK_SIZE,
    expected_sha256: Optional[str] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> str:
    """Stream-copy src_path to dest_path in bounded chunks using an atomic temp .part commit."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_part = dest_path.parent / f".{dest_path.name}.{uuid.uuid4().hex[:8]}.part"
    hasher = hashlib.sha256()
    try:
        with open(src_path, "rb") as src, open(tmp_part, "wb") as dst:
            while True:
                if cancel_check is not None and cancel_check():
                    raise RuntimeError("File stream copy cancelled.")
                chunk = src.read(chunk_size)
                if not chunk:
                    break
                dst.write(chunk)
                hasher.update(chunk)
            dst.flush()
        actual_hash = hasher.hexdigest().lower()
        if expected_sha256 and actual_hash != expected_sha256.strip().lower():
            raise ValueError(
                f"SHA-256 mismatch during stream copy: expected '{expected_sha256}', got '{actual_hash}'."
            )
        os.replace(tmp_part, dest_path)
        return actual_hash
    except Exception:
        try:
            tmp_part.unlink(missing_ok=True)
        except OSError:
            pass
        raise


class TransferStorageManager:
    """Manages storage root, safe path isolation, temporary .part files, and atomic commits."""

    def __init__(self, root_dir: Optional[Path | str] = None) -> None:
        if root_dir is None:
            self.root_dir = (Path.home() / ".snow" / "transfers").resolve()
        else:
            self.root_dir = Path(root_dir).resolve()

        self.parts_dir = (self.root_dir / ".parts").resolve()
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        """Ensure that the root and .parts directories exist with safe permissions."""
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.parts_dir.mkdir(parents=True, exist_ok=True)

    def set_root_dir(self, new_root: Path | str) -> Path:
        """Validate and switch the active transfer destination root cleanly."""
        validated = validate_pc_transfer_dir(new_root)
        self.root_dir = validated
        self.parts_dir = (self.root_dir / ".parts").resolve()
        self._ensure_directories()
        logger.info("TransferStorageManager destination root updated to '%s'.", self.root_dir)
        return self.root_dir

    def check_free_space(self, required_bytes: int) -> tuple[bool, int]:
        """Return (has_enough_space, free_bytes) for transfer root storage."""
        return check_free_space(self.parts_dir if self.parts_dir.exists() else self.root_dir, required_bytes)

    def resolve_destination_path(self, filename: str) -> Path:
        """Resolve a safe destination path within the transfer root.

        Enforces strict boundary isolation:
        - Sanitizes filename.
        - Ensures resolved target is strictly a child of root_dir.
        - Disallows symlink traversal escaping root.
        """
        clean_name = sanitize_filename(filename)
        candidate = (self.root_dir / clean_name).resolve()

        # Enforce containment inside root_dir
        if not candidate.is_relative_to(self.root_dir):
            raise PermissionError(f"Path escape attempt detected for filename: '{filename}'")

        # Disallow symlinks escaping root
        if candidate.is_symlink():
            real_target = candidate.resolve()
            if not real_target.is_relative_to(self.root_dir):
                raise PermissionError("Symlink escape attempt detected.")

        return candidate

    def get_part_path(self, transfer_id: str) -> Path:
        """Return the temporary .part file path for an in-flight transfer."""
        clean_id = re.sub(r"[^a-zA-Z0-9_\-]", "", transfer_id)
        if not clean_id:
            raise ValueError(f"Invalid transfer ID: '{transfer_id}'")
        return (self.parts_dir / f"{clean_id}.part").resolve()

    def check_duplicate(self, filename: str, expected_sha256: str) -> Tuple[bool, bool, Optional[str]]:
        """Check if a completed file with the given name and SHA-256 already exists.

        Returns:
            Tuple[bool, bool, Optional[str]]: (already_exists, is_conflict, existing_sha256)
            - (True, False, hash) if destination exists and has matching SHA-256.
            - (False, True, hash) if destination exists but has different SHA-256.
            - (False, False, None) if destination does not exist.
        """
        clean_expected = expected_sha256.strip().lower()
        try:
            dest_path = self.resolve_destination_path(filename)
        except Exception:
            return (False, False, None)

        if not dest_path.exists() or dest_path.is_dir():
            return (False, False, None)

        # Do not mistake a partial file for a completed duplicate
        if dest_path.name.endswith(".part"):
            return (False, False, None)

        existing_hash = compute_stream_sha256(dest_path)
        if existing_hash == clean_expected:
            return (True, False, existing_hash)
        else:
            return (False, True, existing_hash)

    def atomic_commit(self, part_path: Path, dest_path: Path, expected_sha256: str) -> str:
        """Verify the integrity of the completed .part file and atomically commit to dest_path.

        Args:
            part_path: Path to the completed temporary .part file.
            dest_path: Path to the target final destination file.
            expected_sha256: Expected 64-character hexadecimal SHA-256 digest.

        Returns:
            str: Verified SHA-256 hash.

        Raises:
            ValueError: If part_path does not exist or SHA-256 digest does not match.
            PermissionError: If dest_path escapes root_dir.
        """
        if not part_path.exists():
            raise FileNotFoundError(f"Temporary file '{part_path}' does not exist.")

        # Re-validate destination isolation immediately before committing
        resolved_dest = dest_path.resolve()
        if not resolved_dest.is_relative_to(self.root_dir):
            self.delete_part_file(part_path)
            raise PermissionError(f"Destination '{resolved_dest}' escapes transfer root.")

        # Compute streaming SHA-256 of the complete temporary file
        actual_hash = compute_stream_sha256(part_path)
        clean_expected = expected_sha256.strip().lower()

        if actual_hash != clean_expected:
            # Integrity verification failed: reject and clean up corrupt .part file
            logger.warning(
                "SHA-256 integrity verification failed for '%s'. Expected %s, got %s. Removing corrupt part.",
                dest_path.name,
                clean_expected,
                actual_hash,
            )
            self.delete_part_file(part_path)
            raise ValueError(
                f"SHA-256 integrity mismatch: expected '{clean_expected}', actual '{actual_hash}'."
            )

        # Atomic replacement: replaces existing or creates fresh destination
        try:
            # os.replace is atomic on both POSIX and modern Windows (NTFS)
            os.replace(part_path, resolved_dest)
            logger.info("Successfully committed completed file '%s' (SHA-256: %s)",
                        resolved_dest.name, actual_hash)
            return actual_hash
        except OSError as oex:
            if oex.errno == errno.EXDEV:
                stream_copy_file(part_path, resolved_dest, expected_sha256=clean_expected)
                self.delete_part_file(part_path)
                logger.info("Successfully committed cross-device file '%s' (SHA-256: %s)",
                            resolved_dest.name, actual_hash)
                return actual_hash
            logger.error("Failed to atomically commit '%s' to '%s': %s",
                         part_path, resolved_dest, oex)
            self.delete_part_file(part_path)
            raise
        except Exception as exc:
            logger.error("Failed to atomically commit '%s' to '%s': %s",
                         part_path, resolved_dest, exc)
            self.delete_part_file(part_path)
            raise

    def delete_part_file(self, part_path: Path) -> bool:
        """Safely delete a temporary .part file."""
        try:
            if part_path.exists() and part_path.is_file():
                part_path.unlink()
                return True
        except Exception as exc:
            logger.warning("Failed to delete temporary part file '%s': %s", part_path, exc)
        return False

    def cleanup_stale_parts(
        self, max_age_seconds: float = 86400.0, active_transfer_ids: Optional[Set[str]] = None
    ) -> int:
        """Remove abandoned .part files older than max_age_seconds.

        Protects active transfers whose transfer IDs are in active_transfer_ids.
        Returns the count of cleaned up files.
        """
        active_ids = active_transfer_ids or set()
        now = time.time()
        cleaned_count = 0

        if not self.parts_dir.exists():
            return 0

        for item in self.parts_dir.iterdir():
            if item.is_file() and item.name.endswith(".part"):
                transfer_id = item.name[:-5]
                if transfer_id in active_ids:
                    continue

                try:
                    mtime = item.stat().st_mtime
                    if (now - mtime) > max_age_seconds:
                        item.unlink()
                        cleaned_count += 1
                        logger.info("Cleaned up abandoned partial transfer file '%s'", item.name)
                except Exception as exc:
                    logger.warning("Error inspecting/removing partial file '%s': %s", item, exc)

        return cleaned_count


def _is_reparse_or_symlink_path(path: Path) -> bool:
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


def _conflict_safe_destination(dest_dir: Path, safe_name: str, expected_sha256: str) -> tuple[Path, bool]:
    """Return (final_path, already_exists_with_matching_hash) using conflict-safe naming."""
    resolved_root = dest_dir.resolve()
    base_candidate = (resolved_root / safe_name).resolve()
    if not base_candidate.is_relative_to(resolved_root):
        raise PermissionError(f"Path escape attempt detected for filename '{safe_name}'.")

    if not base_candidate.exists():
        return base_candidate, False
    if not base_candidate.is_dir() and not _is_reparse_or_symlink_path(base_candidate):
        try:
            if hmac.compare_digest(compute_stream_sha256(base_candidate), expected_sha256.lower()):
                return base_candidate, True
        except OSError:
            pass

    stem = Path(safe_name).stem
    suffix = Path(safe_name).suffix
    for idx in range(1, 1000):
        numbered = f"{stem} ({idx}){suffix}"
        candidate = (resolved_root / numbered).resolve()
        if not candidate.is_relative_to(resolved_root):
            raise PermissionError(f"Collision path escape for '{safe_name}'.")
        if not candidate.exists():
            return candidate, False
        if not candidate.is_dir() and not _is_reparse_or_symlink_path(candidate):
            try:
                if hmac.compare_digest(compute_stream_sha256(candidate), expected_sha256.lower()):
                    return candidate, True
            except OSError:
                pass

    raise RuntimeError(f"Exhausted collision-safe names for '{safe_name}'.")


def commit_verified_clipboard_files(
    dest_dir: Path,
    entries: Sequence[Dict[str, Any]],
    max_files: int = 5,
    max_total_bytes: int = 15 * 1024 * 1024,
) -> List[Path]:
    """Stage clipboard files into .parts, verify byte sizes & SHA-256, and commit collision-safely.

    All files in the bundle are verified BEFORE committing any final file or OS clipboard handle.
    """
    if not entries or len(entries) > max_files:
        raise ValueError(f"Clipboard file commit requires 1 to {max_files} entries.")

    resolved_dest_dir = Path(dest_dir).resolve()
    if _is_reparse_or_symlink_path(resolved_dest_dir):
        raise PermissionError("Destination transfer directory cannot be a symlink or junction.")
    resolved_dest_dir.mkdir(parents=True, exist_ok=True)
    parts_dir = (resolved_dest_dir / ".parts").resolve()
    parts_dir.mkdir(parents=True, exist_ok=True)

    staged: List[tuple[Path, str, str]] = []
    total_size = 0

    def _cleanup_parts() -> None:
        for p_path, _, _ in staged:
            try:
                p_path.unlink(missing_ok=True)
            except OSError:
                pass

    try:
        for entry in entries:
            safe_name = sanitize_filename(str(entry.get("name") or ""))
            expected_size = int(entry.get("size_bytes", 0))
            expected_sha256 = str(entry.get("sha256") or "").strip().lower()
            if len(expected_sha256) != 64:
                raise ValueError(f"Missing valid SHA-256 digest for '{safe_name}'.")
            if expected_size < 0 or expected_size > max_total_bytes:
                raise ValueError(f"File '{safe_name}' size ({expected_size}) exceeds 15 MiB limit.")

            part_path = (parts_dir / f"cb_{uuid.uuid4().hex}.part").resolve()
            if not part_path.is_relative_to(parts_dir):
                raise PermissionError("Staging path escape detected.")

            hasher = hashlib.sha256()
            written = 0
            src_path_raw = entry.get("path")
            raw_bytes = entry.get("data")

            if raw_bytes is not None:
                raw_buf = bytes(raw_bytes)
                written = len(raw_buf)
                hasher.update(raw_buf)
                part_path.write_bytes(raw_buf)
            elif src_path_raw is not None:
                src_p = Path(src_path_raw)
                if _is_reparse_or_symlink_path(src_p) or not src_p.is_file():
                    raise ValueError(f"Source file invalid or missing for '{safe_name}'.")
                with open(src_p, "rb") as src_f, open(part_path, "wb") as dst_f:
                    while True:
                        chunk = src_f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        written += len(chunk)
                        total_size += len(chunk)
                        if written > max_total_bytes or total_size > max_total_bytes:
                            raise ValueError("Clipboard file bundle exceeds 15 MiB size limit.")
                        hasher.update(chunk)
                        dst_f.write(chunk)
            else:
                raise ValueError(f"Entry '{safe_name}' missing source data or path.")

            if raw_bytes is not None:
                total_size += written
                if total_size > max_total_bytes:
                    raise ValueError("Clipboard file bundle exceeds 15 MiB size limit.")

            staged.append((part_path, safe_name, expected_sha256))

            actual_sha256 = hasher.hexdigest().lower()
            if written != expected_size or not hmac.compare_digest(actual_sha256, expected_sha256):
                raise ValueError(
                    f"Integrity verification failed for '{safe_name}': expected {expected_sha256} ({expected_size}B), "
                    f"got {actual_sha256} ({written}B)."
                )

        committed_paths: List[Path] = []
        for part_path, safe_name, expected_sha256 in staged:
            final_dest, already_present = _conflict_safe_destination(resolved_dest_dir, safe_name, expected_sha256)
            if already_present:
                part_path.unlink(missing_ok=True)
            else:
                os.replace(part_path, final_dest)
            committed_paths.append(final_dest)

        return committed_paths
    except Exception:
        _cleanup_parts()
        raise
