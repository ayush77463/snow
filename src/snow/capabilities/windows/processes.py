"""Read-only Windows process monitoring capability for SNOW.

Provides safe enumeration of running processes with CPU and memory utilization.
Strictly read-only: no process termination, killing, suspension, or modification.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

import psutil

logger = logging.getLogger(__name__)

DEFAULT_PROCESS_LIMIT: int = 25
MAX_PROCESS_LIMIT: int = 100
ALLOWED_SORT_KEYS = {"memory", "cpu", "name"}


class WindowsProcessMonitor:
    """Provides read-only inspection of active Windows processes."""

    def list_processes_sync(
        self, limit: int = DEFAULT_PROCESS_LIMIT, sort_by: str = "memory"
    ) -> dict[str, Any]:
        """Synchronously enumerate active processes with bounded limits and sorting.

        Args:
            limit: Maximum process records to return (1 to 100).
            sort_by: Metric to sort descending ('memory', 'cpu', or 'name').

        Returns:
            Structured dictionary with process list and total count.
        """
        # Validate limit
        if not isinstance(limit, int) or isinstance(limit, bool):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": f"Process limit must be an integer, got {type(limit).__name__}.",
            }

        if not (1 <= limit <= MAX_PROCESS_LIMIT):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": f"Process limit must be between 1 and {MAX_PROCESS_LIMIT}, got {limit}.",
            }

        sort_key = (sort_by or "memory").strip().lower()
        if sort_key not in ALLOWED_SORT_KEYS:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": f"Invalid sort_by '{sort_by}'. Must be one of {sorted(ALLOWED_SORT_KEYS)}.",
            }

        process_records: List[dict[str, Any]] = []

        # Iterate over active processes capturing strictly safe attributes
        for p in psutil.process_iter(
            attrs=["pid", "name", "cpu_percent", "memory_info", "status"],
            ad_value=None,
        ):
            try:
                info = p.info
                pid = info.get("pid")
                if pid is None:
                    continue

                name = info.get("name") or "unknown"
                status = info.get("status") or "unknown"

                cpu_pct = info.get("cpu_percent")
                if cpu_pct is None or cpu_pct < 0.0:
                    cpu_pct = 0.0

                mem_info = info.get("memory_info")
                if mem_info:
                    mem_mb = round(mem_info.rss / (1024 * 1024), 2)
                else:
                    mem_mb = 0.0

                process_records.append({
                    "pid": pid,
                    "name": name,
                    "cpu_percent": float(cpu_pct),
                    "memory_mb": float(mem_mb),
                    "status": str(status),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as exc:
                logger.debug("Skipping process during iteration: %s", exc)
                continue

        # Sort according to requested metric descending
        if sort_key == "memory":
            process_records.sort(key=lambda x: x["memory_mb"], reverse=True)
        elif sort_key == "cpu":
            process_records.sort(key=lambda x: x["cpu_percent"], reverse=True)
        elif sort_key == "name":
            process_records.sort(key=lambda x: x["name"].lower())

        sliced = process_records[:limit]

        return {
            "success": True,
            "status": "SUCCESS",
            "count": len(sliced),
            "total_enumerated": len(process_records),
            "sort_by": sort_key,
            "processes": sliced,
        }

    async def list_processes(
        self, limit: int = DEFAULT_PROCESS_LIMIT, sort_by: str = "memory"
    ) -> dict[str, Any]:
        """Asynchronously enumerate processes on a worker thread."""
        return await asyncio.to_thread(self.list_processes_sync, limit, sort_by)
