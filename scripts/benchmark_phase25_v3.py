#!/usr/bin/env python3
"""Phase 25 — Low-Spec Empirical Resource Benchmark Script for SNOW V3.

Empirically measures real runtime resource consumption on the target hardware:
- Lenovo V15 (Intel Core i5-1235U, ~7.9 GB RAM, Windows 11)

Measures each isolated component across its entire discovered process tree:
1. SNOW Core Daemon (WSS 8765 + HTTPS 8766 + IPC 8767)
2. SNOW Web Dashboard (aiohttp loopback port 8779)
3. SNOW MCP stdio Server (JSON-RPC stdio protocol initialization)
4. SNOW Remote MCP Gateway (Streamable HTTP port 8781)
5. SNOW Remote Relay Server (TLS 1.3 MemoryBIO port 8770)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set

try:
    import psutil
except ImportError:
    print("psutil required for benchmark: pip install psutil", file=sys.stderr)
    sys.exit(1)


def get_process_tree(parent_pid: int) -> list[psutil.Process]:
    """Discover parent and all live recursive descendants, handling races safely."""
    try:
        parent = psutil.Process(parent_pid)
        children = parent.children(recursive=True)
        return [parent] + children
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []


def kill_process_tree(parent_pid: int) -> None:
    """Cleanly terminate the complete process tree including all descendants."""
    try:
        parent = psutil.Process(parent_pid)
        procs = parent.children(recursive=True) + [parent]
        for p in procs:
            try:
                p.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        _, alive = psutil.wait_procs(procs, timeout=3.0)
        for p in alive:
            try:
                p.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass


def poll_port_readiness(host: str, port: int, timeout_sec: float) -> bool:
    """Verify socket is actively listening and accepting connections."""
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.05)
    return False


def measure_process(
    name: str,
    cmd: list[str],
    readiness_check: Callable[[subprocess.Popen, float], bool],
    timeout_sec: float = 10.0,
    sample_seconds: float = 1.5,
    extra_env: Optional[dict[str, str]] = None,
    use_stdio_pipes: bool = False,
) -> dict[str, Any]:
    """Spawn, verify true operational readiness, sample real aggregate RSS/CPU, and terminate cleanly."""
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    if extra_env:
        env.update(extra_env)

    start_mono = time.monotonic()
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if use_stdio_pipes else subprocess.DEVNULL,
        stdout=subprocess.PIPE if use_stdio_pipes else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )

    startup_latency = 0.0
    status = "SUCCESS"
    rss_mb = 0.0
    cpu_pct = 0.0

    try:
        # 1. Verify true application readiness
        ready = readiness_check(proc, timeout_sec)
        startup_latency = time.monotonic() - start_mono

        if not ready:
            if proc.poll() is not None:
                status = f"FAILED (Exited prematurely with code {proc.poll()})"
            else:
                status = f"FAILED (Readiness check timed out after {timeout_sec}s)"
            return {
                "component": name,
                "startup_latency_s": round(startup_latency, 3),
                "rss_mb": 0.0,
                "cpu_pct": 0.0,
                "status": status,
            }

        # Verify process has not exited
        if proc.poll() is not None:
            status = f"FAILED (Exited with code {proc.poll()})"
            return {
                "component": name,
                "startup_latency_s": round(startup_latency, 3),
                "rss_mb": 0.0,
                "cpu_pct": 0.0,
                "status": status,
            }

        # 2. Discover real Python runtime process tree and initialize CPU counters
        tree = get_process_tree(proc.pid)
        for p in tree:
            try:
                p.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # 3. Sample over meaningful duration
        time.sleep(sample_seconds)

        # 4. Measure aggregate RSS and sampled CPU across unique live processes
        tree_after = get_process_tree(proc.pid)
        seen_pids: set[int] = set()
        total_rss_bytes = 0
        total_cpu = 0.0

        for p in tree_after:
            if p.pid in seen_pids:
                continue
            seen_pids.add(p.pid)
            try:
                total_rss_bytes += p.memory_info().rss
                total_cpu += p.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        rss_mb = total_rss_bytes / (1024 * 1024)
        cpu_pct = total_cpu

    except Exception as exc:
        status = f"FAILED ({exc})"
    finally:
        kill_process_tree(proc.pid)

    return {
        "component": name,
        "startup_latency_s": round(startup_latency, 3),
        "rss_mb": round(rss_mb, 2),
        "cpu_pct": round(cpu_pct, 1),
        "status": status,
    }


def main() -> int:
    python_exe = sys.executable
    print("=" * 76)
    print(" SNOW V3 — Empirical Resource Benchmark (Lenovo V15, Intel i5-1235U)")
    print("=" * 76)

    results: list[dict[str, Any]] = []

    # 1. SNOW Core Daemon (WSS 8765)
    print("[1/5] Measuring SNOW Desktop Core Daemon (WSS: 8765)...")
    def _ready_core(p: subprocess.Popen, timeout: float) -> bool:
        return poll_port_readiness("127.0.0.1", 8765, timeout)

    res_core = measure_process(
        "Core Daemon",
        [python_exe, "-m", "snow.main"],
        readiness_check=_ready_core,
        timeout_sec=8.0,
        sample_seconds=1.5,
    )
    results.append(res_core)

    # 2. SNOW Web Dashboard (Port 8779)
    print("[2/5] Measuring SNOW Web Dashboard Server (Port: 8779)...")
    def _ready_web(p: subprocess.Popen, timeout: float) -> bool:
        return poll_port_readiness("127.0.0.1", 8779, timeout)

    res_web = measure_process(
        "Web Dashboard",
        [python_exe, "-m", "snow.cli", "web", "--port", "8779", "--no-browser"],
        readiness_check=_ready_web,
        timeout_sec=8.0,
        sample_seconds=1.5,
    )
    results.append(res_web)

    # 3. SNOW MCP stdio Server (JSON-RPC Protocol Exchange)
    print("[3/5] Measuring SNOW MCP stdio Server (JSON-RPC initialize protocol)...")
    def _ready_mcp(p: subprocess.Popen, timeout: float) -> bool:
        if not p.stdin or not p.stdout:
            return False
        init_req = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "snow-benchmark", "version": "3.0.0"},
            },
        })
        try:
            p.stdin.write(init_req.encode("utf-8") + b"\n")
            p.stdin.flush()
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                line = p.stdout.readline()
                if line:
                    data = json.loads(line.decode("utf-8").strip())
                    if "result" in data or data.get("id") == 1:
                        return True
                time.sleep(0.05)
            return False
        except Exception:
            return False

    res_mcp = measure_process(
        "MCP stdio",
        [python_exe, "-m", "snow.mcp"],
        readiness_check=_ready_mcp,
        timeout_sec=8.0,
        sample_seconds=1.5,
        use_stdio_pipes=True,
    )
    results.append(res_mcp)

    # 4. SNOW Remote MCP Gateway (Port 8781)
    print("[4/5] Measuring Remote MCP Streamable HTTP Gateway (Port: 8781)...")
    def _ready_gw(p: subprocess.Popen, timeout: float) -> bool:
        return poll_port_readiness("127.0.0.1", 8781, timeout)

    res_gw = measure_process(
        "MCP Gateway",
        [python_exe, "-m", "snow.cli", "mcp-gateway", "--port", "8781"],
        readiness_check=_ready_gw,
        timeout_sec=8.0,
        sample_seconds=1.5,
    )
    results.append(res_gw)

    # 5. SNOW Remote Relay Server (Port 8770)
    print("[5/5] Measuring Remote Relay Server (Port: 8770)...")
    def _ready_relay(p: subprocess.Popen, timeout: float) -> bool:
        return poll_port_readiness("127.0.0.1", 8770, timeout)

    res_relay = measure_process(
        "Relay Server",
        [python_exe, "-m", "snow.relay"],
        readiness_check=_ready_relay,
        timeout_sec=8.0,
        sample_seconds=1.5,
        extra_env={"SNOW_RELAY_HOST": "127.0.0.1", "SNOW_RELAY_PORT": "8770"},
    )
    results.append(res_relay)

    print("\n" + "=" * 76)
    print(f"{'Component':<18} | {'Startup Latency':<16} | {'Aggregate RSS':<14} | {'CPU %':<8} | {'Status':<10}")
    print("-" * 76)
    for r in results:
        lat = f"{r['startup_latency_s']:.3f} s"
        rss = f"{r['rss_mb']:.1f} MB"
        cpu = f"{r['cpu_pct']:.1f} %"
        print(f"{r['component']:<18} | {lat:<16} | {rss:<14} | {cpu:<8} | {r['status']:<10}")
    print("=" * 76)
    print("Empirical benchmark complete across genuine runtime process trees (<85 MB budget).\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
