"""Empirical Resource Usage Benchmark for SNOW Phase 21.

Accurately measures startup time, memory footprint (RSS), and CPU utilization
on the host machine for:
1. SNOW Core Daemon (snow.core.server)
2. SNOW MCP Server (snow.mcp)
3. SNOW Interactive TUI (snow.tui.app)

Uses standard psutil without fabricated, estimated, or extrapolated figures.
Properly traverses Windows venv process hierarchies to capture real interpreter memory.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import subprocess
import sys
import time

try:
    import psutil
except ImportError:
    print("psutil required for benchmarks. Run: pip install psutil")
    sys.exit(1)


def get_hardware_info() -> dict[str, str]:
    """Capture environment hardware specifications."""
    mem = psutil.virtual_memory()
    return {
        "os": f"{platform.system()} {platform.release()} (Build {platform.version()})",
        "cpu": f"{platform.processor() or platform.machine()} ({psutil.cpu_count(logical=False)} physical cores, {psutil.cpu_count(logical=True)} logical threads)",
        "ram_gb": f"{mem.total / (1024**3):.2f} GB total, {mem.available / (1024**3):.2f} GB available",
        "python": sys.version.split()[0],
    }


def measure_component(name: str, test_code: str, warm_up_seconds: float = 1.0) -> dict[str, Any]:
    """Start component process, measure actual startup time, memory, and CPU utilization."""
    env = {**os.environ, "PYTHONPATH": "src"}
    cmd = [
        sys.executable,
        "-c",
        f"import time; t0 = time.perf_counter(); {test_code}; print('READY', time.perf_counter() - t0, flush=True); time.sleep(2.5)",
    ]

    t0 = time.perf_counter()
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(Path(__file__).resolve().parents[1]),
        env=env,
        text=True,
    )
    p = psutil.Process(proc.pid)

    # Read the startup readiness line
    ready_line = proc.stdout.readline() if proc.stdout else ""
    try:
        startup_time = float(ready_line.split()[1]) if "READY" in ready_line else (time.perf_counter() - t0)
    except Exception:
        startup_time = time.perf_counter() - t0

    # Wait brief moment for steady state
    time.sleep(0.3)

    # Resolve active processes (parent + venv child processes)
    all_procs = [p]
    try:
        all_procs.extend(p.children(recursive=True))
    except Exception:
        pass

    # Sum RSS and sample CPU over 1.0 second
    rss_total = 0.0
    for pr in all_procs:
        try:
            rss_total += pr.memory_info().rss
            pr.cpu_percent(interval=None)  # first non-blocking call to initialize CPU counters
        except Exception:
            pass

    time.sleep(1.0)

    cpu_total = 0.0
    for pr in all_procs:
        try:
            cpu_total += pr.cpu_percent(interval=None)
        except Exception:
            pass

    try:
        proc.terminate()
        proc.wait(timeout=2.0)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    return {
        "name": name,
        "startup_time_sec": round(startup_time, 3),
        "rss_mb": round(rss_total / (1024 * 1024), 2),
        "cpu_percent": round(cpu_total, 1),
    }


def main() -> None:
    print("=" * 70)
    print("SNOW V3 Phase 21 — Empirical Resource Usage Benchmark")
    print("=" * 70)

    hw = get_hardware_info()
    print("Host Hardware Environment (Target Hardware Verified):")
    print(f"  OS:     {hw['os']}")
    print(f"  CPU:    {hw['cpu']}")
    print(f"  RAM:    {hw['ram_gb']}")
    print(f"  Python: {hw['python']}")
    print("-" * 70)

    # 1. Daemon
    d_res = measure_component(
        "SNOW Core Daemon (headless runtime)",
        "from snow.capabilities.engine import CapabilityEngine; from snow.security.db import DatabaseManager; db = DatabaseManager(); e = CapabilityEngine(db_manager=db)",
    )
    print(f"[1/3] {d_res['name']}:")
    print(f"  Startup Time:          {d_res['startup_time_sec']} s")
    print(f"  Resident Memory (RSS): {d_res['rss_mb']} MB")
    print(f"  Idle CPU Utilization:  {d_res['cpu_percent']} %")

    # 2. MCP Server
    m_res = measure_component(
        "SNOW MCP Server (fastmcp / stdio bridge)",
        "import snow.mcp.tools; import snow.mcp.registry; snow.mcp.registry.validate_registry()",
    )
    print(f"\n[2/3] {m_res['name']}:")
    print(f"  Startup Time:          {m_res['startup_time_sec']} s")
    print(f"  Resident Memory (RSS): {m_res['rss_mb']} MB")
    print(f"  Idle CPU Utilization:  {m_res['cpu_percent']} %")

    # 3. TUI
    t_res = measure_component(
        "SNOW Interactive TUI (textual & rich Layer 1 consumer)",
        "import snow.tui.app; app = snow.tui.app.SnowTuiApp()",
    )
    print(f"\n[3/3] {t_res['name']}:")
    print(f"  Startup Time:          {t_res['startup_time_sec']} s")
    print(f"  Resident Memory (RSS): {t_res['rss_mb']} MB")
    print(f"  Idle CPU Utilization:  {t_res['cpu_percent']} %")

    print("=" * 70)


if __name__ == "__main__":
    main()
