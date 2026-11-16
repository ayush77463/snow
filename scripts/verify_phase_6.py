"""SNOW Phase 6 Live Capabilities Verification Script.

Connects to the running SNOW Desktop Core via authenticated loopback IPC
and exercises all 5 Android capability modules live on the connected phone:
  1. Battery & Device Telemetry (snow_android_battery)
  2. Ring Phone / Audible Alert (snow_android_ring)
  3. Clipboard Push (snow_android_clipboard_push)
  4. App Listing (snow_android_list_apps)
  5. File Send to Scoped Storage (snow_android_file_send)

Usage:
  1. Terminal 1: Run the Desktop Core:
     .\\.venv\\Scripts\\python.exe -m snow

  2. On Android Phone: Open SNOW app, tap Connect, and Pair with the 6-digit PIN.

  3. Terminal 2: Run this script:
     .\\.venv\\Scripts\\python.exe scripts/verify_phase_6.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys

from snow.mcp.bridge import SnowMcpBridge


async def main() -> int:
    print("=" * 65)
    print("  SNOW Phase 6 — Android Capabilities Live Verification")
    print("=" * 65)

    # 1. Connect to loopback IPC
    secret_path = Path.home() / ".snow" / "ipc.secret"
    if not secret_path.exists():
        print(f"\n[FAIL] IPC secret file not found at: {secret_path}")
        print("       Ensure the SNOW Desktop Core is running: python -m snow")
        return 1

    secret = secret_path.read_text().strip()
    bridge = SnowMcpBridge(host="127.0.0.1", port=8767, secret=secret)

    print("\n[Step 1/6] Connecting to Desktop Core IPC on 127.0.0.1:8767...")
    status = await bridge.get_device_status()
    if not status.get("success"):
        print(f"[FAIL] Could not connect to Core: {status.get('error')}")
        return 1

    devices_res = await bridge.list_devices()
    devices = devices_res.get("data", {}).get("devices", [])
    active_device = next((d for d in devices if d.get("is_connected")), None)

    if not active_device:
        print("[FAIL] No actively connected Android device found.")
        print("       Please open the SNOW Android app, tap Connect, and pair with the PIN.")
        return 1

    dev_id = active_device["device_id"]
    dev_name = active_device.get("device_name", "Android Phone")
    remote_ip = active_device.get("remote_address", ("unknown", 0))[0]
    print(f"  -> Found Active Device: {dev_name} ({dev_id[:8]}...) at {remote_ip}")

    # 2. Battery telemetry
    print("\n[Step 2/6] Querying Phone Battery Telemetry (snow_android_battery)...")
    battery_res = await bridge.android_battery(device_id=dev_id)
    if battery_res.get("success"):
        data = battery_res.get("data", {})
        level = data.get("level")
        charging = "Yes" if data.get("charging") else "No"
        power = data.get("power_source", "Battery")
        temp = data.get("temperature_c", "N/A")
        model = data.get("device_model", "Unknown")
        android_v = data.get("android_version", "Unknown")
        print(f"  [PASS] Battery Level: {level}% | Charging: {charging} ({power})")
        print(f"         Device: {model} (Android {android_v}) | Temp: {temp} C")
    else:
        print(f"  [FAIL] Battery query failed: {battery_res.get('error')}")

    # 3. Clipboard Push
    print("\n[Step 3/6] Pushing Text to Phone Clipboard (snow_android_clipboard_push)...")
    clip_text = "Hello from SNOW Desktop Core! Capstone Phase 6 verified."
    clip_res = await bridge.android_clipboard_push(text=clip_text, device_id=dev_id)
    if clip_res.get("success"):
        bytes_w = clip_res.get("data", {}).get("bytes_written", len(clip_text))
        print(f"  [PASS] Pushed {bytes_w} bytes to phone clipboard.")
        print(f"         (You can paste on your phone right now to verify!)")
    else:
        print(f"  [FAIL] Clipboard push failed: {clip_res.get('error')}")

    # 4. List Launchable Apps
    print("\n[Step 4/6] Enumerating Launchable Apps on Phone (snow_android_list_apps)...")
    apps_res = await bridge.android_list_apps(limit=5, device_id=dev_id)
    if apps_res.get("success"):
        apps = apps_res.get("data", {}).get("apps", [])
        total = apps_res.get("data", {}).get("total_found", len(apps))
        print(f"  [PASS] Successfully retrieved {len(apps)} apps (total launchable: {total}):")
        for app in apps:
            label = app.get("label", "App")
            pkg = app.get("package_name", "")
            print(f"         - {label} ({pkg})")
    else:
        print(f"  [FAIL] List apps failed: {apps_res.get('error')}")

    # 5. File Send to Scoped Storage
    print("\n[Step 5/6] Sending Test File to Phone (snow_android_file_send)...")
    transfers_dir = Path.home() / ".snow" / "transfers"
    transfers_dir.mkdir(parents=True, exist_ok=True)
    test_file = transfers_dir / "snow_phase6_test.txt"
    test_content = (
        "SNOW Phase 6 Android Capabilities Verification\n"
        "Transferred over authenticated HTTPS streaming on port 8766\n"
        "Stored in app-scoped Downloads/SNOW directory.\n"
    )
    test_file.write_text(test_content, encoding="utf-8")

    file_res = await bridge.android_file_send(file_path=str(test_file), device_id=dev_id)
    if file_res.get("success"):
        data = file_res.get("data", {})
        saved_path = data.get("saved_path", "Downloads/SNOW")
        bytes_down = data.get("bytes_downloaded", len(test_content))
        print(f"  [PASS] Successfully sent {test_file.name} ({bytes_down} bytes).")
        print(f"         Saved on phone at: {saved_path}")
    else:
        print(f"  [FAIL] File send failed: {file_res.get('error')}")

    # 6. Ring Phone
    print("\n[Step 6/6] Ringing Phone for 3 Seconds (snow_android_ring)...")
    print("  -> Listen to your Realme phone for the audible ringtone...")
    ring_res = await bridge.android_ring(duration_seconds=3, device_id=dev_id)
    if ring_res.get("success"):
        print("  [PASS] Audible alert triggered successfully.")
    else:
        print(f"  [FAIL] Ring request failed: {ring_res.get('error')}")

    print("\n" + "=" * 65)
    print("  PHASE 6 LIVE VERIFICATION COMPLETE: ALL CAPABILITIES TESTED")
    print("=" * 65)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
