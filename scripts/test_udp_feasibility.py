"""SNOW Phase 1.4 Empirical UDP Diagnostic Utility.

DIAGNOSTIC UTILITY NOTICE:
---------------------------
- This script is a one-off Phase 1.4 empirical diagnostic utility used to probe
  UDP reachability between the Windows host and Android test device.
- The IP addresses, subnet masks, and local ADB executable path configured below
  are specific to the historical test session/environment (Realme RMX5110 hotspot).
- This is NOT a portable automated regression test and is NOT executed during CI.
- This is NOT part of the production SNOW discovery architecture.
- The test results recorded with this script represent empirical observations on
  a specific network topology, not guaranteed behaviors across other network types.

Probe Directions Tested:
1. Laptop -> Phone (Unicast, Subnet Broadcast, Limited Broadcast 255.255.255.255)
2. Phone -> Laptop (Unicast, Subnet Broadcast, Limited Broadcast 255.255.255.255)
"""

import socket
import subprocess
import threading
import time

ADB_PATH = r"C:\Users\ayush\AppData\Local\Android\Sdk\platform-tools\adb.exe"
UDP_PORT = 8766
LAPTOP_IP = "10.16.46.23"
PHONE_IP = "10.16.46.35"
SUBNET_BROADCAST = "10.16.46.255"
LIMITED_BROADCAST = "255.255.255.255"

results = {}

def test_laptop_to_phone():
    print("\n--- Test: Laptop -> Phone ---")
    for dest_name, dest_ip in [("Unicast", PHONE_IP), ("Subnet_Broadcast", SUBNET_BROADCAST), ("Limited_Broadcast", LIMITED_BROADCAST)]:
        # Start listener on phone via ADB
        cmd = [ADB_PATH, "shell", f"timeout 2 nc -u -l -p {UDP_PORT}"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(0.4)

        # Send from laptop
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        test_payload = f"PING_FROM_LAPTOP_{dest_name}".encode()
        try:
            sock.sendto(test_payload, (dest_ip, UDP_PORT))
        except Exception as e:
            results[f"Laptop->Phone ({dest_name})"] = f"FAIL (Send error: {e})"
            proc.kill()
            sock.close()
            continue
        sock.close()

        try:
            stdout, _ = proc.communicate(timeout=2.5)
            if "PING_FROM_LAPTOP" in stdout:
                results[f"Laptop->Phone ({dest_name})"] = "PASS (Received)"
                print(f"  Laptop -> Phone ({dest_name} to {dest_ip}): PASS (Received: {stdout.strip()})")
            else:
                results[f"Laptop->Phone ({dest_name})"] = "FAIL (No packet received)"
                print(f"  Laptop -> Phone ({dest_name} to {dest_ip}): FAIL (Empty output)")
        except subprocess.TimeoutExpired:
            proc.kill()
            results[f"Laptop->Phone ({dest_name})"] = "FAIL (Timeout)"
            print(f"  Laptop -> Phone ({dest_name} to {dest_ip}): FAIL (Timeout)")


def test_phone_to_laptop():
    print("\n--- Test: Phone -> Laptop ---")
    for dest_name, dest_ip in [("Unicast", LAPTOP_IP), ("Subnet_Broadcast", SUBNET_BROADCAST), ("Limited_Broadcast", LIMITED_BROADCAST)]:
        received = []
        stop_evt = threading.Event()

        def listen_laptop():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind(("0.0.0.0", UDP_PORT))
            sock.settimeout(2.0)
            try:
                data, addr = sock.recvfrom(1024)
                received.append((data.decode(errors="replace").strip(), addr))
            except socket.timeout:
                pass
            finally:
                sock.close()

        t = threading.Thread(target=listen_laptop)
        t.start()
        time.sleep(0.3)

        # Phone sends packet via ADB with -q 0 (quit on EOF)
        msg = f"PING_FROM_PHONE_{dest_name}"
        send_cmd = [ADB_PATH, "shell", f"echo '{msg}' | nc -u -q 0 {dest_ip} {UDP_PORT}"]
        try:
            subprocess.run(send_cmd, capture_output=True, timeout=2.0)
        except subprocess.TimeoutExpired:
            pass

        t.join(timeout=2.5)
        if received:
            results[f"Phone->Laptop ({dest_name})"] = f"PASS (Received from {received[0][1]})"
            print(f"  Phone -> Laptop ({dest_name} to {dest_ip}): PASS (Received: {received[0][0]} from {received[0][1]})")
        else:
            results[f"Phone->Laptop ({dest_name})"] = "FAIL (Packet not received / dropped by firewall or network)"
            print(f"  Phone -> Laptop ({dest_name} to {dest_ip}): FAIL (Dropped / Timeout)")


if __name__ == "__main__":
    test_laptop_to_phone()
    test_phone_to_laptop()
    print("\n" + "=" * 60)
    print("UDP FEASIBILITY SUMMARY:")
    for k, v in results.items():
        print(f"  {k:35} : {v}")
    print("=" * 60)
