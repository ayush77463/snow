# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification file for SNOW Windows Standalone Distribution.

Bundles SNOW into a standalone directory/executable distribution including:
- Core daemon and MCP engine
- Streamable HTTP Gateway and zero-port-forwarding expose tool
- Local Web Dashboard and all static HTML/JS/CSS assets
- Lightweight Win32 System Tray Companion
"""

import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

SPEC_ROOT = Path(SPECPATH).resolve()
REPO_ROOT = SPEC_ROOT.parent.parent
SRC_DIR = REPO_ROOT / "src"

# Explicit data file mappings (source -> destination in bundle)
datas = [
    (str(SRC_DIR / "snow" / "web" / "static"), "snow/web/static"),
]
if (REPO_ROOT / "snow.png").is_file():
    datas.append((str(REPO_ROOT / "snow.png"), "."))

# Hidden imports required by dynamic dispatch and asyncio
hiddenimports = [
    "snow.cli",
    "snow.main",
    "snow.daemon",
    "snow.core.config",
    "snow.core.server",
    "snow.tray",
    "snow.tray.app",
    "snow.tray.autostart",
    "snow.web.server",
    "snow.mcp.remote_gateway",
    "snow.mcp.expose",
    "snow.mcp.bridge",
    "snow.mcp.oauth",
    "snow.network.account_discovery",
    "aiohttp",
    "cryptography",
    "psutil",
    "sqlite3",
    "winreg",
    "ctypes",
    "ctypes.wintypes",
]

# Collect additional submodules for resilience
hiddenimports += collect_submodules("snow")

a = Analysis(
    [str(SRC_DIR / "snow" / "cli.py")],
    pathex=[str(SRC_DIR)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "scipy", "pandas"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="snow",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

exe_tray = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="snow-tray",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    exe_tray,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="snow",
)
