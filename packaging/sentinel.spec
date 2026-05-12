# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Eresus Sentinel CLI
# Usage: pyinstaller packaging/sentinel.spec

import sys
from pathlib import Path

ROOT = Path(SPECPATH).parent
SRC  = ROOT / "python"

block_cipher = None

a = Analysis(
    [str(SRC / "sentinel" / "cli" / "main.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=[
        (str(ROOT / "rules"),             "rules"),
        (str(ROOT / "config" / "schemas"), "config/schemas"),
        (str(SRC / "sentinel" / "data"),  "sentinel/data"),
    ],
    hiddenimports=[
        "sentinel.cli",
        "sentinel.cli.main",
        "sentinel.artifact",
        "sentinel.firewall",
        "sentinel.firewall.input",
        "sentinel.firewall.output",
        "sentinel.sast",
        "sentinel.sast.secrets_scanner",
        "sentinel.redteam",
        "sentinel.agent",
        "sentinel.agent.mcp",
        "sentinel.supply_chain",
        "sentinel.aibom",
        "sentinel.mcp_proxy",
        "sentinel.sarif_output",
        "sentinel.finding",
        "sentinel.rules",
        "sentinel.policy",
        "sentinel.config",
        "yaml",
        "rich",
        "rich.console",
        "rich.table",
        "rich.progress",
        "click",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "torch",
        "tensorflow",
        "transformers",
        "onnxruntime",
        "matplotlib",
        "notebook",
        "jupyter",
        "IPython",
        "scipy",
        "sklearn",
        "pandas",
        "numpy",
        "PIL",
        "cv2",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="sentinel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
