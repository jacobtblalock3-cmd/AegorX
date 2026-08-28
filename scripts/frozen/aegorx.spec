# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for standalone AegorX builds (Windows / macOS / Linux).

Build from the repo root:
    pyinstaller --noconfirm scripts/frozen/aegorx.spec

Bundles the pinned trust keys and the YARA rule set; deliberately excludes
the heavy ML stack — frozen binaries degrade gracefully to signatures+YARA.
"""

import glob
import os

ROOT = os.path.abspath(os.path.join(SPECPATH, "..", ".."))

trust_keys = glob.glob(os.path.join(ROOT, "aegorx", "signing", "trusted_keys", "*.pub"))
rule_files = glob.glob(os.path.join(ROOT, "rules", "*.yar"))

datas = [(p, "aegorx/signing/trusted_keys") for p in trust_keys]
datas += [(p, "rules") for p in rule_files]

a = Analysis(
    [os.path.join(ROOT, "scripts", "frozen", "entry.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=["aegorx.cli"],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "scipy",
        "pandas",
        "sklearn",
        "lightgbm",
        "numpy",
        "IPython",
        "pytest",
        "setuptools",
        "pip",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="aegorx",
    debug=False,
    strip=False,
    upx=False,
    console=True,
)
