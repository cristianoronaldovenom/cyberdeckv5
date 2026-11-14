# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for OMNI â€” one file, console, both platforms.

``pyinstaller packaging/omni.spec`` (or ``packaging/build_windows.ps1`` /
``packaging/build_macos.sh``) produces ``dist/OMNI.exe`` on Windows and
``dist/OMNI`` on macOS from this one definition.

The toolkit discovers its modules *at runtime*
(``importlib.import_module("omni.<trade>.modules")``), which a frozen build
cannot see, so ``collect_submodules`` is what keeps every module in the archive.
``assets/`` and ``data/`` are bundled next to the binary because they are read
from disk (the KeeLoq manufacturer DB, the flip index), and the registry walks
them the same way it does in the source tree.
"""

import os
import sys

from PyInstaller.utils.hooks import collect_submodules

SPEC = os.path.abspath(SPECPATH) if "SPECPATH" in globals() else os.getcwd()
ROOT = os.path.dirname(SPEC)

hidden = collect_submodules("omni")
# curses is imported lazily inside the dashboard, and on Windows it is the
# optional `windows-curses` wheel (_curses.pyd) â€” name it or it is left out.
hidden += ["curses", "_curses", "_curses_panel", "tkinter",
           "tkinter.ttk", "tkinter.font", "tkinter.messagebox"]
datas = []
for folder in ("assets", "data"):
    source = os.path.join(ROOT, folder)
    if os.path.isdir(source):
        datas.append((source, folder))

ICON = os.path.join(SPEC, "cyberdeck.ico")

a = Analysis(
    [os.path.join(SPEC, "omni_launcher.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tests", "pytest", "_pytest", "matplotlib"],
    noarchive=False,
)

pyz = PYZ(a.pure)

EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="OMNI",
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
    icon=ICON if os.path.isfile(ICON) else None,
)

if sys.platform == "darwin":
    # a second, bundle-shaped build so Finder double-click works as well
    app = BUNDLE(
        EXE(
            pyz,
            a.scripts,
            a.binaries,
            a.datas,
            [],
            name="OMNI-cli",
            console=True,
            exclude_binaries=False,
        ),
        name="OMNI.app",
        icon=None,
        bundle_identifier="org.omni.toolkit",
        info_plist={
            "CFBundleName": "OMNI",
            "CFBundleDisplayName": "OMNI",
            "CFBundleShortVersionString": "2.0",
            "LSMinimumSystemVersion": "11.0",
            "NSHighResolutionCapable": True,
        },
    )

