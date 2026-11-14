"""Shared pytest fixtures: isolated config root, fake adb, tmp loot."""

import os
import stat

import pytest


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """Point OMNI's config/loot roots at a temp dir for every test."""
    root = tmp_path / "omni"
    root.mkdir()
    monkeypatch.setenv("OMNI_HOME", str(root))
    monkeypatch.chdir(tmp_path)
    yield root


def _write_shim(bindir, name: str, body: str) -> None:
    """Write a stub tool.

    POSIX ``which``/``shutil.which`` ignore files without the execute bit, so
    the chmod is required on Linux; on Windows the ``.bat`` sibling is what
    gets resolved.
    """
    shim = bindir / name
    shim.write_text(body)
    if os.name == "nt":
        shim.with_suffix(".bat").write_text(body)
    else:
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP
                   | stat.S_IXOTH)


@pytest.fixture
def fake_bin(tmp_path, monkeypatch):
    """Create a directory of stub executables and prepend it to PATH."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    shims = {
        "adb": '#!/bin/sh\necho "List of devices attached"\n',
        "nmap": '#!/bin/sh\necho "22/tcp open ssh"\n',
        "scrcpy": '#!/bin/sh\nexit 0\n',
        "frida": '#!/bin/sh\nexit 0\n',
        "jadx": '#!/bin/sh\nexit 0\n',
        "airmon-ng": '#!/bin/sh\necho "monitor mode vif enabled for [phy0]wlan0mon"\n',
        "airodump-ng": '#!/bin/sh\nsleep 30\n',
        "aireplay-ng": '#!/bin/sh\necho "Sending DeAuth to broadcast -- BSSID: [00:11:22:33:44:55]"\n',
        "aircrack-ng": '#!/bin/sh\nsleep 30\n',
        "hcxdumptool": '#!/bin/sh\nsleep 30\n',
        "rtl_433": '#!/bin/sh\necho \'{"model":"Test","id":1,"rssi":-20}\'\n',
        "iw": '#!/bin/sh\necho "type monitor"\n',
        "hydra": '#!/bin/sh\nsleep 30\n',
        "hashcat": '#!/bin/sh\nsleep 30\n',
    }
    for name, body in shims.items():
        _write_shim(bindir, name, body)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    return bindir

