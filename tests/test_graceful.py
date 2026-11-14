"""Degradation checks: a host without the external tools must stay usable."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from omni.core import proc
from omni.core.module import Module, registry
from omni.wifi import scan

ROOT = Path(__file__).resolve().parent.parent


class _Hostile(Module):
    NAME = "test.hostile"
    FAMILY = "core"
    NEEDS = ("definitely-not-installed",)

    def execute(self) -> str:
        return "ran"


def test_missing_tool_warns_instead_of_blocking_validation():
    mod = _Hostile()
    mod.validate()          # no raise even though the tool is absent
    assert mod.tools_missing() == ["definitely-not-installed"]


def test_required_option_reports_usage():
    mod = registry.build("brute.codes")
    usage = mod.usage()
    assert "MASK" in usage


NETSH_OUTPUT = """
Interface name : Wi-Fi 2

There are 2 networks currently visible.

SSID 1 : TELUS1234
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 7a:82:fe:56:80:43
         Signal             : 78%
         Channel            : 11

SSID 2 : FreeCafe
    Authentication          : Open
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 40%
         Channel            : 6
"""


def test_parse_netsh_reads_aps_and_signal_percent():
    aps = scan.parse_netsh(NETSH_OUTPUT)
    assert [ap["ssid"] for ap in aps] == ["TELUS1234", "FreeCafe"]
    assert aps[0]["channel"] == 11
    assert aps[0]["security"] == "WPA2"
    assert aps[0]["signal"] == -61.0
    assert aps[1]["security"] == "OPEN"


def test_scan_any_uses_netsh_on_windows(monkeypatch):
    from omni.core import platform as host
    monkeypatch.setattr(host, "is_windows", lambda: True)
    monkeypatch.setattr(scan, "scan_netsh", lambda: [{"ssid": "x"}])
    assert scan.scan_any("") == [{"ssid": "x"}]


def test_install_hint_is_never_empty():
    assert proc.install_hint("nmap")


def test_manifest_lists_every_module_file():
    from omni.core._manifest import MODULES

    listed = set(MODULES)
    found = {f"omni.{p.parent.parent.name}.modules.{p.stem}"
             for p in ROOT.joinpath("omni").glob("*/modules/*.py")
             if not p.name.startswith("_")}
    assert found == listed


def test_cli_survives_a_missing_tool(tmp_path):
    """`omni run android.info` with no adb exits 0 and explains itself."""
    result = subprocess.run(
        [sys.executable, "-m", "omni.cli", "--no-color", "run", "android.info"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(ROOT), timeout=90)
    assert result.returncode == 0
    assert "adb" in (result.stdout + result.stderr)


def test_menu_module_imports_and_has_goals():
    from omni.core import menu, tasks

    assert tasks.TASKS
    assert callable(menu.run)
