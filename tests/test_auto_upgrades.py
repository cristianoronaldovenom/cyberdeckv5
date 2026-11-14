"""One-click and power-up helpers: pure parsers and safe plan construction."""

from __future__ import annotations

import json

from omni.core import auto, elevate
from omni.pentest import hostscan
from omni.wifi.modules.passwords import parse_nmcli_saved


WIN_ARP = """
Interface: 192.168.1.108 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.254         00-11-22-33-44-55     dynamic
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
"""

LINUX_NEIGH = """
192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
10.0.0.5 dev eth0 lladdr 00:11:22:33:44:55 STALE
fe80::1 dev eth0 lladdr 00:11:22:33:44:55 router
"""

IPCONFIG = """
Wireless LAN adapter Wi-Fi:
   Connection-specific DNS Suffix  . : lan
   IPv4 Address. . . . . . . . . . . : 192.168.1.108
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1

Ethernet adapter Bluetooth:
   IPv4 Address. . . . . . . . . . . : 169.254.10.20
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
"""


def test_parse_arp_windows_keeps_real_hosts():
    found = hostscan.parse_arp(WIN_ARP)
    assert found == ["192.168.1.1", "192.168.1.254"]


def test_parse_arp_linux_ignores_ipv6():
    found = hostscan.parse_arp(LINUX_NEIGH)
    assert found == ["192.168.1.1", "10.0.0.5"]


def test_parse_ipconfig_extracts_only_slash_24():
    assert hostscan.parse_ipconfig(IPCONFIG) == ["192.168.1.0/24"]


def test_parse_nmcli_saved():
    rows = parse_nmcli_saved("Home:hunter2\nCafe:\n")
    assert rows[0] == {"ssid": "Home", "key": "hunter2", "auth": "WPA2"}
    assert rows[1]["auth"] == "OPEN"


def test_ping_args_are_platform_appropriate(monkeypatch):
    monkeypatch.setattr(hostscan.host, "is_windows", lambda: True)
    assert hostscan.ping_args("192.0.2.1")[:2] == ["ping", "-n"]
    monkeypatch.setattr(hostscan.host, "is_windows", lambda: False)
    monkeypatch.setattr(hostscan.host, "is_macos", lambda: True)
    assert hostscan.ping_args("192.0.2.1")[:2] == ["ping", "-c"]


def test_auto_plan_has_no_unbuildable_steps():
    from omni.core.module import registry

    plan = auto.build_plan("safe")
    assert plan
    for _label, name, _opts in plan:
        assert registry.get(name) is not None, name


def test_auto_markdown_report_roundtrip(tmp_path):
    report = {"started": "20260101_000000", "platform": "test",
              "profile": "safe", "done": 1, "total": 2,
              "results": [{"label": "ok", "module": "core.devices", "ok": True,
                           "summary": "ran"},
                          {"label": "skip", "module": "x", "ok": False,
                           "skipped": True, "error": "no tool"}]}
    path = tmp_path / "r.md"
    auto.write_markdown(str(path), report)
    body = path.read_text(encoding="utf-8")
    assert "[PASS] ok" in body
    assert "[SKIP] skip" in body


def test_elevation_probe_never_raises():
    assert isinstance(elevate.is_admin(), bool)
    assert isinstance(elevate.can_elevate(), bool)


def test_auto_module_is_registered_and_option_complete():
    from omni.core.module import registry

    cls = registry.get("core.auto")
    assert cls is not None
    mod = cls()
    assert mod.get("PROFILE") == "safe"
    json.dumps(mod.opts["PROFILE"].__dict__, default=str)
