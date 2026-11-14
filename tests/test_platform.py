"""Platform probes: the Linux/macOS/Windows splits the modules rely on."""

import pytest

from omni.core import platform as host
from omni.wifi import iface


def _fake_os(monkeypatch, name="posix", sysname="Linux", euid=0, tools=()):
    monkeypatch.setattr(host.os, "name", name, raising=False)
    if name == "posix":
        monkeypatch.setattr(host.os, "uname",
                            lambda: type("U", (), {"sysname": sysname})(),
                            raising=False)
        monkeypatch.setattr(host.os, "geteuid", lambda: euid, raising=False)
    monkeypatch.setattr(host.proc, "has", lambda binary: binary in tools)


def test_linux_and_macos_are_mutually_exclusive(monkeypatch):
    _fake_os(monkeypatch, "posix", "Linux")
    assert host.is_linux() and not host.is_macos() and not host.is_windows()
    _fake_os(monkeypatch, "posix", "Darwin")
    assert host.is_macos() and not host.is_linux()


def test_windows_is_detected(monkeypatch):
    _fake_os(monkeypatch, "nt")
    assert host.is_windows() and not host.is_linux()


def test_iw_only_counts_on_linux(monkeypatch):
    _fake_os(monkeypatch, "posix", "Linux", tools=("iw",))
    assert host.iw_present()
    _fake_os(monkeypatch, "posix", "Darwin", tools=("iw",))
    assert not host.iw_present()


def test_lockdown_stores_per_platform(monkeypatch):
    _fake_os(monkeypatch, "nt")
    assert host.lockdown_stores()[0].startswith("C:")
    _fake_os(monkeypatch, "posix", "Darwin")
    assert host.lockdown_stores()[0] == "/var/db/lockdown"
    _fake_os(monkeypatch, "posix", "Linux")
    assert host.lockdown_stores()[0] == "/var/lib/lockdown"


def test_service_restart_matches_the_platform(monkeypatch):
    _fake_os(monkeypatch, "posix", "Darwin")
    assert host.service_restart()[0][0] == "killall"
    _fake_os(monkeypatch, "posix", "Linux")
    assert host.service_restart()[0][0] == "systemctl"
    _fake_os(monkeypatch, "nt")
    assert host.service_restart()[0][0] == "net"


@pytest.mark.parametrize("euid,expected", [(0, 0), (1000, 1)])
def test_root_argv_only_prefixes_when_needed(monkeypatch, euid, expected):
    _fake_os(monkeypatch, "posix", "Darwin", euid=euid)
    assert host.root_argv(["x"]).count("sudo") == expected


def test_macos_wifi_devices_come_from_networksetup(monkeypatch):
    _fake_os(monkeypatch, "posix", "Darwin")
    output = ("Hardware Port: Wi-Fi\nDevice: en0\n\n"
              "Hardware Port: Thunderbolt Bridge\nDevice: bridge0\n")
    monkeypatch.setattr(host.proc, "run",
                        lambda argv, timeout=None: type(
                            "R", (), {"ok": True, "out": output, "err": "",
                                      "text": output})())
    assert host.wireless_interfaces() == ["en0"]


def test_iface_discovery_uses_the_platform_probe(monkeypatch):
    monkeypatch.setattr(host, "wireless_interfaces", lambda: ["en0"])
    monkeypatch.setattr(host, "is_linux", lambda: False)
    monkeypatch.setattr(host, "is_macos", lambda: True)
    assert iface.wireless_interfaces() == ["en0"]
    assert iface.is_wireless("en0") and not iface.is_wireless("eth9")


def test_channel_uses_airport_on_macos(monkeypatch):
    calls = []
    monkeypatch.setattr(host, "is_macos", lambda: True)
    monkeypatch.setattr(host, "airport", lambda: "/usr/bin/airport")
    monkeypatch.setattr(iface.proc, "run",
                        lambda argv, timeout=None: calls.append(argv) or type(
                            "R", (), {"ok": True, "out": "", "err": "",
                                      "text": ""})())
    assert iface.channel("en0", 6)
    assert calls[-1] == ["/usr/bin/airport", "en0", "-c6"]


def test_monitor_mode_falls_back_to_ifconfig_on_macos(monkeypatch):
    monkeypatch.setattr(host, "is_macos", lambda: True)
    monkeypatch.setattr(host, "airport", lambda: "")
    monkeypatch.setattr(iface, "current_mode", lambda name: "managed")
    calls = []
    monkeypatch.setattr(iface.console, "warn", lambda msg: None)
    monkeypatch.setattr(iface.proc, "run",
                        lambda argv, timeout=None: calls.append(argv) or type(
                            "R", (), {"ok": False, "out": "", "err": "",
                                      "text": ""})())
    assert iface.set_monitor("en0") == "en0"
    assert ["ifconfig", "en0", "monitor"] in calls


def test_macos_link_reads_airport_and_ifconfig(monkeypatch):
    monkeypatch.setattr(host, "airport", lambda: "/usr/bin/airport")

    def fake_run(argv, timeout=None):
        text = ("     SSID: HomeNet\n agrCtlRSSI: -52\n"
                if argv[0] == "/usr/bin/airport" else "inet 10.0.0.7 netmask 0xffffff00")
        return type("R", (), {"ok": True, "out": text, "err": "", "text": text})()

    monkeypatch.setattr(iface.proc, "run", fake_run)
    link = iface._macos_link("en0")
    assert link["ssid"] == "HomeNet"
    assert link["signal_dbm"] == "-52"
    assert link["ip"] == "10.0.0.7"
