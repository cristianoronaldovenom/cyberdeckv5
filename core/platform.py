"""Platform capability probes, so Linux assumptions stay in one place.

OMNI targets Linux first, but macOS and Windows are both real hosts for the
non-radio trades. Rather than sprinkle ``os.name`` checks through the modules,
everything asks here:

* :func:`is_linux` / :func:`is_macos` / :func:`is_windows`;
* :func:`airport` — macOS' 802.11 control binary, when present;
* :func:`wireless_interfaces` — sysfs on Linux, ``networksetup`` on macOS;
* :func:`lockdown_stores` — where a host keeps iOS pair records;
* :func:`service_restart` — ``systemctl`` vs ``ifconfig`` vs a Windows service.

Each helper degrades to an empty/neutral answer instead of raising, because
every caller already treats "not supported here" as a normal outcome.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from omni.core import proc

__all__ = ["is_linux", "is_macos", "is_windows", "airport", "iw_present",
           "wireless_interfaces", "lockdown_stores", "service_restart",
           "root_argv", "net_bytes"]

#: macOS 802.11 helper. Deprecated in Sonoma but still present on most hosts.
AIRPORT = ("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/"
           "Current/Resources/airport")


def is_linux() -> bool:
    return os.name == "posix" and not is_macos()


def is_macos() -> bool:
    return os.name == "posix" and bool(
        getattr(os, "uname", None) and os.uname().sysname == "Darwin")


def is_windows() -> bool:
    return os.name == "nt"


def airport() -> str:
    """Path to macOS' ``airport`` helper, or "" when it is gone."""
    if not is_macos():
        return ""
    if os.path.isfile(AIRPORT):
        return AIRPORT
    return shutil.which("airport") or ""


def iw_present() -> bool:
    """``iw`` only exists on Linux (a brew port is not the same tool)."""
    return is_linux() and proc.has("iw")


def wireless_interfaces() -> list[str]:
    """Wireless interface names, best effort, per platform."""
    if is_macos():
        return _macos_wifi_devices()
    if is_windows():
        return _windows_wifi_devices()
    found: list[str] = []
    base = "/sys/class/net"
    try:
        names = os.listdir(base)
    except OSError:
        names = []
    for name in names:
        if os.path.isdir(os.path.join(base, name, "wireless")):
            found.append(name)
    return sorted(found)


def _macos_wifi_devices() -> list[str]:
    """Interfaces behind a ``Hardware Port: Wi-Fi`` from ``networksetup``."""
    res = proc.run(["networksetup", "-listallhardwareports"], timeout=15)
    found, wifi = [], False
    for line in res.out.splitlines():
        line = line.strip()
        if line.lower().startswith("hardware port:"):
            wifi = "wi-fi" in line.lower() or "airport" in line.lower()
        elif wifi and line.lower().startswith("device:"):
            name = line.split(":", 1)[1].strip()
            if name:
                found.append(name)
            wifi = False
    return sorted(set(found))


def _windows_wifi_devices() -> list[str]:
    """Interfaces from ``netsh wlan show interfaces``; no adapter -> []."""
    res = proc.run(["netsh", "wlan", "show", "interfaces"], timeout=15,
                   env={"PYTHONIOENCODING": "utf-8"})
    names: list[str] = []
    for line in res.out.splitlines():
        label, sep, value = line.partition(":")
        if sep and label.strip().lower() in ("name", "nombre", "nome", "naam"):
            value = value.strip()
            if value:
                names.append(value)
    if names:
        return sorted(set(names))
    # fall back to the generic adapter table (localised descriptions included)
    res = proc.run(["netsh", "interface", "show", "interface"], timeout=15,
                   env={"PYTHONIOENCODING": "utf-8"})
    for line in res.out.splitlines():
        low = line.lower()
        if "wi-fi" in low or "wireless" in low or "wlan" in low:
            parts = line.split()
            if parts:
                names.append(parts[-1])
    return sorted(set(names))


def lockdown_stores() -> list[str]:
    """iOS pair-record stores on this host, most authoritative first."""
    if is_windows():
        return [r"C:\ProgramData\Apple\Lockdown"]
    if is_macos():
        return ["/var/db/lockdown", os.path.expanduser("~/Library/Lockdown")]
    return ["/var/lib/lockdown", "/var/db/lockdown"]


def service_restart(interface: str = "") -> list[list[str]]:
    """Commands that make a fresh pairing record take effect on this host."""
    if is_windows():
        return [["net", "stop", "Apple Mobile Device Service"],
                ["net", "start", "Apple Mobile Device Service"]]
    if is_macos():
        return [["killall", "usbmuxd"]]
    return [["systemctl", "restart", "usbmuxd"]]


def root_argv(argv: list[str]) -> list[str]:
    """Prefix ``sudo`` when this platform needs it and we are not root yet."""
    if is_windows() or not hasattr(os, "geteuid") or os.geteuid() == 0:
        return list(argv)
    return ["sudo"] + list(argv)


def net_bytes(interface: str) -> dict:
    """(rx, tx) byte counters for an interface, zeroed when unreadable."""
    stats = {"rx_bytes": 0, "tx_bytes": 0}
    if is_linux():
        for key, name in (("rx_bytes", "rx_bytes"), ("tx_bytes", "tx_bytes")):
            try:
                with open(f"/sys/class/net/{interface}/statistics/{name}",
                          "r", encoding="utf-8") as fh:
                    stats[key] = int(fh.read().strip() or 0)
            except (OSError, ValueError):
                pass
        return stats
    if is_macos():
        # netstat -ib: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts ...
        try:
            out = subprocess.run(["netstat", "-ib"], capture_output=True,
                                 text=True, timeout=15,
                                 errors="replace").stdout
        except (OSError, subprocess.SubprocessError):
            return stats
        for line in out.splitlines():
            parts = line.split()
            if len(parts) > 9 and parts[0] == interface:
                try:
                    stats["rx_bytes"] += int(parts[6])
                    stats["tx_bytes"] += int(parts[9])
                except ValueError:
                    pass
    return stats
