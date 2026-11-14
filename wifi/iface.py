"""Wireless interface control: discovery, monitor mode, channel hopping.

Everything degrades gracefully: when neither ``airmon-ng`` nor ``iw`` is
present the discovery helpers return an empty list and the modules say so
instead of exploding.
"""

from __future__ import annotations

import os
import re
import threading
import time

from omni.core import console, platform as host, proc

__all__ = [
    "wireless_interfaces", "is_wireless", "current_mode", "set_monitor",
    "set_managed", "channel", "parse_channels", "ChannelHopper", "monitor_name",
    "pick", "throughput",
]


def _sysfs_wireless() -> list[str]:
    out = []
    base = "/sys/class/net"
    try:
        names = os.listdir(base)
    except OSError:
        return out
    for name in names:
        if os.path.isdir(os.path.join(base, name, "wireless")):
            out.append(name)
    return out


def _iw_dev() -> list[str]:
    if not proc.has("iw"):
        return []
    res = proc.run(["iw", "dev"], timeout=10)
    if not res.ok:
        return []
    return [m.group(1) for m in re.finditer(r"^\s*Interface\s+(\S+)$",
                                            res.out, re.MULTILINE)]


def wireless_interfaces() -> list[str]:
    """Every wireless interface, from sysfs, ``iw`` or ``networksetup``."""
    names = set(host.wireless_interfaces())
    if host.is_linux():
        names.update(_sysfs_wireless())
        names.update(_iw_dev())
    return sorted(n for n in names if is_wireless(n))


def is_wireless(name: str) -> bool:
    """True when ``name`` is a wireless interface on this platform."""
    if host.is_linux():
        return os.path.isdir(f"/sys/class/net/{name}/wireless")
    return name in host.wireless_interfaces()


def monitor_name(base: str) -> str:
    """``wlan0`` -> ``wlan0mon`` (suffix already present is kept)."""
    return base if base.endswith("mon") else base + "mon"


def current_mode(iface: str) -> str:
    """Interface type from ``iw`` (managed / monitor / ...) or ``unknown``."""
    if host.is_macos():
        return "managed" if _airport_power(iface) else "off"
    if host.is_windows() and not host.is_macos():
        # netsh has no monitor-mode concept on the built-in driver; report
        # managed when the adapter is up so callers keep working
        res = proc.run(["netsh", "wlan", "show", "interfaces"], timeout=15)
        return "managed" if iface and iface in res.out else "unknown"
    if not proc.has("iw"):
        return "unknown"
    res = proc.run(["iw", "dev", iface, "info"], timeout=10)
    match = re.search(r"^\s*type\s+(\S+)$", res.out, re.MULTILINE)
    return match.group(1) if match else "unknown"


def _airport_power(iface: str) -> bool:
    """macOS: is the radio on? (the *airport* CLI was dropped in Sonoma)"""
    res = proc.run(["networksetup", "-getairportpower", iface], timeout=15)
    return bool(res.ok and res.text.strip().lower().endswith("on"))


def set_monitor(iface: str) -> str:
    """Put ``iface`` into monitor mode; returns the resulting iface name.

    Prefers ``airmon-ng`` (it also kills interfering daemons); falls back to
    the manual ``iw`` sequence. macOS has no persistent monitor vifs on the
    built-in card, so there it disassociates and hands the interface back â€”
    capture tools then use ``airport sniff`` style capture themselves. Windows
    has no monitor vif either: ``netsh`` keeps the adapter managed and the
    Windows stand-ins (hosted network, pktmon) do the work.
    """
    if current_mode(iface) == "monitor":
        return iface
    if host.is_windows() and not host.is_macos():
        if proc.has("wsl"):
            console.warn("Windows has no monitor mode on the native driver; "
                         "pass the adapter to WSL for airodump (usbipd)")
        else:
            console.warn("no monitor mode on Windows without WSL; scanning "
                         "uses `netsh wlan show networks`")
        return iface
    if proc.has("airmon-ng"):
        proc.run(["airmon-ng", "check", "kill"], timeout=60)
        res = proc.run(["airmon-ng", "start", iface], timeout=60)
        match = re.search(r"monitor mode (?:vif )?enabled.*?on (\w+)", res.text,
                          re.IGNORECASE)
        if match:
            return match.group(1)
        if proc.has("iw") and proc.run(["iw", "dev", monitor_name(iface),
                                        "info"]).ok:
            return monitor_name(iface)
    if host.is_macos():
        tool = host.airport()
        if tool:
            proc.run([tool, "-z"], timeout=30)          # disassociate
        if proc.run(["ifconfig", iface, "monitor"], timeout=30).ok:
            return iface
        console.warn(f"{iface}: no monitor mode on this adapter/driver")
        return iface
    mon = monitor_name(iface)
    for argv in (["ip", "link", "set", iface, "down"],
                 ["iw", "dev", iface, "interface", "add", mon, "type",
                  "monitor"],
                 ["ip", "link", "set", mon, "up"]):
        res = proc.run(argv, timeout=30)
        if not res.ok:
            raise RuntimeError(f"{' '.join(argv)}: {res.text}")
    if current_mode(mon) != "monitor":
        raise RuntimeError(f"could not enable monitor mode on {mon}")
    return mon


def set_managed(iface: str) -> None:
    """Return an interface to managed mode (also stops a monitor vif)."""
    if host.is_macos():
        proc.run(["ifconfig", iface, "-monitor"], timeout=30)
    elif current_mode(iface) in ("monitor", "unknown") and proc.has("iw"):
        proc.run(["ip", "link", "set", iface, "down"], timeout=30)
        proc.run(["iw", "dev", iface, "set", "type", "managed"], timeout=30)
        proc.run(["ip", "link", "set", iface, "up"], timeout=30)
    for argv in host.service_restart(iface):
        proc.run(argv, timeout=60)


def channel(iface: str, ch: int) -> bool:
    """Tune ``iface`` to channel ``ch``."""
    if host.is_macos():
        tool = host.airport()
        if tool:
            return proc.run([tool, iface, f"-c{int(ch)}"], timeout=15).ok
    if proc.has("iw"):
        res = proc.run(["iw", "dev", iface, "set", "channel", str(int(ch))],
                       timeout=15)
        return res.ok
    return proc.run(["iwconfig", iface, "channel", str(int(ch))]).ok


def parse_channels(spec: str) -> list[int]:
    """``"1-3,6,11"`` -> ``[1, 2, 3, 6, 11]``; bad tokens are skipped."""
    out: list[int] = []
    for token in re.split(r"[,\s]+", spec or ""):
        if not token:
            continue
        if "-" in token:
            lo, _, hi = token.partition("-")
            try:
                a, b = int(lo), int(hi)
            except ValueError:
                continue
            out.extend(range(min(a, b), max(a, b) + 1))
            continue
        try:
            out.append(int(token))
        except ValueError:
            continue
    return sorted(set(out))


class ChannelHopper:
    """Dwell on each channel of a list until stopped (background thread)."""

    def __init__(self, iface: str, channels: list[int], dwell: float = 0.4):
        self.iface = iface
        self.channels = [c for c in channels if c]
        self.dwell = max(0.05, float(dwell))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.seen: list[int] = []

    def start(self) -> None:
        if not self.channels:
            return
        channel(self.iface, self.channels[0])

        def _loop() -> None:
            i = 1
            while not self._stop.wait(self.dwell):
                ch = self.channels[i % len(self.channels)]
                channel(self.iface, ch)
                self.seen.append(ch)
                i += 1

        self._thread = threading.Thread(target=_loop, name="omni-wifi-hop",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def __enter__(self) -> "ChannelHopper":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
        console.debug(f"hopped over {len(set(self.seen))} channel(s)")


def pick(preferred: str | None = None) -> str:
    """Resolve an interface: explicit value, config, or the first wireless."""
    from omni.core import config
    iface = preferred or config.get_value("wifi.interface")
    if iface:
        return str(iface)
    found = wireless_interfaces()
    if not found:
        raise RuntimeError("no wireless interface found (monitor-mode capable "
                           "adapter required)")
    return found[0]


def link_info(iface: str) -> dict:
    """Current association: SSID, address, signal and counters.

    Everything here is best-effort sysfs/`ip` reading — a disconnected
    interface simply yields empty fields rather than raising.
    """
    info: dict = {"iface": iface, "ssid": "", "ip": "", "signal_dbm": ""}
    if host.is_windows() and not host.is_macos():
        info.update(_windows_link(iface))
        info.update(throughput(iface))
        return info
    if host.is_macos():
        info.update(_macos_link(iface))
        info.update(throughput(iface))
        return info
    try:
        with open("/proc/net/wireless", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip().startswith(iface + ":"):
                    parts = line.replace(".", "").split()
                    if len(parts) >= 4:
                        info["signal_dbm"] = parts[3]
                    break
    except OSError:
        pass
    out = proc.run(["iw", "dev", iface, "link"], timeout=15).out
    for line in out.splitlines():
        line = line.strip()
        if line.lower().startswith("ssid:"):
            info["ssid"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("signal:"):
            info["signal_dbm"] = line.split(":", 1)[1].strip().split()[0]
    addr = proc.run(["ip", "-4", "-o", "addr", "show", "dev", iface],
                    timeout=15).out
    for token in addr.split():
        if "/" in token and token.count(".") == 3:
            info["ip"] = token.split("/")[0]
            break
    info.update(throughput(iface))
    return info


def throughput(iface: str) -> dict:
    """Cheap link counters for progress reporting."""
    stats = host.net_bytes(iface)
    stats["timestamp"] = time.time()
    return stats


def _windows_link(iface: str) -> dict:
    """SSID / signal / address on Windows from ``netsh`` and ``ipconfig``."""
    out: dict = {"ssid": "", "ip": "", "signal_dbm": ""}
    res = proc.run(["netsh", "wlan", "show", "interfaces"], timeout=15,
                   env={"PYTHONIOENCODING": "utf-8"})
    current = ""
    for line in res.out.splitlines():
        label, sep, value = line.partition(":")
        if not sep:
            continue
        key = label.strip().lower()
        value = value.strip()
        if key in ("name", "nombre", "nome", "naam"):
            current = value
        elif current and current != iface:
            continue
        elif key in ("ssid", "state", "signal", "receive rate", "rx rate"):
            if key == "ssid":
                out["ssid"] = value
            elif key == "signal" and value.endswith("%"):
                try:
                    out["signal_dbm"] = str(round(int(value.rstrip("%")) / 2 - 100, 1))
                except ValueError:
                    pass
    ip = proc.run(["ipconfig"], timeout=15,
                  env={"PYTHONIOENCODING": "utf-8"}).out
    block = ip.split(iface, 1)[-1] if iface and iface in ip else ip
    match = re.search(r"IPv4[^\n]*?:\s*(\d+\.\d+\.\d+\.\d+)", block)
    if match:
        out["ip"] = match.group(1)
    return out


def _macos_link(iface: str) -> dict:
    """SSID / signal / address on macOS, from ``airport -I`` and ``ifconfig``."""
    out: dict = {"ssid": "", "ip": "", "signal_dbm": ""}
    tool = host.airport()
    if tool:
        res = proc.run([tool, "-I"], timeout=15)
        for line in res.out.splitlines():
            name, _, value = line.strip().partition(":")
            if name.strip() == "SSID":
                out["ssid"] = value.strip()
            elif name.strip() == "agrCtlRSSI":
                out["signal_dbm"] = value.strip()
    res = proc.run(["ifconfig", iface], timeout=15)
    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", res.out)
    if match:
        out["ip"] = match.group(1)
    return out

