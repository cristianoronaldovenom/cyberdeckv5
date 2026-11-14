"""What this machine actually is: adapters, devices, radios, tools, loot.

``omni devices`` answers the first question of every session — *what can this box
do right now* — instead of leaving the operator to guess and then read a failure.
It is deliberately read-only and cheap: interfaces from sysfs/``iw``/PnP, USB
ids, adb and iOS device lists, serial ports, radio hardware, and which external
tools each trade is missing.

Every probe returns a row, present or not, so an empty section is information
too ("no monitor adapter" is the answer to a later `wifi.inject` failure).
"""

from __future__ import annotations

import os
import sys

from omni.core import platform as host, proc, setup

__all__ = ["Section", "inventory", "render", "TOOLS", "SERIAL_DIRS"]

#: tool -> the trades that are dead without it
TOOLS = {
    "iw": "wifi",
    "airmon-ng": "wifi",
    "airodump-ng": "wifi",
    "aireplay-ng": "wifi",
    "mdk4": "wifi flood/jam",
    "hostapd": "fake AP",
    "dnsmasq": "fake AP",
    "tcpdump": "sniffing",
    "tshark": "HTTPS/pcap analysis",
    "hcxdumptool": "PMKID",
    "reaver": "WPS",
    "hashcat": "cracking",
    "nmap": "scanning",
    "adb": "android",
    "scrcpy": "android screen",
    "pymobiledevice3": "iphone",
    "idevice_id": "iphone (paired)",
    "rtl_433": "sub-GHz sensors",
    "rtl_power": "SDR sweep",
    "proxmark3": "RFID",
}

#: where serial adapters appear, per platform
SERIAL_DIRS = ("/dev/serial/by-id", "/dev")


class Section:
    """One block of the report."""

    __slots__ = ("title", "rows", "note")

    def __init__(self, title: str, note: str = ""):
        self.title = title
        self.rows: list[tuple[str, str, bool]] = []
        self.note = note

    def add(self, name: str, detail: str, present: bool = True) -> None:
        self.rows.append((name, detail, present))

    @property
    def count(self) -> int:
        return sum(1 for _n, _d, ok in self.rows if ok)

    def table(self) -> list[list[str]]:
        return [[("+" if ok else "-"), name, detail]
                for name, detail, ok in self.rows]


def _wireless() -> Section:
    from omni.wifi import iface as iface_mod

    section = Section("wireless adapters")
    try:
        names = iface_mod.wireless_interfaces()
    except Exception as exc:                        # noqa: BLE001 - no radio
        section.note = f"probe failed: {exc}"
        return section
    for name in names:
        mode = iface_mod.current_mode(name)
        section.add(name, f"mode={mode}", mode not in ("off", "unknown"))
    if not names:
        section.note = "no wireless interface — wifi.* needs one (monitor mode)"
    return section


def _usb() -> Section:
    """USB ids on Linux; friendly names from PnP on Windows, ioreg on macOS."""
    section = Section("usb devices")
    if host.is_linux():
        for line in proc.run(["lsusb"], timeout=10).lines()[:40]:
            parts = line.split(None, 5)
            section.add(parts[0] if parts else "?", line, True)
    elif host.is_windows():
        for line in proc.run(["powershell", "-NoProfile", "-Command",
                              "Get-PnpDevice -PresentOnly | "
                              "Select-Object -ExpandProperty FriendlyName"],
                             timeout=25).lines()[:40]:
            section.add(line[:30], "present", True)
    else:
        for line in proc.run(["system_profiler", "SPUSBDataType"],
                             timeout=25).lines():
            if line.strip().endswith(":"):
                section.add(line.strip().rstrip(":")[:30], "usb", True)
    if not section.rows:
        section.note = "nothing reported (lsusb / PnP unavailable)"
    return section


def _serial() -> Section:
    section = Section("serial ports")
    for folder in SERIAL_DIRS:
        if not os.path.isdir(folder):
            continue
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for name in names:
            if name.startswith(("ttyUSB", "ttyACM", "cu.", "ttyS")):
                section.add(os.path.join(folder, name), "serial", True)
    if not section.rows:
        section.note = "no serial adapter (CC1101 / Proxmark / GPS)"
    return section


def _phones() -> Section:
    section = Section("phones")
    if proc.has("adb"):
        for line in proc.run(["adb", "devices"], timeout=20).lines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                section.add(parts[0], f"adb {parts[1]}", parts[1] == "device")
    if proc.has("idevice_id"):
        for udid in proc.run(["idevice_id", "-l"], timeout=20).lines():
            section.add(udid, "idevice (paired)", True)
    if not section.rows:
        section.note = ("no phone seen — android needs USB debugging on, "
                        "iphone needs a pair record")
    return section


def _radios() -> Section:
    section = Section("radio hardware")
    has_spi = host.is_linux() and os.path.isdir("/dev")
    section.add("CC1101 (SPI)", "spidev + GPIO" if has_spi else "Linux only",
                has_spi)
    for tool, what in (("rtl_test", "SDR dongle"), ("proxmark3", "RFID")):
        section.add(tool, what, proc.has(tool))
    return section


def _tools() -> Section:
    section = Section("external tools")
    for tool, trade in sorted(TOOLS.items()):
        found = proc.which(tool) or ""
        where = ("wsl" if str(found).startswith("wsl:") else "path") if found else ""
        detail = f"{where}: {setup.HELP.get(tool, trade)}" if found \
            else f"{setup.HELP.get(tool, trade)} — needed for {trade}"
        section.add(tool, detail, bool(found))
    section.note = ("a missing tool greys out the matching modules — install "
                    "what the attack you want needs")
    return section


def _loot() -> Section:
    section = Section("loot directory")
    from omni.core import config
    path = config.output_dir("")
    writable = os.access(path, os.W_OK)
    section.add(path, "writable" if writable else "not writable", writable)
    return section


BUILDERS = {"wireless": _wireless, "usb": _usb, "serial": _serial,
            "phones": _phones, "radios": _radios, "tools": _tools,
            "loot": _loot}


def inventory(sections: tuple[str, ...] = ()) -> list[Section]:
    """Build the report; ``sections`` limits it (blank = every block)."""
    wanted = [name for name in BUILDERS if not sections or name in sections]
    return [BUILDERS[name]() for name in wanted]


def render(sections: list[Section]) -> dict:
    """Print the report and return the same data as a dict."""
    from omni.core import console

    console.kv([("host", sys.platform), ("python", sys.version.split()[0])])
    data: dict = {}
    for section in sections:
        console.section(f"{section.title} ({section.count})")
        if section.rows:
            console.table(["", "item", "detail"], section.table())
        if section.note:
            console.info(section.note)
        data[section.title] = [{"item": name, "detail": detail, "ok": ok}
                               for name, detail, ok in section.rows]
    ready = sum(section.count for section in sections)
    total = sum(len(section.rows) for section in sections)
    console.ok(f"{ready}/{total} positive — `run core.doctor` for module "
               "readiness, `list` for the modules")
    return data

    def count(self) -> int:
        return sum(1 for _n, _d, ok in self.rows if ok)

    def table(self) -> list[list[str]]:
        return [[("+" if ok else "-"), name, detail]
                for name, detail, ok in self.rows]
