"""Bluetooth recon: adapter state, classic inquiry, BLE scan, link quality."""

from __future__ import annotations

import re

from omni.core import proc

__all__ = ["adapters", "inquiry", "ble_scan", "parse_inquiry", "parse_ble",
           "spoofable", "rssi"]


def adapters() -> list[dict]:
    if not proc.has("hciconfig"):
        return []
    res = proc.run(["hciconfig"], timeout=15)
    out = []
    for block in re.split(r"(?=^hci\d+)", res.out, flags=re.MULTILINE):
        m = re.match(r"^(hci\d+):\s*(\S+)", block)
        if not m:
            continue
        addr = re.search(r"BD Address:\s*([0-9A-F:]{17})", block)
        out.append({"dev": m.group(1), "state": m.group(2),
                    "address": addr.group(1) if addr else ""})
    return out


def parse_inquiry(text: str) -> list[dict]:
    """Parse ``hcitool scan`` output."""
    rows = []
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9A-F:]{17})\s+(.+)$", line.strip(), re.IGNORECASE)
        if m and m.group(2).strip():
            rows.append({"address": m.group(1).upper(), "name": m.group(2)})
    return rows


def inquiry(seconds: int = 15) -> list[dict]:
    """Classic discoverable-device scan."""
    proc.require("hcitool", "apt install bluez")
    res = proc.run(["hcitool", "scan", "--length", str(min(48, int(seconds)))],
                   timeout=60)
    return parse_inquiry(res.out)


def parse_ble(text: str) -> list[dict]:
    """Parse ``hcitool lescan`` output."""
    rows = []
    for line in text.splitlines():
        if line.startswith("LE Scan"):
            continue
        m = re.match(r"^\s*([0-9A-F:]{17})\s*(.*)$", line.strip(), re.IGNORECASE)
        if m:
            rows.append({"address": m.group(1).upper(), "name": m.group(2)})
    return rows


def ble_scan(seconds: int = 10) -> list[dict]:
    proc.require("hcitool", "apt install bluez")
    res = proc.run(["hcitool", "lescan", "--duplicates"],
                   timeout=max(3, int(seconds)))
    return parse_ble(res.out)


def spoofable() -> list[dict]:
    """Adapters that report a BD address (i.e. can be renamed/spoofed)."""
    return [a for a in adapters() if a["address"]]


def rssi(address: str, dev: str = "hci0") -> dict:
    """Poll the RSSI of a connected device (handy for distance estimation)."""
    proc.require("hcitool", "apt install bluez")
    res = proc.run(["hcitool", "-i", dev, "rssi", address], timeout=15)
    m = re.search(r"RSSI return value:\s*(-?\d+)", res.out)
    dbm = int(m.group(1)) if m else None
    # free-space path loss with a 2.4 GHz reference at 1 m (-59 dBm typical)
    metres = round(10 ** ((-59 - dbm) / 20.0), 2) if dbm else None
    return {"address": address, "rssi": dbm, "approx_metres": metres}
