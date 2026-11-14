"""Access-point / client discovery: ``iw`` scan and ``airodump-ng`` CSV.

Both parsers are pure functions over captured text so they are unit-testable
without a radio.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import tempfile
import time

from omni.core import config, proc
from omni.core.util import slug

__all__ = [
    "parse_iw_scan", "parse_airodump_csv", "parse_netsh", "scan_iw",
    "scan_airodump", "scan_netsh", "scan_any", "ranked", "save_targets",
    "SECURITY_ORDER",
]

#: ordered worst-to-best, used to rank the weakest security seen
SECURITY_ORDER = ["OPEN", "WEP", "WPA", "WPA2", "WPA3", "WPS"]


def parse_iw_scan(text: str) -> list[dict]:
    """Parse ``iw dev <if> scan`` output into AP dicts."""
    aps: list[dict] = []
    cur: dict | None = None
    for line in text.splitlines():
        m = re.match(r"^BSS ([0-9a-fA-F:]{17})", line)
        if m:
            cur = {"bssid": m.group(1).lower(), "ssid": "", "channel": None,
                   "signal": None, "security": set(), "wps": False}
            aps.append(cur)
            continue
        if cur is None:
            continue
        stripped = line.strip()
        if stripped.startswith("SSID:"):
            cur["ssid"] = stripped.partition(":")[2].strip()
        elif stripped.startswith("signal:"):
            mm = re.search(r"(-?\d+(?:\.\d+)?)", stripped)
            if mm:
                cur["signal"] = float(mm.group(1))
        elif stripped.startswith("* channel:"):
            mm = re.search(r"(\d+)", stripped)
            if mm:
                cur["channel"] = int(mm.group(1))
        elif stripped.startswith("primary channel:"):
            mm = re.search(r"(\d+)", stripped)
            if mm and cur["channel"] is None:
                cur["channel"] = int(mm.group(1))
        elif re.search(r"Authentication suites:.*SAE", stripped):
            cur["security"].discard("WPA2")
            cur["security"].add("WPA3")
        elif "RSN:" in stripped:
            cur["security"].add("WPA2")
        elif "WPA:" in stripped:
            cur["security"].add("WPA")
        elif "WPS:" in stripped:
            cur["wps"] = True
    out = []
    for ap in aps:
        sec = ap.pop("security")
        if not sec:
            label = "WPS" if ap["wps"] else "OPEN"
        else:
            label = "/".join(sorted(sec)) or "OPEN"
        ap["security"] = label
        out.append(ap)
    return out


def _int(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _security_from_cipher(privacy: str, cipher: str, auth: str) -> str:
    """Map airodump privacy/cipher/auth columns onto a security label."""
    privacy = (privacy or "").strip()
    if privacy.upper().startswith("WEP"):
        return "WEP"
    if not privacy:
        return "OPEN"
    auth = (auth or "").upper()
    if "SAE" in auth:
        return "WPA3"
    return "WPA2"


def scan_iw(iface: str, settle: float = 3.0) -> list[dict]:
    """Active scan through ``iw`` (needs managed mode)."""
    proc.require("iw")
    time.sleep(max(0.0, settle))
    res = proc.run(["iw", "dev", iface, "scan"], timeout=60)
    if not res.ok and "busy" in res.text.lower():
        res = proc.run(["iw", "dev", iface, "scan", "passive"], timeout=60)
    return parse_iw_scan(res.out)


def parse_netsh(text: str) -> list[dict]:
    """Parse ``netsh wlan show networks mode=bssid`` into the same AP dicts.

    The output is localised, so labels are matched by shape as well as text:
    SSID lines, BSSID lines, ``Signal : NN%`` and ``Authentication``.
    """
    aps: list[dict] = []
    cur: dict | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("ssid ") and ":" in line:
            cur = {"bssid": "", "ssid": line.partition(":")[2].strip(),
                   "channel": None, "signal": None, "security": "OPEN"}
            aps.append(cur)
            continue
        if cur is None:
            continue
        if "bssid" in low and ":" in line:
            match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
            if match:
                cur["bssid"] = match.group(1).lower()
        elif "signal" in low and ":" in line:
            match = re.search(r"(\d+)%", line)
            if match:
                # netsh reports 0..100 %, map it onto the dBm range used by iw
                cur["signal"] = round(int(match.group(1)) / 2.0 - 100.0, 1)
        elif "channel" in low or "canal" in low or "kanal" in low:
            match = re.search(r":\s*(\d+)", line)
            if match and cur["channel"] is None:
                cur["channel"] = int(match.group(1))
        elif "authentication" in low or "authentification" in low:
            value = line.partition(":")[2].strip().upper()
            if not value or "OPEN" in value:
                cur["security"] = "OPEN"
            elif "WEP" in value:
                cur["security"] = "WEP"
            elif "SAE" in value or "WPA3" in value:
                cur["security"] = "WPA3"
            elif "WPA" in value:
                cur["security"] = "WPA2" if "2" not in value else "WPA2"
    return [ap for ap in aps if ap["bssid"]]


def scan_netsh() -> list[dict]:
    """Windows scan through ``netsh wlan show networks`` (no extra tools)."""
    res = proc.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                   timeout=40, env={"PYTHONIOENCODING": "utf-8"})
    return parse_netsh(res.out)


def scan_any(iface: str = "") -> list[dict]:
    """Best available scan: netsh on Windows, iw elsewhere, then airodump."""
    from omni.core import platform as host
    if host.is_windows():
        return scan_netsh()
    if proc.has("iw") and iface:
        return scan_iw(iface)
    if proc.has("airodump-ng"):
        return scan_airodump(iface or "wlan0mon")
    return []


def scan_airodump(mon_iface: str, seconds: int = 25,
                  band: str = "abg") -> list[dict]:
    """Passive scan through airodump-ng into a throwaway CSV."""
    proc.require("airodump-ng")
    with tempfile.TemporaryDirectory() as tmp:
        prefix = os.path.join(tmp, "omni-scan")
        proc.run(["airodump-ng", "-i", mon_iface, "--band", band,
                  "--output-format", "csv", "-w", prefix],
                 timeout=max(15, seconds + 20))
        csv_path = prefix + "-01.csv"
        if not os.path.exists(csv_path):
            return []
        with open(csv_path, "r", encoding="utf-8", errors="replace") as fh:
            return parse_airodump_csv(fh.read())


def ranked(aps: list[dict]) -> list[dict]:
    """Weakest security first, then strongest signal."""
    def key(ap: dict):
        sec = (ap.get("security") or "OPEN").upper()
        rank = next((i for i, s in enumerate(SECURITY_ORDER) if sec.startswith(s)),
                    99)
        return (rank, -(ap.get("signal") or -999))

    return sorted(aps, key=key)


def save_targets(aps: list[dict], name: str = "targets") -> str:
    """Write a JSON target list into the loot directory."""
    path = os.path.join(config.output_dir("wifi"), f"{slug(name)}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(aps, fh, indent=2)
    return path

    if privacy.upper().startswith("WEP"):
        return "WEP"
    if not privacy:
        return "OPEN"
    auth = (auth or "").upper()
    if "SAE" in auth:
        return "WPA3"
    if "PSK" in auth or "MGT" in auth:
        return "WPA2"
    return "WPA"


def parse_airodump_csv(text: str) -> list[dict]:
    """Parse an ``airodump-ng --output-format csv`` capture (AP section only)."""
    rows: list[dict] = []
    section = ""
    reader = csv.reader(io.StringIO(text))
    header_ap: list[str] | None = None
    for raw in reader:
        cells = [c.strip() for c in raw]
        if not any(cells):
            continue
        if cells[0].startswith("BSSID"):
            header_ap = cells
            section = "ap"
            continue
        if cells[0].startswith("Station MAC"):
            section = "station"
            continue
        if section != "ap" or header_ap is None:
            continue
        rec = dict(zip(header_ap, cells))
        if not re.match(r"^[0-9a-fA-F:]{17}$", rec.get("BSSID", "")):
            continue
        rows.append({
            "bssid": rec["BSSID"].lower(),
            "ssid": rec.get("ESSID", ""),
            "channel": _int(rec.get("channel")),
            "signal": _int(rec.get("Power")),
            "security": _security_from_cipher(rec.get("Privacy", ""),
                                              rec.get("Cipher", ""),
                                              rec.get("Authentication", "")),
            "beacons": _int(rec.get("# beacons")),
            "data": _int(rec.get("# data")),
        })
    return rows
