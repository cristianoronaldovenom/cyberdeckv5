"""Read HTTPS metadata: SNI, certificate names and DNS, without a key.

Run against a capture file, or let it capture for you on an interface. This is
the "what is this client doing" read-out that stays available when HTTPS stops
you at the ciphertext — and the same pass runs ``wifi.extract`` when you do
hold a PSK, so plaintext HTTP and credentials come out too.
"""

from __future__ import annotations

import json
import os
import time

from omni.core import config, console, platform as host, proc
from omni.core.module import Option
from omni.wifi import extract, pcapread, tlsmeta
from omni.wifi.modules._base import WifiModule

__all__ = ["Tls"]


class Tls(WifiModule):
    NAME = "wifi.tls"
    DESCRIPTION = "Extract SNI / certificate names / DNS out of HTTPS traffic"
    OPTIONS = (Option("PCAP", "capture to read"),
               Option("IFACE", "or capture here instead"),
               Option("SECONDS", "capture length when IFACE is used", "30"),
               Option("PSK", "optional key: also decrypt what is decryptable"),
               Option("OUT", "output directory"))

    def execute(self) -> dict:
        path = self.get("PCAP")
        if not path and self.get("IFACE"):
            path = self._capture(self.get("IFACE"), self.get_int("SECONDS", 30))
        if not path:
            raise ValueError("give PCAP= or IFACE= (with SECONDS=)")
        if not os.path.isfile(path):
            raise FileNotFoundError(f"no such capture: {path}")

        report = tlsmeta.report(path)
        console.kv([("capture", path), ("hosts", str(len(report["hosts"]))),
                    ("encrypted frames", str(report["encrypted_frames"]))])
        for name in report["sni"][:25]:
            console.info(f"sni      {name}")
        for name in report["cert_cn"][:25]:
            console.info(f"cert-cn  {name}")
        for name in report["dns"][:25]:
            console.info(f"dns      {name}")

        out = os.path.expanduser(
            self.get("OUT") or os.path.join(config.output_dir("wifi/tls"),
                                            time.strftime("%Y%m%d_%H%M%S")))
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "tls.json"), "w", encoding="utf-8",
                  newline="\n") as fh:
            json.dump(report, fh, indent=2)
            fh.write("\n")
        if self.get("PSK"):
            keys = self._keys(path)
            if not keys:
                console.warn("no SSID in the capture to match the passphrase to")
            else:
                decoded = extract.extract([path], keys, out)
                report["creds"] = [list(c) for c in decoded.creds]
                console.ok(f"{len(decoded.creds)} credential(s) recovered "
                           f"({decoded.frames} frame(s) decrypted)")
        console.ok(f"{len(report['hosts'])} host name(s) -> {out}")
        if not report["hosts"]:
            console.warn("nothing decodable — encrypted (CCMP) captures need "
                         "PSK/keys, open ones only carry traffic after a join")
        return report

    def _keys(self, path: str) -> dict[str, str]:
        """Keys from PSK (a file of ``ssid:psk`` lines, or one passphrase)."""
        given = os.path.expanduser(self.get("PSK"))
        if os.path.isfile(given):
            return extract.load_keys(extract.read_text(given))
        try:
            names = pcapread.ssid_map(path).values()
        except (pcapread.PcapError, OSError):
            return {}
        return {name.decode("utf-8", "replace"): self.get("PSK")
                for name in names if name}

    def _capture(self, iface: str, seconds: int) -> str:
        proc.require("tcpdump", "install tcpdump to capture here")
        folder = config.output_dir("wifi/tls")
        os.makedirs(folder, exist_ok=True)
        target = os.path.join(folder,
                              f"sniff_{time.strftime('%Y%m%d_%H%M%S')}.pcap")
        console.info(f"capturing on {iface} for {seconds}s")
        # the timeout *is* the capture length: tcpdump is killed, file stays
        proc.run(host.root_argv(["tcpdump", "-i", iface, "-U", "-w", target,
                                 "-s", "0"]), timeout=max(5, seconds))
        return target
