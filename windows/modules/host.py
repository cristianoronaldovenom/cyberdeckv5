"""Wi-Fi key recovery and host recon."""

from __future__ import annotations

from omni.core import console
from omni.core.module import Option
from omni.windows import recon, wifi
from omni.windows.modules._base import WindowsModule


class WifiKeys(WindowsModule):
    NAME = "windows.wifi"
    DESCRIPTION = "Dump saved WLAN profiles with their cleartext PSKs"

    def execute(self) -> list[dict]:
        rows = wifi.keys()
        console.table(["ssid", "auth", "key"],
                      [[r["ssid"], r["auth"],
                        r["key"] or ("(enterprise)" if "Enterprise" in r["auth"]
                                     else "(open)")] for r in rows])
        return rows


class Recon(WindowsModule):
    NAME = "windows.recon"
    DESCRIPTION = "Host triage: users, admins, AV, shares, autoruns"
    OPTIONS = (Option("WHAT", "users|admins|av|shares|autoruns|software|defender",
                      "users", choices=("users", "admins", "av", "shares",
                                        "autoruns", "software", "defender")),)

    def execute(self) -> list[str]:
        what = self.get("WHAT")
        fn = {"users": recon.users, "admins": recon.administrators,
              "av": recon.antivirus, "shares": recon.shares,
              "autoruns": recon.autoruns,
              "software": recon.installed_software}[what] \
            if what != "defender" else None
        rows = fn() if fn else recon.defender_status().splitlines()
        for row in rows:
            console.info(row)
        return rows
