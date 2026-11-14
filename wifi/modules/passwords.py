"""Saved Wi-Fi passwords from the host's own store, per platform.

Windows: ``netsh wlan show profile key=clear`` (no elevation needed for the
current user's profiles). Linux: NetworkManager via ``nmcli``. macOS: the
current SSID through ``security`` (other saved entries need Keychain access,
which is still one command each).
"""

from __future__ import annotations

import re

from omni.core import config, console, platform as host, proc
from omni.core.module import Option
from omni.wifi.modules._base import WifiModule

__all__ = ["Passwords", "parse_nmcli_saved"]


def parse_nmcli_saved(text: str) -> list[dict]:
    """``nmcli -g name,password connection show`` -> rows (blank PSK = open)."""
    rows = []
    for line in text.splitlines():
        name, sep, password = line.partition(":")
        if not sep or not name.strip():
            continue
        rows.append({"ssid": name.strip(), "key": password.strip(),
                     "auth": "WPA2" if password.strip() else "OPEN"})
    return rows


class Passwords(WifiModule):
    NAME = "wifi.passwords"
    DESCRIPTION = "Show Wi-Fi passwords saved on this computer"
    OPTIONS = (Option("SAVE", "write them to the loot dir", "true",
                      choices=("true", "false")),)

    def execute(self) -> list[dict]:
        if host.is_windows():
            from omni.windows import wifi
            rows = wifi.keys()
        elif host.is_macos():
            ssid = proc.run(["networksetup", "-getairportnetwork", "en0"],
                            timeout=15).out.partition(":")[2].strip()
            rows = []
            if ssid:
                key = proc.run(["security", "find-generic-password", "-wa", ssid],
                               timeout=15).out.strip()
                rows.append({"ssid": ssid, "key": key, "auth": "WPA2"})
        else:
            text = proc.run(["nmcli", "-s", "-g", "name,password",
                             "connection", "show"], timeout=30).out
            rows = parse_nmcli_saved(text)
            if not rows:
                console.warn("nmcli not found, or no saved Wi-Fi connections")
        rows = [r for r in rows if r.get("ssid")]
        if not rows:
            console.warn("no saved Wi-Fi profile on this account")
            return []
        console.table(["ssid", "auth", "password"],
                      [[r["ssid"], r.get("auth", "?"),
                        r.get("key") or ("(enterprise)"
                                         if "Enterprise" in r.get("auth", "")
                                         else "(open)")] for r in rows])
        if self.get_bool("SAVE", True):
            import json
            out = f"{config.output_dir('wifi')}/passwords.json"
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, indent=2)
            console.ok(f"{len(rows)} profile(s) -> {out}")
        return rows
