"""Windows Wi-Fi profile harvesting (``netsh``) with key recovery."""

from __future__ import annotations

import re

from omni.core import proc

__all__ = ["profiles", "profile_detail", "keys", "wlan_report"]


def profiles() -> list[str]:
    """Names of every saved WLAN profile."""
    res = proc.run(["netsh", "wlan", "show", "profiles"], timeout=60)
    return re.findall(r"All User Profile\s*:\s*(.+)", res.out)


def profile_detail(name: str) -> dict:
    """Full profile XML-ish dump including the cleartext key."""
    res = proc.run(["netsh", "wlan", "show", "profile", f"name={name}",
                    "key=clear"], timeout=60)
    data = {"name": name, "raw": res.text}
    for label, key in (("Authentication", "auth"), ("Cipher", "cipher"),
                       ("Key Content", "key"), ("SSID name", "ssid")):
        m = re.search(rf"{label}\s*:\s*(.+)", res.out)
        if m:
            data[key] = m.group(1).strip().strip('"')
    return data


def keys() -> list[dict]:
    """Every saved profile with its PSK (empty when the profile is open)."""
    out = []
    for name in profiles():
        detail = profile_detail(name)
        out.append({"ssid": detail.get("ssid", name),
                    "auth": detail.get("auth", "?"),
                    "key": detail.get("key", "")})
    return out


def wlan_report() -> dict:
    """Interface state plus the key table, ready for JSON output."""
    iface = proc.run(["netsh", "wlan", "show", "interfaces"], timeout=60).text
    return {"interfaces": iface, "profiles": keys()}
