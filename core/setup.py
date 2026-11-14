"""Install the external tools a task needs, per platform, without leaving the app.

The menu warns "missing tool(s)" and that was a dead end. This turns the warning
into an offer: one command per tool from the platform's own package manager
(``winget`` / ``brew`` / ``apt``) or from ``pip`` for the Python-side tools
(``pymobiledevice3`` is a CLI we drive, so it is a tool, not a dependency).

Nothing here is required for the toolkit to start — it is the "make it work"
step for the features that shell out, and every command is shown before it runs
and can be skipped. A failed install never aborts the rest: the report says what
landed and the caller can re-check.
"""

from __future__ import annotations

import os

from omni.core import console, platform as host, proc

__all__ = ["PLAN", "PIP", "RECOMMENDED", "recommended", "plan_for", "missing",
           "install", "backend", "rows"]

#: tool -> (winget id, brew formula, apt package) — blank means "not packaged"
PLAN = {
    "tshark": ("WiresharkFoundation.Wireshark", "wireshark", "tshark"),
    "nmap": ("Insecure.Nmap", "nmap", "nmap"),
    "wireshark": ("WiresharkFoundation.Wireshark", "wireshark", "wireshark"),
    "adb": ("Google.PlatformTools", "android-platform-tools",
            "android-tools-adb"),
    "scrcpy": ("Genymobile.scrcpy", "scrcpy", "scrcpy"),
    "hashcat": ("Hashcat.Hashcat", "hashcat", "hashcat"),
    "aircrack-ng": ("", "aircrack-ng", "aircrack-ng"),
    "mdk4": ("", "mdk4", "mdk4"),
    "hostapd": ("", "hostapd", "hostapd"),
    "dnsmasq": ("", "dnsmasq", "dnsmasq"),
    "tcpdump": ("", "tcpdump", "tcpdump"),
    "reaver": ("", "reaver", "reaver"),
    "hcxdumptool": ("", "hcxdumptool", "hcxdumptool"),
}

#: tools that are a pip package, not a system package
PIP = {"pymobiledevice3": "pymobiledevice3", "idevice_id": "",
        "frida": "frida-tools"}

#: a small, quick set that unlocks most modules on each host
RECOMMENDED = {
    "windows": ("nmap", "adb", "hashcat", "tshark"),
    "macos": ("nmap", "adb", "hashcat", "tshark"),
    "linux": ("nmap", "aircrack-ng", "hcxdumptool", "adb", "hashcat",
              "tshark", "reaver"),
}


def recommended() -> list[str]:
    """Tools worth installing first on this platform (present ones dropped)."""
    if host.is_windows():
        wanted = RECOMMENDED["windows"]
    elif host.is_macos():
        wanted = RECOMMENDED["macos"]
    else:
        wanted = RECOMMENDED["linux"]
    return missing(wanted)

#: one plain line per tool, because "hostapd" means nothing on its own
HELP = {
    "hostapd": "runs the fake access point (the network people join)",
    "dnsmasq": "hands out DHCP and DNS to whoever joins the fake network",
    "tcpdump": "captures packets for the sniffer (pktmon replaces it on Windows)",
    "mdk4": "floods: fake beacons, auth requests, deauth",
    "aireplay-ng": "sends deauth frames (legacy aircrack-ng tool)",
    "airodump-ng": "scans APs and clients",
    "aircrack-ng": "cracks the captured handshake",
    "hcxdumptool": "harvests PMKID hashes without a client",
    "reaver": "WPS PIN attack",
    "tshark": "Wireshark CLI: fields, HTTP, TLS decryption",
    "nmap": "port scanning",
    "adb": "talks to Android devices",
    "scrcpy": "Android screen mirroring",
    "pymobiledevice3": "talks to iPhones",
    "hashcat": "GPU hash cracking",
    "pktmon": "Windows packet capture (built in)",
}


def explain(tools: tuple[str, ...] | list[str]) -> list[str]:
    """``tool — what it does`` lines for the console."""
    return [f"{tool} — {HELP.get(tool, 'see packaging/README.md')}"
            for tool in tools]



def backend() -> str:
    """Which installer this host has: winget / brew / apt / pip-only."""
    if host.is_windows():
        return "winget" if proc.has("winget") else "none"
    if host.is_macos():
        return "brew" if proc.has("brew") else "none"
    if host.is_linux():
        return "apt" if proc.has("apt-get") else "none"
    return "none"


def _argv(tool: str) -> list[str]:
    """The install command for one tool on this host (``[]`` when unknown)."""
    if tool in PIP and PIP[tool]:
        return [os.environ.get("PYTHON", "python"), "-m", "pip", "install",
                "--user", PIP[tool]]
    entry = PLAN.get(tool)
    if not entry:
        return []
    choice = backend()
    winget_id, formula, package = entry
    if choice == "winget" and winget_id:
        return ["winget", "install", "--id", winget_id, "--silent",
                "--accept-package-agreements", "--accept-source-agreements"]
    if choice == "brew" and formula:
        return ["brew", "install", formula]
    if choice == "apt" and package:
        return ["sudo", "apt-get", "install", "-y", package]
    # a Linux-only tool on a Windows host: install it *inside* WSL, which is
    # where the radio stack actually lives on this platform. `-u root` avoids
    # sudo's password prompt, which a menu run cannot answer.
    if host.is_windows() and package and proc.has("wsl"):
        return ["wsl", "-u", "root", "apt-get", "install", "-y", package]
    return []


def wsl_missing() -> bool:
    """Windows without WSL: the wireless tools have nowhere to come from."""
    return host.is_windows() and not proc.has("wsl")


def wsl_plan() -> list[str]:
    """The command that installs WSL itself (one reboot, then reboot-free)."""
    return ["wsl", "--install", "-d", "Ubuntu"]



def missing(tools: tuple[str, ...] | list[str]) -> list[str]:
    return [tool for tool in tools if not proc.has(tool)]


def plan_for(tools: tuple[str, ...] | list[str]) -> list[tuple[str, list[str]]]:
    """``[(tool, argv)]`` for the tools that are missing and installable."""
    return [(tool, _argv(tool)) for tool in missing(tools) if _argv(tool)]


def rows(tools: tuple[str, ...] | list[str]) -> list[list[str]]:
    plan = plan_for(tools)
    return [[tool, " ".join(argv)] for tool, argv in plan]


def install(tools: tuple[str, ...] | list[str], timeout: int = 900,
            dry: bool = False) -> dict:
    """Install what is missing; returns ``{installed, failed, skipped}``."""
    plan = plan_for(tools)
    stuck = [tool for tool in missing(tools)
             if not _argv(tool)]
    if not plan:
        console.warn("nothing installable for: " + (", ".join(stuck) or "-"))
        return {"installed": [], "failed": [], "skipped": stuck}
    console.table(["tool", "command"], [[tool, " ".join(argv)]
                                        for tool, argv in plan])
    for tool, argv in plan:
        console.info(f"installing {tool} …")
        if dry:
            continue
        res = proc.run(argv, timeout=timeout)
        if not res.ok:
            console.warn(f"{tool}: {res.text.strip()[:160]}")
    result = {"installed": [tool for tool, _a in plan if proc.has(tool)],
              "failed": [tool for tool, _a in plan if not proc.has(tool)],
              "skipped": stuck, "backend": backend(), "dry": dry}
    proc.clear_cache()
    if not dry:
        result = {"installed": [tool for tool, _a in plan if proc.has(tool)],
                  "failed": [tool for tool, _a in plan if not proc.has(tool)],
                  "skipped": stuck, "backend": backend(), "dry": dry}
        if result["installed"]:
            console.ok(f"installed: {', '.join(result['installed'])}")
        if result["failed"]:
            console.warn(f"still missing after install: "
                         f"{', '.join(result['failed'])} (a new shell may be "
                         "needed for PATH)")
    return result
