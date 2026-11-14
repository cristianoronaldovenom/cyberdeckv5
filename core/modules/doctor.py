"""Housekeeping: dependency and hardware readiness matrix (``omni doctor``)."""

from __future__ import annotations

import os
import platform
import shutil

from omni.core import console, platform as host, proc
from omni.core.module import Option
from omni.core.module import Module, registry

__all__ = ["Doctor"]

#: family -> tools whose absence limits that trade
FAMILY_TOOLS = {
    "wifi": ("airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
             "hcxdumptool", "hcxpcapngtool", "wash", "reaver", "iw", "mdk4",
             "hostapd", "dnsmasq"),
    "radio": ("rtl_433", "rtl_power", "rtl_fm", "pm3", "nfc-list", "mode2",
              "ir-ctl", "hciconfig", "lsusb"),
    "car": ("iw", "python3"),
    "brute": ("hashcat", "john", "hydra", "rockyou.txt"),
    "pentest": ("nmap", "nikto", "whatweb"),
    "android": ("adb", "scrcpy"),
    "ios": ("pymobiledevice3", "ideviceinfo", "idevicescreenshot", "usbmuxd",
            "ifuse"),
    "mobile": ("frida", "jadx", "apktool"),
}

#: capability gates that need a device node, not just a binary
HARDWARE = {
    "cc1101 spi": ("/dev/spidev0.0", "/dev/spidev0.1"),
    "wifi adapter": ("/sys/class/net",),
    "ir receiver": ("/dev/lirc0",),
    "hid gadget": ("/dev/hidg0",),
}


#: how to install a missing package on this host
_INSTALL_HINT = ("winget install <id> (or `omni setup`)"
                 if host.is_windows()
                 else "brew install <pkg>" if host.is_macos()
                 else "sudo apt install <pkg>")


def _tool_state(tool: str) -> tuple[bool, str]:
    if shutil.which(tool):
        return True, shutil.which(tool) or ""
    for root in ("/usr/share/wordlists", "/usr/share/seclists"):
        candidate = os.path.join(root, tool)
        if os.path.exists(candidate):
            return True, candidate
    return False, ""


class Doctor(Module):
    NAME = "core.doctor"
    DESCRIPTION = "Report tool/hardware readiness per trade (Kali first)"
    FAMILY = "core"
    OPTIONS = (Option("FAMILY", "only check one trade"),)

    def execute(self) -> dict:
        is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else "n/a"
        console.kv([("platform", platform.platform()),
                    ("python", platform.python_version()),
                    ("root", "yes" if is_root is True else
                     "no" if is_root is False else "n/a")])
        families = ([self.get("FAMILY")] if self.get("FAMILY")
                    else list(FAMILY_TOOLS))
        report: dict = {"families": {}, "hardware": {}, "missing_total": 0}
        for family in families:
            tools = FAMILY_TOOLS.get(family, ())
            missing = []
            for tool in tools:
                ok, where = _tool_state(tool)
                if ok:
                    console.debug(f"{family}: {tool} -> {where}")
                else:
                    missing.append(tool)
            registered = len(registry.all(family))
            modules = [m.NAME for m in registry.all(family)
                       if any(not proc.has(t) for t in m.NEEDS)]
            report["families"][family] = {
                "missing": missing, "modules": registered,
                "blocked_modules": len(modules)}
            report["missing_total"] += len(missing)
            console.table(["family", "modules", "missing tools"],
                          [[family, str(registered), ", ".join(missing) or "-"]])
        for label, paths in HARDWARE.items():
            if label == "wifi adapter":
                present = bool(host.wireless_interfaces())
            else:
                present = any(os.path.exists(p) for p in paths)
            report["hardware"][label] = present
        console.table(["hardware", "present"],
                      [[k, "yes" if v else "no"]
                       for k, v in report["hardware"].items()])
        if report["missing_total"] == 0:
            console.ok("all checked tools present")
        else:
            console.warn(f"{report['missing_total']} tool(s) missing — install "
                         f"with: {_INSTALL_HINT} (see install.sh)")
        return report
