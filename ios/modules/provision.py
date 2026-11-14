"""iOS takeover: configuration profiles and app payload install/remove.

A configuration profile is the closest thing iOS has to "root the boring way":
it can install a trusted CA, set an HTTP proxy, restrict features, or supervise
the device — and the *stock* install path takes a `.mobileconfig` silently.

Requires Developer Mode only for `profile supervise`; the rest work on a
device that merely trusts the host.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.ios.modules._base import IosModule

__all__ = ["Profiles", "ProfileInstall", "ProfileRemove", "AppInstall",
           "AppUninstall"]


class Profiles(IosModule):
    NAME = "ios.profiles"
    DESCRIPTION = "List installed configuration profiles"
    NEEDS = ("pymobiledevice3",)

    def execute(self) -> dict:
        out = self.client().check("profile", "list").out
        console.info(out.strip())
        return {"output": out.strip()}


class ProfileInstall(IosModule):
    NAME = "ios.profile_install"
    DESCRIPTION = "Install a .mobileconfig (CA, proxy, restrictions, supervise)"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("PROFILE", ".mobileconfig file", "", required=True),
               Option("KEYBAG", "keybag for supervise mode"))

    def execute(self) -> dict:
        client = self.client()
        path = os.path.expanduser(self.get("PROFILE"))
        if not os.path.isfile(path):
            raise FileNotFoundError(f"no such profile: {path}")
        args = ["profile", "install", path]
        if self.get("KEYBAG"):
            args += ["--keybag", os.path.expanduser(self.get("KEYBAG"))]
        client.check(*args, timeout=300)
        console.ok(f"profile installed — confirm the prompt on the device")
        return {"profile": path}


class ProfileRemove(IosModule):
    NAME = "ios.profile_remove"
    DESCRIPTION = "Remove an installed configuration profile"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("IDENTIFIER", "profile identifier", "", required=True))

    def execute(self) -> dict:
        self.client().check("profile", "remove", self.get("IDENTIFIER"))
        console.ok(f"removed {self.get('IDENTIFIER')}")
        return {"removed": self.get("IDENTIFIER")}


class AppInstall(IosModule):
    NAME = "ios.app_install"
    DESCRIPTION = "Install an IPA/app bundle onto the device"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("PATH", "path to .ipa or .app", "", required=True))

    def execute(self) -> dict:
        client = self.client()
        path = os.path.expanduser(self.get("PATH"))
        if not os.path.exists(path):
            raise FileNotFoundError(f"no such app payload: {path}")
        client.check("apps", "install", path, timeout=900)
        console.ok(f"installed {path}")
        return {"installed": path}


class AppUninstall(IosModule):
    NAME = "ios.app_uninstall"
    DESCRIPTION = "Remove an app by bundle identifier"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("BUNDLE", "bundle identifier", "", required=True))

    def execute(self) -> dict:
        self.client().check("apps", "uninstall", self.get("BUNDLE"))
        console.ok(f"uninstalled {self.get('BUNDLE')}")
        return {"uninstalled": self.get("BUNDLE")}
