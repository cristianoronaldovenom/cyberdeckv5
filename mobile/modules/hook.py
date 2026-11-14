"""Frida hooking helper: attach a script to a running app."""

from __future__ import annotations

from omni.core import console
from omni.core.module import Option
from omni.mobile.modules._base import MobileModule

__all__ = ["Hook"]


class Hook(MobileModule):
    NAME = "mobile.hook"
    DESCRIPTION = "Inject a Frida script into a running app (needs frida)"
    NEEDS = ("frida",)
    OPTIONS = (Option("APP", "target package / process", "", required=True),
               Option("SCRIPT", "path to the .js agent", ""),
               Option("DEVICE", "frida device id (gadget default)", ""))

    def execute(self) -> str:
        import subprocess  # frida is an optional dependency, import lazily

        script = self.get("SCRIPT")
        if not script or not script.endswith(".js"):
            raise ValueError("SCRIPT must point to a Frida agent (.js)")
        argv = ["frida", *(["-D", self.get("DEVICE")] if self.get("DEVICE") else []),
                "-f", self.get("APP"), "-l", script]
        console.info(f"frida: attaching {self.get('APP')} with {script}")
        return subprocess.run(argv, check=False).returncode
