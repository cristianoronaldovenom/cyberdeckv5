"""List attached devices and pick one."""

from __future__ import annotations

from omni.android.adb import Adb
from omni.core import console, proc
from omni.core.module import Module


class Devices(Module):
    NAME = "android.devices"
    DESCRIPTION = "List attached/paired devices and select the working one"
    FAMILY = "android"
    NEEDS = ("adb",)

    def execute(self) -> list[dict]:
        if not proc.has("adb"):
            console.warn("adb is not installed — " + proc.install_hint("adb"))
        client = Adb()
        found = client.devices()
        if not found:
            console.warn("nothing attached — enable USB debugging and accept "
                         "the RSA prompt on the device")
            return []
        console.table(["serial", "state", "model", "transport"],
                      [[d.serial, d.state, d.model or "-", d.transport]
                       for d in found])
        if client.serial and any(d.serial == client.serial and d.usable
                                 for d in found):
            console.ok(f"selected: {client.serial}")
        else:
            picked = client.pick()
            if picked:
                console.ok(f"selected: {picked.serial}")
        return [{"serial": d.serial, "state": d.state} for d in found]
