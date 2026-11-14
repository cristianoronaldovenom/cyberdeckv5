"""iOS family: device inventory, pairing and lockdown info."""

from __future__ import annotations

from omni.core import console
from omni.core.module import Option
from omni.ios.modules._base import IosModule

__all__ = ["Devices", "Info", "Pair"]


class Devices(IosModule):
    NAME = "ios.devices"
    DESCRIPTION = "List attached iPhones/iPads (UDID, name, state)"
    OPTIONS = ()

    def execute(self) -> dict:
        client = self.client()
        devices = client.devices()
        if not devices:
            console.warn("no device found — unlock it and tap Trust")
            return {"devices": []}
        console.table(["udid", "name", "state", "link"],
                      [[d.udid, d.name, d.state, d.connection]
                       for d in devices])
        console.info(f"use one with: omni config set ios.udid <udid>")
        return {"devices": [d.udid for d in devices]}


class Info(IosModule):
    NAME = "ios.info"
    DESCRIPTION = "Device identity and lockdown values (no Developer Mode needed)"
    OPTIONS = (Option("UDID", "target UDID"),)

    KEYS = ("DeviceName", "ProductType", "ProductVersion", "BuildVersion",
            "SerialNumber", "UniqueDeviceID", "CPUArchitecture", "RegionInfo")

    def execute(self) -> dict:
        client = self.client()
        found = client.info()
        rows = [[key, str(found.get(key, ""))] for key in self.KEYS
                if found.get(key)]
        console.table(["field", "value"], rows or [["-", "no output"]])
        return {key: str(found.get(key, "")) for key in self.KEYS if found.get(key)}


class Pair(IosModule):
    NAME = "ios.pair"
    DESCRIPTION = "Pair with the device (tap Trust when prompted)"
    OPTIONS = (Option("UDID", "target UDID"),)

    def execute(self) -> dict:
        client = self.client()
        if client.is_paired():
            console.info("already paired")
            return {"paired": True}
        out = client.pair()
        console.ok("paired — confirm the Trust prompt on the device")
        return {"paired": True, "output": out.strip()[-200:]}
