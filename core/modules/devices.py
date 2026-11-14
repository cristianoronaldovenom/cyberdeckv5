"""This box right now: adapters, phones, radios, tools and loot (``omni devices``).

Read-only and cheap. Every probe returns a row whether or not it is present,
so an empty section is an answer too ("no adapter" explains a later failure).
"""

from __future__ import annotations

from omni.core import console, devices
from omni.core.module import Module, Option

__all__ = ["Devices"]


class Devices(Module):
    NAME = "core.devices"
    DESCRIPTION = "Inventory this host: adapters, phones, radios, tools, loot"
    FAMILY = "core"
    OPTIONS = (Option("SECTIONS",
                      "comma list: wireless,usb,serial,phones,radios,tools,loot",
                      ""),)

    def execute(self) -> dict:
        wanted = tuple(part.strip().lower()
                       for part in self.get("SECTIONS").split(",")
                       if part.strip())
        return devices.render(devices.inventory(wanted))
