"""Inspect a Flipper firmware bundle (.uf2 / zipped update)."""

import json

from omni.core import console
from omni.core.module import Option
from omni.flip import firmware
from omni.flip.modules._base import FlipModule

__all__ = ["Firmware"]


class Firmware(FlipModule):
    NAME = "flip.firmware"
    DESCRIPTION = "Inspect a firmware bundle: entries, format, firmware part"
    OPTIONS = (Option("BUNDLE", "path to .uf2/.zip", "", required=True),)

    def execute(self) -> dict:
        info = firmware.inspect_bundle(self.get("BUNDLE"))
        console.table(["field", "value"],
                      [[k, str(v)[:80]] for k, v in info.items()])
        return info
