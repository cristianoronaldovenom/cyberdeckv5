"""Normalize / convert / install Flipper captures."""

import os

from omni.core import console
from omni.core.module import Option
from omni.flip import files
from omni.flip.modules._base import FlipModule

__all__ = ["Convert", "Push"]


class Convert(FlipModule):
    NAME = "flip.convert"
    DESCRIPTION = "Re-save any captured file as a canonical .sub in the loot dir"
    OPTIONS = (Option("FILE", "path to .sub/.ir/.ibtn", "", required=True),
               Option("OUT", "output basename (no extension)", ""))

    def execute(self) -> str:
        target = files.convert_to_sub(self.get("FILE"),
                                      self.get("OUT") or None)
        console.ok(f"written: {target}")
        return target


class Push(FlipModule):
    NAME = "flip.push"
    DESCRIPTION = "Copy a capture onto a mounted Flipper SD card"
    OPTIONS = (Option("FILE", "capture to install", "", required=True),
               Option("MOUNT", "SD mount point (default flipper.mount)", ""),
               Option("KIND", "SubGHZ|Infrared|Lagoon", ""))

    def execute(self) -> str:
        dest = files.push_to_sd(self.get("FILE"), self.get("MOUNT") or None,
                                self.get("KIND") or None)
        return dest
