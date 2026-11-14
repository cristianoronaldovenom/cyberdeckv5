"""Screen capture and recording."""

from __future__ import annotations

import os

from omni.core import config, console
from omni.core.module import Option
from omni.android.modules._base import AndroidModule


class Screenshot(AndroidModule):
    NAME = "android.screenshot"
    DESCRIPTION = "Capture the current screen to the loot directory"
    OPTIONS = (Option("NAME", "file name (blank = timestamped)", ""),)

    def execute(self) -> str:
        client = self.adb()
        name = self.get("NAME") or f"screen_{os.urandom(4).hex()}.png"
        if not name.endswith(".png"):
            name += ".png"
        path = os.path.join(config.output_dir("android/screens"), name)
        client.screenshot(path)
        size = os.path.getsize(path)
        console.ok(f"{path} ({size // 1024} KiB)")
        if size < 1024:
            console.warn("tiny file — device may be on a secure (DRM) surface")
        return path


class ScreenRecord(AndroidModule):
    NAME = "android.screenrecord"
    DESCRIPTION = "Record the screen for N seconds (max 180)"
    NEEDS = ("adb",)
    OPTIONS = (Option("SECONDS", "recording length", "10", required=True),)

    def execute(self) -> str:
        client = self.adb()
        seconds = max(1, min(180, self.get_int("SECONDS", 10)))
        path = os.path.join(config.output_dir("android/screens"),
                            f"rec_{os.urandom(4).hex()}.mp4")
        console.info(f"recording {seconds}s ...")
        client.screenrecord(path, seconds)
        console.ok(path)
        return path
