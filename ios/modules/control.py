"""iOS control: HID input, keyguard, clipboard, screenshots.

Coordinates are **0..65535 and screen-normalised**, so the same numbers work on
an iPhone SE and an iPad Pro — no per-model pixel math. They map proportionally
to the display.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.ios.modules._base import IosModule

__all__ = ["Type", "Tap", "Gesture", "Key", "Lock", "Clipboard", "Screenshot"]

#: normalised distance covered by one scroll flick
SCROLL_SPAN = 30000


class Type(IosModule):
    NAME = "ios.type"
    DESCRIPTION = "Type text into the focused field via HID"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("TEXT", "text to type", "", required=True),
               Option("DELAY", "seconds to wait before typing", "0"))

    def execute(self) -> dict:
        client = self.client()
        delay = float(self.get("DELAY") or 0)
        if delay:
            time.sleep(delay)
        client.type_text(self.get("TEXT"))
        console.ok(f"typed {len(self.get('TEXT'))} char(s)")
        return {"chars": len(self.get("TEXT"))}


class Tap(IosModule):
    NAME = "ios.tap"
    DESCRIPTION = "Tap a normalised coordinate (0..65535)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("X", "x, 0=left edge, 65535=right edge", "32768",
                      required=True),
               Option("Y", "y, 0=top edge, 65535=bottom edge", "32768",
                      required=True))

    def execute(self) -> dict:
        client = self.client()
        x, y = self.get_int("X", 32768), self.get_int("Y", 32768)
        client.tap(x, y)
        console.ok(f"tapped {x},{y}")
        return {"x": x, "y": y}


class Gesture(IosModule):
    NAME = "ios.gesture"
    DESCRIPTION = "Swipe, drag or scroll the screen"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("KIND", "swipe|drag|scroll", "swipe",
                      choices=("swipe", "drag", "scroll")),
               Option("FROM_X", "start x (swipe/drag)", "32768"),
               Option("FROM_Y", "start y (swipe/drag)", "60000"),
               Option("TO_X", "end x (swipe/drag)", "32768"),
               Option("TO_Y", "end y (swipe/drag)", "20000"),
               Option("DIRECTION", "scroll direction", "down",
                      choices=("down", "up")),
               Option("STEPS", "scroll repetitions", "1"),
               Option("SECONDS", "gesture duration", "0.3"))

    def execute(self) -> dict:
        client = self.client()
        kind = self.get("KIND")
        duration = float(self.get("SECONDS") or 0.3)
        if kind == "scroll":
            down = self.get("DIRECTION") != "up"
            y1 = 60535 if down else 5000
            y2 = y1 - SCROLL_SPAN if down else y1 + SCROLL_SPAN
            for _ in range(max(1, self.get_int("STEPS", 1))):
                client.swipe(32768, y1, 32768, y2, 0.15)
        elif kind == "drag":
            client.drag(self.get_int("FROM_X"), self.get_int("FROM_Y"),
                        self.get_int("TO_X"), self.get_int("TO_Y"),
                        max(0.4, duration))
        else:
            client.swipe(self.get_int("FROM_X"), self.get_int("FROM_Y"),
                         self.get_int("TO_X"), self.get_int("TO_Y"), duration)
        console.ok(f"{kind} sent")
        return {"kind": kind}


class Key(IosModule):
    NAME = "ios.key"
    DESCRIPTION = "Press a named hardware/soft key (enter, backspace, home…)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("KEY", "key name, e.g. enter|backspace|escape|left",
                      "enter", required=True),
               Option("COUNT", "how many times to press", "1"))

    def execute(self) -> dict:
        client = self.client()
        count = max(1, self.get_int("COUNT", 1))
        client.key(self.get("KEY"), count)
        console.ok(f"{self.get('KEY')} x{count}")
        return {"key": self.get("KEY"), "count": count}


class Lock(IosModule):
    NAME = "ios.lock"
    DESCRIPTION = "Lock/unlock the screen, or report the keyguard state"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("ACTION", "lock|unlock|state", "state",
                      choices=("lock", "unlock", "state")))

    def execute(self) -> dict:
        client = self.client()
        action = self.get("ACTION")
        if action == "lock":
            client.lock()
        elif action == "unlock":
            client.unlock()
            console.info("swipe only — type a passcode yourself if set")
        else:
            state = client.lock_state()
            console.info(state)
            return {"state": state}
        console.ok(f"{action} sent")
        return {"action": action}


class Clipboard(IosModule):
    NAME = "ios.clipboard"
    DESCRIPTION = "Read or write the device pasteboard"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("ACTION", "get|set", "get", choices=("get", "set")),
               Option("TEXT", "text to place on the pasteboard"))

    def execute(self) -> dict:
        client = self.client()
        if self.get("ACTION") == "set":
            if not self.get("TEXT"):
                raise ValueError("SET needs TEXT")
            client.clipboard_set(self.get("TEXT"))
            console.ok("pasteboard written")
            return {"text": self.get("TEXT")}
        text = client.clipboard_get()
        console.info(text or "(empty)")
        return {"text": text}


class Screenshot(IosModule):
    NAME = "ios.screenshot"
    DESCRIPTION = "Capture the screen to a PNG under the loot directory"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("PATH", "explicit output path"))

    def execute(self) -> dict:
        client = self.client()
        path = os.path.expanduser(
            self.get("PATH") or
            os.path.join(config.output_dir("ios/screens"),
                         f"iphone_{time.strftime('%Y%m%d_%H%M%S')}.png"))
        client.screenshot(path)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        if not size:
            console.warn("no bytes written — check Developer Mode and the tunnel")
        else:
            console.ok(f"{size} byte PNG -> {path}")
        return {"path": path, "bytes": size}
