"""Control extensions the thin input/capture modules do not cover.

`omni.android.input` owns type/key/tap/swipe and `omni.android.capture` owns
screenshot/record; this file adds the gestures those lack: label targeting,
hold masks, scroll/fling chains, pattern unlock and crafted intents.
"""

from __future__ import annotations

import time

from omni.android.modules._base import AndroidModule
from omni.core import console
from omni.core.module import Option

__all__ = ["TapText", "Gesture", "Unlock", "Intent"]


class TapText(AndroidModule):
    NAME = "android.tap_text"
    DESCRIPTION = "Find a visible label or content-description and tap its centre"
    OPTIONS = (Option("TEXT", "visible text or content-desc", "", required=True),
               Option("WAIT", "seconds to poll for the node", "0"),
               Option("HOLD", "hold duration in ms (blank = a tap)"))

    def execute(self) -> dict:
        client = self.adb()
        deadline = time.time() + max(0, self.get_int("WAIT", 0))
        while True:
            try:
                x, y = client.find_text_bounds(self.get("TEXT"))
            except Exception:                   # noqa: BLE001 - retry loop
                if time.time() >= deadline:
                    raise
                time.sleep(0.5)
                continue
            hold = self.get_int("HOLD", 0)
            if hold:
                client.long_press(x, y, hold)
            else:
                client.tap(x, y)
            console.ok(f"tapped {self.get('TEXT')!r} at {x},{y}")
            return {"text": self.get("TEXT"), "x": x, "y": y, "hold_ms": hold}


class Gesture(AndroidModule):
    NAME = "android.gesture"
    DESCRIPTION = "Drag, scroll chain or long fling across the display"
    OPTIONS = (Option("KIND", "drag|scroll|fling", "scroll",
                      choices=("drag", "scroll", "fling")),
               Option("FROM_X", "start x", "540"),
               Option("FROM_Y", "start y", "1500"),
               Option("TO_X", "end x", "540"),
               Option("TO_Y", "end y", "500"),
               Option("DIRECTION", "scroll/fling direction", "down",
                      choices=("down", "up", "left", "right")),
               Option("STEPS", "repetitions", "1"),
               Option("MS", "duration", "600"))

    def execute(self) -> dict:
        client = self.adb()
        kind = self.get("KIND")
        if kind == "scroll":
            client.scroll(self.get("DIRECTION"), self.get_int("STEPS", 1))
        elif kind == "fling":
            client.fling(self.get("DIRECTION"), self.get_int("STEPS", 1))
        else:
            client.drag(self.get_int("FROM_X"), self.get_int("FROM_Y"),
                        self.get_int("TO_X"), self.get_int("TO_Y"),
                        self.get_int("MS", 600))
        console.ok(f"{kind} sent")
        return {"kind": kind}


class Unlock(AndroidModule):
    NAME = "android.unlock"
    DESCRIPTION = "Wake and clear a keyguard (swipe, PIN or pattern points)"
    OPTIONS = (Option("PIN", "PIN digits to type after waking"),
               Option("PATTERN", "pattern points as x,y;x,y;..."),
               Option("RETRIES", "attempts before giving up", "1"))

    @staticmethod
    def _draw_pattern(client, pattern: str) -> None:
        points = [p.split(",") for p in pattern.split(";") if p.strip()]
        if len(points) < 2:
            raise ValueError("pattern needs at least two x,y points")
        client.touch_down(int(points[0][0]), int(points[0][1]))
        for point in points[1:]:
            client.touch_move(int(point[0]), int(point[1]))
        client.touch_up(int(points[-1][0]), int(points[-1][1]))

    def execute(self) -> dict:
        client = self.adb()
        attempts = max(1, self.get_int("RETRIES", 1))
        for attempt in range(1, attempts + 1):
            if client.screen_state() == "off":
                client.wake()
                time.sleep(0.4)
            if not client.screen_locked():
                console.info("already unlocked")
                return {"unlocked": True, "attempts": attempt}
            if self.get("PATTERN"):
                self._draw_pattern(client, self.get("PATTERN"))
            elif self.get("PIN"):
                client.swipe_unlock()
                time.sleep(0.3)
                client.text(self.get("PIN"))
                client.key(66)
            else:
                client.swipe_unlock()
            time.sleep(1.0)
            if not client.screen_locked():
                console.ok(f"unlocked after {attempt} attempt(s)")
                return {"unlocked": True, "attempts": attempt}
        console.warn("still locked — wrong credential or a secure keyguard")
        return {"unlocked": False, "attempts": attempts}


class Intent(AndroidModule):
    NAME = "android.intent"
    DESCRIPTION = "Launch an app, or fire a crafted intent at a component/URL"
    OPTIONS = (Option("PACKAGE", "package name to launch"),
               Option("ACTION", "intent action, e.g. VIEW"),
               Option("DATA", "intent data (URL, tel:, file path)"),
               Option("COMPONENT", "package/activity to target"),
               Option("EXTRAS", "key=value pairs separated by ';'"))

    def execute(self) -> dict:
        client = self.adb()
        if self.get("COMPONENT") and self.get("ACTION"):
            args = ["am", "start", "-n", self.get("COMPONENT"),
                    "-a", self.get("ACTION")]
            if self.get("DATA"):
                args += ["-d", self.get("DATA")]
            for pair in self.get("EXTRAS").split(";"):
                if "=" in pair:
                    key, _, val = pair.partition("=")
                    args += ["--es", key.strip(), val.strip()]
            client.shell(*args)
            target = self.get("COMPONENT")
        elif self.get("PACKAGE"):
            client.start_app(self.get("PACKAGE"))
            target = self.get("PACKAGE")
        elif self.get("DATA"):
            client.open_url(self.get("DATA"))
            target = self.get("DATA")
        else:
            raise ValueError("give PACKAGE, COMPONENT+ACTION, or DATA")
        console.ok(f"launched {target}")
        return {"target": target}
