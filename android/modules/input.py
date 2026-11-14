"""Remote input: text, keys, taps, swipes."""

from __future__ import annotations

from omni.core.module import Option
from omni.android.modules._base import AndroidModule


class TypeText(AndroidModule):
    NAME = "android.type"
    DESCRIPTION = "Type text into the focused field (spaces become %s)"
    OPTIONS = (Option("TEXT", "text to type", required=True),)

    def execute(self) -> str:
        text = self.get("TEXT")
        self.adb().text(text)
        return text


class Key(AndroidModule):
    NAME = "android.key"
    DESCRIPTION = "Send a keyevent (named or numeric)"
    OPTIONS = (Option("KEY", "key name or code, e.g. HOME, BACK, 26", required=True),)

    NAMED = {"home": 3, "back": 4, "call": 5, "endcall": 6, "menu": 82,
             "power": 26, "volumeup": 24, "volumedown": 25, "enter": 66,
             "delete": 67, "tab": 61, "space": 62, "appswitch": 187,
             "camera": 27, "search": 84, "wakeup": 224, "sleep": 223}

    def execute(self) -> int:
        raw = self.get("KEY").strip().lower()
        code = self.NAMED.get(raw)
        if code is None:
            try:
                code = int(raw)
            except ValueError:
                raise ValueError(f"unknown key '{raw}'") from None
        self.adb().key(code)
        return code


class Tap(AndroidModule):
    NAME = "android.tap"
    DESCRIPTION = "Tap a screen coordinate"
    OPTIONS = (Option("X", "x pixel", required=True),
               Option("Y", "y pixel", required=True))

    def execute(self) -> tuple[int, int]:
        client = self.adb()
        x, y = self.get_int("X"), self.get_int("Y")
        client.tap(x, y)
        return x, y


class Swipe(AndroidModule):
    NAME = "android.swipe"
    DESCRIPTION = "Swipe between two coordinates"
    OPTIONS = (Option("FROM", "x1,y1", required=True),
               Option("TO", "x2,y2", required=True),
               Option("MS", "duration", "300"))

    def _pair(self, name: str) -> tuple[int, int]:
        raw = self.get(name).replace(" ", "")
        try:
            x, y = raw.split(",")
            return int(x), int(y)
        except ValueError:
            raise ValueError(f"{name} must be x,y") from None

    def execute(self) -> str:
        client = self.adb()
        x1, y1 = self._pair("FROM")
        x2, y2 = self._pair("TO")
        client.swipe(x1, y1, x2, y2, self.get_int("MS", 300))
        return f"{x1},{y1} -> {x2},{y2}"
