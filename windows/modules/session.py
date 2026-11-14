"""Live desktop control: enumerate windows, pick one, drive the clipboard.

``windows.type`` types into *whatever* has focus; ``windows.hotkey`` fires at
whatever has focus. Guessing wrong is what makes an automated run useless, so
this pair adds the missing targeting step and the clipboard: bring the window
you meant to the front, close what is in the way, and pick up whatever the
user copied (passwords, 2FA codes, URLs) as it lands.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.windows import session
from omni.windows.modules._base import WindowsModule

__all__ = ["Window", "Clipboard"]

#: verbs that need a target window
ACTIONS = ("list", "foreground", "focus", "close", "kill", "minimise",
           "maximise")


class Window(WindowsModule):
    NAME = "windows.window"
    DESCRIPTION = "List, focus, close or kill desktop windows by title"
    OPTIONS = (Option("ACTION", "list|foreground|focus|close|kill|minimise"
                       "|maximise", "list", choices=ACTIONS),
               Option("MATCH", "window title (substring; blank = every one)"),
               Option("EXACT", "match the whole title", "false",
                      choices=("true", "false")),
               Option("LIMIT", "rows to print", "30"))

    @staticmethod
    def _handle():
        handle = session.api()
        if handle is None:
            raise RuntimeError("windows.window is a live session call — "
                               "it needs Windows (ctypes user32)")
        return handle

    def _rows(self, windows: list) -> list[list[str]]:
        limit = max(1, self.get_int("LIMIT", 30))
        return [window.to_row() for window in windows[:limit]]

    def execute(self) -> dict:
        handle = self._handle()
        action = self.get("ACTION")
        if action == "list":
            windows = session.find(self.get("MATCH"), handle,
                                   exact=self.get_bool("EXACT"))
            console.table(["hwnd", "title", "class", "size", "state", "pid",
                           "centre"], self._rows(windows))
            console.ok(f"{len(windows)} window(s)")
            return {"windows": [window.to_row() for window in windows[:80]]}

        if action == "foreground":
            window = session.foreground(handle)
            if window is None:
                console.warn("nothing has focus")
                return {"foreground": None}
            console.kv([("hwnd", window.hwnd),
                        ("title", session.safe_text(window.title)),
                        ("class", window.class_name), ("pid", window.pid)])
            return {"foreground": window.to_row()}

        target = session.pick(self.get("MATCH"), handle)
        if target is None:
            raise RuntimeError(f"no window matching {self.get('MATCH')!r} — "
                               "run ACTION=list to see the titles")
        if action == "focus":
            ok = session.focus(target.hwnd, handle)
        elif action == "close":
            ok = session.close(target.hwnd, handle)
        elif action == "kill":
            pid = session.terminate(target.hwnd, handle)
            ok = bool(pid)
            if ok:
                console.warn(f"killed pid {pid} "
                             f"({session.safe_text(target.title, 40)!r})")
        elif action == "minimise":
            ok = session.minimise(target.hwnd, handle)
        else:
            ok = session.maximise(target.hwnd, handle)
        title = session.safe_text(target.title, 44)
        if ok:
            console.ok(f"{action}: {title!r} ({target.hwnd})")
        else:
            console.warn(f"{action} was refused for {title!r} "
                         "(an elevated window refuses a normal caller)")
        return {"action": action, "hwnd": target.hwnd, "title": target.title,
                "ok": ok}



class Clipboard(WindowsModule):
    NAME = "windows.clipboard"
    DESCRIPTION = "Read, set, clear or watch the clipboard"
    OPTIONS = (Option("ACTION", "get|set|clear|watch", "get",
                       choices=("get", "set", "clear", "watch")),
               Option("TEXT", "text to place on the clipboard"),
               Option("SECONDS", "watch window", "15"),
               Option("OUT", "watch log path"))

    @staticmethod
    def _handle():
        handle = session.api()
        if handle is None:
            raise RuntimeError("windows.clipboard is a live session call — "
                               "it needs Windows (ctypes user32)")
        return handle

    def execute(self) -> dict:
        handle = self._handle()
        action = self.get("ACTION")
        if action == "set":
            if not self.get("TEXT"):
                raise ValueError("SET needs TEXT")
            chars = session.set_clipboard_text(self.get("TEXT"), handle)
            console.ok(f"clipboard set ({chars} char(s))")
            return {"chars": chars, "text": self.get("TEXT")}
        if action == "clear":
            cleared = session.clear_clipboard(handle)
            console.ok("clipboard cleared" if cleared else "clipboard busy")
            return {"cleared": cleared}

        if action == "get":
            text = session.clipboard_text(handle)
            console.info(text or "(empty)")
            return {"text": text, "chars": len(text)}

        seconds = max(1, self.get_int("SECONDS", 15))
        path = os.path.expanduser(
            self.get("OUT") or os.path.join(
                config.output_dir("windows/clipboard"),
                f"clip_{time.strftime('%Y%m%d_%H%M%S')}.log"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        console.info(f"watching the clipboard for {seconds}s -> {path}")
        seen: list[str] = []
        deadline = time.time() + seconds
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            while time.time() < deadline:
                try:
                    text = session.clipboard_text(handle)
                except Exception:                 # noqa: BLE001 - transient
                    text = ""
                if text and text not in seen:
                    seen.append(text)
                    fh.write(f"{time.strftime('%H:%M:%S')}\t{text}\n")
                    fh.flush()
                    console.ok(f"captured: {text[:60]!r}")
                time.sleep(0.5)
        console.ok(f"{len(seen)} unique clip(s) -> {path}")
        return {"captured": seen, "path": path}
