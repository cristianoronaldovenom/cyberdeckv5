"""Scripted iPhone control: the same flow grammar, over HID.

``ios.remote`` is interactive; this runs a whole sequence unattended — unlock,
launch the app, type, swipe, screenshot — with per-step reporting, so a
"get to this screen" routine is one command and reproducible afterwards.

iOS has no accessibility tree to poll, so ``wait`` waits a fixed time rather
than for a label (Android's ``wait`` does poll). Coordinates are 0..65535 and
screen-normalised, or fractions: ``tap 0.5,0.85`` means the same thing on an
iPhone SE and an iPad Pro.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console, flow
from omni.core.module import Option
from omni.ios.modules._base import IosModule

__all__ = ["Automate", "SWIPES", "normalise"]

#: direction -> (from, to) in 0..65535 screen-normalised coordinates
SWIPES = {"up": ((32768, 60000), (32768, 10000)),
          "down": ((32768, 10000), (32768, 60000)),
          "left": ((60000, 32768), (8000, 32768)),
          "right": ((8000, 32768), (60000, 32768))}

#: the full normalised screen
SPAN = 65535


def normalise(text: str) -> tuple[int, int]:
    """``0.5,0.5`` (fractions) or ``32768,32768`` (normalised) -> a point."""
    raw = (text or "").replace(";", ",").split(",")
    if len(raw) < 2:
        raise ValueError(f"expected 'x,y' coordinates, got {text!r}")
    try:
        x, y = float(raw[0]), float(raw[1])
    except ValueError:
        raise ValueError(f"expected numbers, got {text!r}") from None
    if 0.0 <= x <= 1.0 and 0.0 <= y <= 1.0:
        x, y = x * SPAN, y * SPAN
    clamp = lambda value: int(max(0, min(SPAN, round(value))))  # noqa: E731
    return clamp(x), clamp(y)


class Automate(IosModule):
    NAME = "ios.automate"
    DESCRIPTION = "Run a scripted iPhone flow (tap/type/key/swipe/shot/launch)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("SCRIPT", "steps separated by ';' or newlines"),
               Option("FILE", "read the script from this file"),
               Option("STOP", "stop at the first failing step", "true",
                      choices=("true", "false")),
               Option("DRY", "parse and print the plan only", "false",
                      choices=("true", "false")))

    #: verbs this trade understands
    VERBS = flow.CORE_VERBS + ("lock", "home", "text", "drag")

    def script(self) -> str:
        """The script text, from FILE when given, else from SCRIPT."""
        if self.get("FILE"):
            path = os.path.expanduser(self.get("FILE"))
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read()
        return self.get("SCRIPT")


    def handlers(self, client) -> dict:
        """verb -> callable, bound to one device session."""

        def tap(step):
            x, y = normalise(step.arg(0))
            client.tap(x, y)
            return f"{x},{y}"

        def wait(step):
            seconds = min(600.0, step.number(0, 1.0))
            console.info(f"waiting {seconds:g}s (iOS has no view tree "
                         "to poll)")
            time.sleep(max(0.0, seconds))
            return seconds

        def kind(step):
            text = " ".join(step.args).strip()
            if not text:
                raise ValueError("type needs text")
            client.type_text(text)
            return text

        def key(step):
            name = step.arg(0).strip().lower()
            if not name:
                raise ValueError("key needs a name, e.g. enter")
            client.key(name, max(1, step.integer(1, 1)))
            return name

        def swipe(step):
            direction = (step.arg(0) or "up").strip().lower()
            if direction not in SWIPES:
                raise ValueError(f"swipe {direction!r} not in "
                                 f"{', '.join(sorted(SWIPES))}")
            (x1, y1), (x2, y2) = SWIPES[direction]
            client.swipe(x1, y1, x2, y2, max(0.05, step.number(1, 0.3)))
            return direction

        def drag(step):
            x1, y1 = normalise(step.arg(0))
            x2, y2 = normalise(step.arg(1))
            client.drag(x1, y1, x2, y2, max(0.4, step.number(2, 0.8)))
            return f"{x1},{y1} -> {x2},{y2}"

        def scroll(step):
            direction = "up" if (step.arg(0) or "down") == "down" else "down"
            (x1, y1), (x2, y2) = SWIPES[direction]
            for _ in range(max(1, step.integer(1, 1))):
                client.swipe(x1, y1, x2, y2, 0.15)
            return direction

        def sleep(step):
            seconds = min(600.0, step.number(0, 1.0))
            time.sleep(max(0.0, seconds))
            return seconds

        def shot(step):
            path = os.path.expanduser(
                step.arg(0) or os.path.join(
                    config.output_dir("ios/screens"),
                    f"flow_{time.strftime('%Y%m%d_%H%M%S')}.png"))
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            client.screenshot(path)
            return path

        def launch(step):
            bundle = step.arg(0).strip()
            if not bundle:
                raise ValueError("launch needs a bundle identifier")
            client.launch(bundle)
            return bundle

        def unlock(step):
            client.unlock()
            if step.arg(0):
                time.sleep(0.6)
                client.type_text(step.arg(0))
            return "unlocked"

        def lock(step):                            # noqa: ARG001 - uniform API
            client.lock()
            return "locked"

        def home(step):                            # noqa: ARG001 - uniform API
            client.key("home", 1)
            return "home"

        return {"tap": tap, "wait": wait, "type": kind, "text": kind,
                "key": key, "swipe": swipe, "drag": drag, "scroll": scroll,
                "sleep": sleep, "shot": shot, "launch": launch,
                "unlock": unlock, "lock": lock, "home": home}

    @staticmethod
    def _show(row: dict) -> None:
        if row["ok"]:
            console.ok(f"{row['step']}  ->  {row.get('value')}")
        else:
            console.err(f"{row['step']}  !!  {row.get('error')}")

    def execute(self) -> dict:
        script = self.script()
        if not script.strip():
            raise ValueError("give SCRIPT or FILE")
        steps = flow.parse(script, verbs=self.VERBS)
        if not steps:
            raise ValueError("the script has no steps")
        if self.get_bool("DRY"):
            for line in flow.describe(steps):
                console.info(line)
            return {"plan": flow.describe(steps), "dry": True}
        client = self.client()
        console.info(f"{len(steps)} step(s) — starting")
        report = flow.execute(steps, self.handlers(client),
                              stop_on_error=self.get_bool("STOP", True),
                              observer=self._show)
        if report["ok"]:
            console.ok(f"flow complete: {report['ran']} step(s)")
        else:
            console.warn(f"{report['failed']} step(s) failed after "
                         f"{report['ran']} of {len(steps)}")
        return report
