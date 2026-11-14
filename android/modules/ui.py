"""Tree-driven Android control: read the view, then automate a whole flow.

``android.tap_text`` looks a label up once. This pair closes the gap to an
unattended run:

* ``android.ui`` — the dumped view tree as data: every label, id, class and
  the exact bounds, so a target can be inspected (or tapped) before the flow
  that uses it is written;
* ``android.automate`` — a small script (see :mod:`omni.core.flow`) executed
  step by step with per-step reporting, so a login-and-open-the-inbox sequence
  is one command instead of fifteen.
"""

from __future__ import annotations

import os
import re
import time

from omni.android import ui as tree
from omni.android.modules._base import AndroidModule
from omni.core import config, console, flow
from omni.core.module import Option

__all__ = ["UiDump", "Automate", "KEYCODES", "snapshot", "screen_size"]

#: named key -> Android keycode (``input keyevent <code>``)
KEYCODES = {
    "enter": 66, "back": 4, "home": 3, "recents": 187, "app_switch": 187,
    "tab": 61, "space": 62, "delete": 67, "backspace": 67, "escape": 111,
    "up": 19, "down": 20, "left": 21, "right": 22, "center": 23,
    "power": 26, "wakeup": 224, "sleep": 223, "camera": 27, "menu": 82,
    "volume_up": 24, "volume_down": 25, "mute": 164, "search": 84,
    "forward_del": 112, "move_home": 122, "move_end": 123, "insert": 124,
}
for _letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    KEYCODES[_letter.lower()] = 29 + "ABCDEFGHIJKLMNOPQRSTUVWXYZ".index(_letter)
for _digit in "0123456789":
    KEYCODES[_digit] = 7 + "0123456789".index(_digit)

#: coordinate pair in a script: ``tap 540,1200``
COORDS = re.compile(r"^\s*(-?\d+)\s*,\s*(-?\d+)\s*$")

#: finger-direction -> (from, to) as fractions of the display
SWIPES = {"up": ((0.5, 0.72), (0.5, 0.28)),
          "down": ((0.5, 0.28), (0.5, 0.72)),
          "left": ((0.8, 0.5), (0.2, 0.5)),
          "right": ((0.2, 0.5), (0.8, 0.5))}


def screen_size(client) -> tuple[int, int]:
    """Physical display size from ``wm size``; ``1080x2400`` as a fallback."""
    out = client.shell_result("wm", "size").out
    match = re.search(r"(\d+)x(\d+)", out)
    if not match:
        return 1080, 2400
    return int(match.group(1)), int(match.group(2))


def snapshot(client) -> tuple[list[tree.Node], str]:
    """The live view tree: ``(nodes, raw xml)``.

    ``uiautomator dump /dev/tty`` is the cheap path (no file, no cleanup);
    some builds only write to a file, so the second attempt goes through
    ``/sdcard`` and reads it back.
    """
    raw = client.shell_result("uiautomator", "dump", "/dev/tty",
                              timeout=60).out
    if "<?xml" not in raw:
        remote = "/sdcard/omni_dump.xml"
        client.shell_result("uiautomator", "dump", remote, timeout=60)
        raw = client.shell_result("cat", remote, timeout=60).out
        client.shell_result("rm", "-f", remote)
    return tree.parse_dump(raw), raw


class UiDump(AndroidModule):
    NAME = "android.ui"
    DESCRIPTION = "Read the view tree: labels, ids, bounds — and tap a node"
    OPTIONS = (Option("ACTION", "list|find|text|tap|dump", "list",
                       choices=("list", "find", "text", "tap", "dump")),
               Option("MATCH", "text, content-desc or id to match"),
               Option("CLASS", "class name filter, e.g. EditText"),
               Option("CLICKABLE", "only clickable nodes", "false",
                      choices=("true", "false")),
               Option("LIMIT", "rows to print", "40"),
               Option("OUT", "where to save the raw XML (ACTION=dump)"))

    def execute(self) -> dict:
        client = self.adb()
        nodes, raw = snapshot(client)
        if not nodes:
            console.warn("empty view tree — a secure window, or the screen "
                         "is off")
            return {"nodes": 0}
        action = self.get("ACTION")
        if action == "dump":
            path = os.path.expanduser(
                self.get("OUT") or
                os.path.join(config.output_dir("android/ui"),
                             f"dump_{time.strftime('%Y%m%d_%H%M%S')}.xml"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(raw if raw.lstrip().startswith("<") else
                         raw[raw.find("<"):] + "\n")
            console.ok(f"{len(nodes)} node(s) -> {path}")
            return {"nodes": len(nodes), "path": path}

        if action == "text":
            page = tree.labels(nodes)
            for label in page[:max(1, self.get_int("LIMIT", 40))]:
                console.info(label)
            console.ok(f"{len(page)} label(s) on screen")
            return {"labels": page}

        wanted = {}
        if self.get("MATCH"):
            wanted["text"] = self.get("MATCH")
        if self.get("CLASS"):
            wanted["cls"] = self.get("CLASS")
        if self.get_bool("CLICKABLE"):
            wanted["clickable"] = True
        hits = tree.find(nodes, **wanted) if wanted else list(nodes)

        if action == "tap":
            node = tree.pick(hits)
            if node is None:
                raise RuntimeError(f"no node matching {self.get('MATCH')!r}")
            x, y = node.centre
            client.tap(x, y)
            console.ok(f"tapped {node.label!r} at {x},{y}")
            return {"tapped": node.label, "x": x, "y": y}

        console.table(["label", "class", "click", "centre"],
                      tree.rows(hits, self.get_int("LIMIT", 40)))
        console.ok(f"{len(hits)} of {len(nodes)} node(s) matched")
        return {"matched": len(hits), "nodes": [n.to_row() for n in hits[:60]]}



class Automate(AndroidModule):
    NAME = "android.automate"
    DESCRIPTION = "Run a scripted UI flow (wait/tap/type/key/swipe/shot/launch)"
    OPTIONS = (Option("SCRIPT", "steps separated by ';' or newlines"),
               Option("FILE", "read the script from this file"),
               Option("STOP", "stop at the first failing step", "true",
                      choices=("true", "false")),
               Option("DRY", "parse and print the plan only", "false",
                      choices=("true", "false")),
               Option("AWAIT", "default wait timeout, seconds", "10"))

    #: verbs this trade understands (``text`` is an alias of ``type``)
    VERBS = flow.CORE_VERBS + ("back", "home", "recents", "text")

    def script(self) -> str:
        """The script text, from FILE when given, else from SCRIPT."""
        if self.get("FILE"):
            path = os.path.expanduser(self.get("FILE"))
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read()
        return self.get("SCRIPT")

    # -- step helpers ------------------------------------------------------
    def _await(self) -> float:
        try:
            return max(0.0, float(self.get("AWAIT") or 10))
        except ValueError:
            return 10.0

    @staticmethod
    def _find(client, needle: str, timeout: float) -> tree.Node | None:
        deadline = time.time() + max(0.0, timeout)
        while True:
            nodes, _raw = snapshot(client)
            node = tree.select(nodes, text=needle)
            if node is not None:
                return node
            if time.time() >= deadline:
                return None
            time.sleep(0.5)

    @staticmethod
    def _point(client, step: flow.Step) -> tuple[int, int]:
        """``tap 540,1200`` uses the numbers; ``tap "Sign in"`` the node."""
        coords = COORDS.match(step.arg(0))
        if coords:
            return int(coords.group(1)), int(coords.group(2))
        needle = " ".join(step.args).strip()
        if not needle:
            raise ValueError("tap needs a label or x,y")
        node = Automate._find(client, needle, 5.0)
        if node is None:
            raise RuntimeError(f"no node matching {needle!r} on screen")
        return node.centre

    def handlers(self, client) -> dict:
        """verb -> callable, bound to one device session."""
        await_default = self._await()

        def tap(step):
            x, y = self._point(client, step)
            client.tap(x, y)
            return f"{x},{y}"

        def wait(step):
            needle = step.arg(0).strip()
            if not needle:
                raise ValueError("wait needs a label")
            node = self._find(client, needle, step.number(1, await_default))
            if node is None:
                raise RuntimeError(f"{needle!r} never appeared")
            return f"{node.label} at {node.centre[0]},{node.centre[1]}"

        def kind(step):
            raw = " ".join(step.args).strip()
            if not raw:
                raise ValueError("type needs text")
            client.text(raw)
            return raw

        def key(step):
            name = step.arg(0).strip().lower()
            code = KEYCODES.get(name)
            if code is None and name.isdigit():
                code = int(name)
            if code is None:
                raise ValueError(f"unknown key {name!r}")
            client.key(int(code))
            return name

        def swipe(step):
            direction = (step.arg(0) or "up").strip().lower()
            if direction not in SWIPES:
                raise ValueError(f"swipe {direction!r} not in "
                                 f"{', '.join(sorted(SWIPES))}")
            width, height = screen_size(client)
            (fx1, fy1), (fx2, fy2) = SWIPES[direction]
            client.swipe(int(width * fx1), int(height * fy1),
                         int(width * fx2), int(height * fy2),
                         max(50, int(step.number(1, 200))))
            return direction

        def scroll(step):
            direction = (step.arg(0) or "down").strip().lower()
            client.scroll(direction, max(1, step.integer(1, 1)))
            return direction

        def sleep(step):
            seconds = min(600.0, step.number(0, 1.0))
            time.sleep(max(0.0, seconds))
            return seconds

        def shot(step):
            path = os.path.expanduser(
                step.arg(0) or os.path.join(
                    config.output_dir("android/screens"),
                    f"flow_{time.strftime('%Y%m%d_%H%M%S')}.png"))
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            client.screenshot(path)
            return path

        def launch(step):
            package = step.arg(0).strip()
            if not package:
                raise ValueError("launch needs a package")
            client.start_app(package)
            return package

        def unlock(step):
            if client.screen_state() in ("asleep", "off"):
                client.wake()
                time.sleep(0.4)
            if not client.screen_locked():
                return "already clear"
            client.swipe_unlock()
            time.sleep(0.4)
            if step.arg(0):
                client.text(step.arg(0))
                client.key(66)
                time.sleep(0.6)
            return "unlocked"

        def press(name):
            def handler(step):                    # noqa: ARG001 - uniform API
                client.key(KEYCODES[name])
                return name
            return handler

        return {"tap": tap, "wait": wait, "type": kind, "text": kind,
                "key": key, "swipe": swipe, "scroll": scroll, "sleep": sleep,
                "shot": shot, "launch": launch, "unlock": unlock,
                "back": press("back"), "home": press("home"),
                "recents": press("recents")}

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
        console.info(f"{len(steps)} step(s) — starting")
        report = flow.execute(steps, self.handlers(self.adb()),
                              stop_on_error=self.get_bool("STOP", True),
                              observer=self._show)
        if report["ok"]:
            console.ok(f"flow complete: {report['ran']} step(s)")
        else:
            console.warn(f"{report['failed']} step(s) failed after "
                         f"{report['ran']} of {len(steps)}")
        return report
