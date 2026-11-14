"""Interactive remote control for an iPhone, in one persistent session.

Every other ``ios.*`` module is one-shot: it spawns ``pymobiledevice3``, does
one thing and exits. Driving a phone that way costs a process per tap. This
keeps one client alive and reads commands from a prompt — the actual "remote
control" experience:

    omni run ios.remote
    iphone> tap 32768 40000
    iphone> text hello world
    iphone> key enter
    iphone> shot
    iphone> lock

``dispatch`` is a pure function over ``(client, line) -> (output, quit)`` so the
whole command surface is testable without a device, and ``SCRIPT`` replays a
semicolon-separated list non-interactively (piping/scripting without a TTY).
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.ios.modules._base import IosModule

__all__ = ["Remote", "HELP", "dispatch"]

HELP = (
    ("help", "this list"),
    ("status", "lock state"),
    ("wake", "press power (toggle screen)"),
    ("shot [path]", "screenshot to loot"),
    ("tap X Y", "tap normalised coords (0..65535)"),
    ("long X Y [ms]", "press and hold"),
    ("swipe X1 Y1 X2 Y2 [s]", "swipe"),
    ("scroll up|down [n]", "flick the screen"),
    ("text <words>", "type text"),
    ("key <name> [n]", "press a key (enter, backspace, home...)"),
    ("app", "home button"),
    ("apps [grep]", "list bundles"),
    ("launch BUNDLE", "start an app"),
    ("kill NAME", "SIGKILL matching processes"),
    ("clip [get|set TEXT]", "read/write the pasteboard"),
    ("lock / unlock", "screen wake/sleep"),
    ("loc LAT LON / loc clear", "spoof GPS"),
    ("battery", "battery levels"),
    ("sleep S", "pause"),
    ("quit", "leave"),
)


def _battery(client) -> str:
    res = client.run("diagnostics", "battery", "single", timeout=60)
    return res.text.strip() or "(no battery data)"


def dispatch(client, line: str) -> tuple[str, bool]:
    """Run one console command. Returns (output, should_quit)."""
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return "", False
    parts = raw.split()
    cmd, args = parts[0].lower(), parts[1:]

    def num(index: int, default: int = 0) -> int:
        try:
            return int(args[index])
        except (IndexError, ValueError):
            return default

    if cmd in ("quit", "exit", "q"):
        return "bye", True
    if cmd == "help":
        return "\n".join(f"  {name:<28}{desc}" for name, desc in HELP), False
    if cmd == "status":
        return f"lock: {client.lock_state()}", False
    if cmd == "wake":
        client.wake()
        return "power pressed", False
    if cmd == "shot":
        path = args[0] if args else os.path.join(
            config.output_dir("ios/screens"),
            f"iphone_{time.strftime('%Y%m%d_%H%M%S')}.png")
        client.screenshot(path)
        return f"saved {path}", False
    if cmd == "tap":
        client.tap(num(0, 32768), num(1, 32768))
        return f"tapped {num(0)}, {num(1)}", False
    if cmd == "long":
        client.press_hold(num(0), num(1), num(2, 800))
        return f"held {num(0)}, {num(1)}", False
    if cmd == "swipe":
        client.swipe(num(0), num(1), num(2), num(3), float(num(4, 30)) / 100.0)
        return "swiped", False
    if cmd == "scroll":
        steps = client.scroll(args[0] if args else "down", num(1, 1))
        return f"scrolled {steps}", False
    if cmd == "text":
        text = raw.split(" ", 1)[1] if len(parts) > 1 else ""
        client.type_text(text)
        return f"typed {len(text)} chars", False
    if cmd == "key":
        client.key(args[0] if args else "enter", num(1, 1))
        return "key sent", False
    if cmd == "app":
        client.press_button("home")
        return "home", False
    if cmd == "apps":
        apps = client.apps()
        if args:
            apps = [a for a in apps if args[0].lower() in a.lower()]
        return "\n".join(apps[:40]), False
    if cmd == "launch":
        client.launch(args[0])
        return f"launched {args[0]}", False
    if cmd == "kill":
        return f"killed {client.kill(args[0])}", False
    if cmd == "clip":
        if args and args[0] == "set":
            client.clipboard_set(raw.split(" ", 2)[2])
            return "clipboard written", False
        return client.clipboard_get() or "(empty)", False
    if cmd == "lock":
        client.lock()
        return "locked", False
    if cmd == "unlock":
        client.unlock()
        return "unlocked", False
    if cmd == "loc":
        if args and args[0] == "clear":
            client.clear_location()
            return "location cleared", False
        client.set_location(float(args[0]), float(args[1]))
        return f"location {args[0]},{args[1]}", False
    if cmd == "battery":
        return _battery(client), False
    if cmd == "sleep":
        time.sleep(num(0, 1))
        return f"slept {num(0, 1)}s", False
    return f"? unknown command {cmd!r} — try help", False
