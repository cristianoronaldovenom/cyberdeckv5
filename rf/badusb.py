"""BadUSB — Ducky Script subset -> USB HID keyboard reports.

On a Raspberry Pi Zero 2 W configured as a USB gadget (hidg), reports are
written straight to /dev/hidg0; anywhere else a MockHid records the typed
text so scripts can be tested offline.
"""

from __future__ import annotations

import time

# HID keyboard usage IDs (the common subset)
_HID = {
    "a": 0x04, "b": 0x05, "c": 0x06, "d": 0x07, "e": 0x08, "f": 0x09,
    "g": 0x0A, "h": 0x0B, "i": 0x0C, "j": 0x0D, "k": 0x0E, "l": 0x0F,
    "m": 0x10, "n": 0x11, "o": 0x12, "p": 0x13, "q": 0x14, "r": 0x15,
    "s": 0x16, "t": 0x17, "u": 0x18, "v": 0x19, "w": 0x1A, "x": 0x1B,
    "y": 0x1C, "z": 0x1D, "1": 0x1E, "2": 0x1F, "3": 0x20, "4": 0x21,
    "5": 0x22, "6": 0x23, "7": 0x24, "8": 0x25, "9": 0x26, "0": 0x27,
    "enter": 0x28, "esc": 0x29, "backspace": 0x2A, "tab": 0x2B,
    "space": 0x2C, "-": 0x2D, "=": 0x2E, "[": 0x2F, "]": 0x30,
    "\\": 0x31, ";": 0x33, "'": 0x34, ",": 0x36, ".": 0x37, "/": 0x38,
}
_MODS = {"ctrl": 0x01, "shift": 0x02, "alt": 0x04, "gui": 0x08, "windows": 0x08}
_SHIFTED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+{}|:\"<>?")
_SHIFT_MAP = {"!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6",
             "&": "7", "*": "8", "(": "9", ")": "0", "_": "-", "+": "=",
             "{": "[", "}": "]", "|": "\\", ":": ";", '"': "'",
             "<": ",", ">": ".", "?": "/"}
_REV_SHIFT = {v: k for k, v in _SHIFT_MAP.items()}


def _report(modifier: int, key: int) -> bytes:
    return bytes([modifier, 0, key, 0, 0, 0, 0, 0])


class MockHid:
    """Records what a HID keyboard would type (for tests/demo)."""

    def __init__(self):
        self.typed = ""
        self.reports: list[bytes] = []

    def write(self, report: bytes) -> None:
        self.reports.append(bytes(report))
        key = report[2]
        if not key:
            return
        for name, code in _HID.items():
            if code == key:
                if key == _HID["space"]:
                    self.typed += " "
                    return
                if key == _HID["enter"]:
                    self.typed += "\n"
                    return
                if key == _HID["tab"]:
                    self.typed += "\t"
                    return
                ch = name
                if report[0] & 0x02:  # shift held
                    ch = _REV_SHIFT.get(ch, ch.upper())
                self.typed += ch
                return


class HidGadgetWriter:
    """Writes reports to a Pi Zero USB gadget HID node (/dev/hidg0)."""

    def __init__(self, node: str = "/dev/hidg0"):
        self.node = node
        self.fh = open(node, "wb")

    def write(self, report: bytes) -> None:
        self.fh.write(bytes(report))
        self.fh.flush()

    def close(self):
        self.fh.close()


def parse(script: str) -> list[tuple]:
    """Ducky Script subset -> [('delay', ms) | ('string', s) |
    ('key', name) | ('mod', mod, key)] actions."""
    actions: list[tuple] = []
    for raw in script.splitlines():
        line = raw.strip()
        if not line or line.upper().startswith("REM"):
            continue
        parts = line.split(None, 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""
        if cmd == "DELAY":
            try:
                actions.append(("delay", int(arg)))
            except ValueError:
                continue
        elif cmd == "STRING":
            actions.append(("string", arg))
        elif cmd in ("ENTER", "TAB", "ESC", "SPACE", "BACKSPACE"):
            actions.append(("key", cmd.lower()))
        elif cmd.lower() in _MODS:
            key = arg.strip().lower()
            if key in _HID:
                actions.append(("mod", _MODS[cmd.lower()], key))
        elif len(cmd) == 1:
            actions.append(("string", line))
    return actions


def run_ducky(script: str, writer, delay_scale: float = 1.0) -> str:
    """Execute a Ducky Script against a writer; returns nothing (mock has text)."""
    def press(mod: int, key: str):
        writer.write(_report(mod, _HID[key]))
        writer.write(_report(0, 0))  # key release

    for action in parse(script):
        kind = action[0]
        if kind == "delay":
            if delay_scale:
                time.sleep(action[1] / 1000.0 * delay_scale)
        elif kind == "string":
            for ch in action[1]:
                if ch == " ":
                    press(0, "space")
                    continue
                shift = ch.isupper() or ch in _SHIFTED
                base = _SHIFT_MAP.get(ch, ch.lower())
                if base in _HID:
                    press(0x02 if shift else 0, base)
        elif kind == "key":
            press(0, action[1])
        elif kind == "mod":
            press(action[1], action[2])
    return ""


DEMO_SCRIPT = """REM Unleashed-Pi BadUSB demo
DELAY 300
STRING Hello from Unleashed-Pi!
ENTER
"""
