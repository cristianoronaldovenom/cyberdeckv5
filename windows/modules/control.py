"""Windows keyboard/mouse control with stdlib ctypes — no autohotkey, no deps.

The windows.* trade could only *read* the host; this drives it: type, click,
move, hotkeys and lock. It acts on the machine it runs on (host, VM or RDP
session), which is what a post-exploitation foothold does anyway.

``ctypes.windll`` only exists on Windows, so it is bound lazily and the modules
degrade with a clear message elsewhere.
"""

from __future__ import annotations

import ctypes
import os
import time

from omni.core import console, proc
from omni.core.module import Option
from omni.windows.modules._base import WindowsModule

__all__ = ["TypeText", "Click", "Move", "Hotkey", "Lock", "KEY_CODES", "user32"]

#: named keys -> virtual-key codes
KEY_CODES = {
    "enter": 0x0D, "tab": 0x09, "esc": 0x1B, "space": 0x20,
    "backspace": 0x08, "delete": 0x2E, "up": 0x26, "down": 0x28,
    "left": 0x25, "right": 0x27, "home": 0x24, "end": 0x23,
    "win": 0x5B, "ctrl": 0x11, "alt": 0x12, "shift": 0x10,
}
for _letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    KEY_CODES[_letter.lower()] = ord(_letter)
for _digit in "0123456789":
    KEY_CODES[_digit] = ord(_digit)
for _index in range(1, 13):
    KEY_CODES[f"f{_index}"] = 0x6F + _index

user32 = ctypes.windll.user32 if os.name == "nt" else None


def _key(name: str) -> int:
    try:
        return KEY_CODES[name.lower()]
    except KeyError:
        raise ValueError(f"unknown key {name!r}") from None


def _press(code: int) -> None:
    user32.keybd_event(code, 0, 0, 0)
    user32.keybd_event(code, 0, 2, 0)


class TypeText(WindowsModule):
    NAME = "windows.type"
    DESCRIPTION = "Type text into the focused window (unicode key events)"
    OPTIONS = (Option("TEXT", "text to type", "", required=True),
               Option("ENTER", "press Enter afterwards", "false",
                      choices=("true", "false")),
               Option("DELAY_MS", "gap between characters", "0"))

    def execute(self) -> dict:
        text = self.get("TEXT")
        delay = self.get_int("DELAY_MS", 0) / 1000.0
        for char in text:
            if char == "\n":
                _press(KEY_CODES["enter"])
            else:
                # KEYEVENTF_UNICODE: send the codepoint, not the layout key
                user32.keybd_event(0, ord(char), 4, 0)
                user32.keybd_event(0, ord(char), 4 | 2, 0)
            if delay:
                time.sleep(delay)
        if self.get_bool("ENTER"):
            _press(KEY_CODES["enter"])
        console.ok(f"typed {len(text)} char(s)")
        return {"chars": len(text)}


class Click(WindowsModule):
    NAME = "windows.click"
    DESCRIPTION = "Click a screen position (or wherever the pointer is)"
    OPTIONS = (Option("X", "x pixel (blank = current)"),
               Option("Y", "y pixel (blank = current)"),
               Option("BUTTON", "left|right|middle", "left",
                      choices=("left", "right", "middle")),
               Option("DOUBLE", "double click", "false",
                      choices=("true", "false")))

    FLAGS = {"left": (0x02, 0x04), "right": (0x08, 0x10),
             "middle": (0x20, 0x40)}

    def execute(self) -> dict:
        if self.get("X") and self.get("Y"):
            user32.SetCursorPos(self.get_int("X"), self.get_int("Y"))
            time.sleep(0.05)
        down, up = self.FLAGS[self.get("BUTTON")]
        for _ in range(2 if self.get_bool("DOUBLE") else 1):
            user32.mouse_event(down, 0, 0, 0, 0)
            user32.mouse_event(up, 0, 0, 0, 0)
            time.sleep(0.05)
        console.ok(f"{self.get('BUTTON')} click sent")
        return {"button": self.get("BUTTON")}


class Move(WindowsModule):
    NAME = "windows.move"
    DESCRIPTION = "Move the pointer to an absolute position"
    OPTIONS = (Option("X", "x pixel", "", required=True),
               Option("Y", "y pixel", "", required=True))

    def execute(self) -> dict:
        user32.SetCursorPos(self.get_int("X"), self.get_int("Y"))
        return {"x": self.get_int("X"), "y": self.get_int("Y")}


class Hotkey(WindowsModule):
    NAME = "windows.hotkey"
    DESCRIPTION = "Send a key combination, e.g. win+r or ctrl+shift+esc"
    OPTIONS = (Option("COMBO", "combo like ctrl+alt+t", "", required=True),)

    def execute(self) -> dict:
        codes = [_key(part) for part in self.get("COMBO").split("+") if part]
        for code in codes:
            user32.keybd_event(code, 0, 0, 0)
        for code in reversed(codes):
            user32.keybd_event(code, 0, 2, 0)
        console.ok(f"sent {self.get('COMBO')}")
        return {"combo": self.get("COMBO")}


class Lock(WindowsModule):
    NAME = "windows.lock"
    DESCRIPTION = "Lock the workstation, or report the foreground window"
    OPTIONS = (Option("ACTION", "lock|state", "lock",
                      choices=("lock", "state")),)

    def execute(self) -> dict:
        if self.get("ACTION") == "state":
            handle = user32.GetForegroundWindow()
            console.info(f"foreground hwnd: {handle}")
            return {"foreground": int(handle)}
        res = proc.run(["rundll32.exe", "user32.dll,LockWorkStation"], timeout=20)
        if not res.ok:
            console.warn(f"lock failed: {res.text.strip()[:120]}")
        else:
            console.ok("workstation locked")
        return {"locked": res.ok}


class Screenshot(WindowsModule):
    NAME = "windows.screenshot"
    DESCRIPTION = "Capture the screen to a BMP via GDI (no Pillow needed)"
    OPTIONS = (Option("OUT", "output path"),)

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize", ctypes.c_uint32), ("biWidth", ctypes.c_int32),
                    ("biHeight", ctypes.c_int32), ("biPlanes", ctypes.c_uint16),
                    ("biBitCount", ctypes.c_uint16),
                    ("biCompression", ctypes.c_uint32),
                    ("biSizeImage", ctypes.c_uint32),
                    ("biXPelsPerMeter", ctypes.c_int32),
                    ("biYPelsPerMeter", ctypes.c_int32),
                    ("biClrUsed", ctypes.c_uint32),
                    ("biClrImportant", ctypes.c_uint32)]

    def execute(self) -> dict:
        from omni.core import config
        width = user32.GetSystemMetrics(0)
        height = user32.GetSystemMetrics(1)
        path = os.path.expanduser(
            self.get("OUT") or
            os.path.join(config.output_dir("windows"), "screen.bmp"))
        os.makedirs(os.path.dirname(path), exist_ok=True)

        gdi = ctypes.windll.gdi32
        screen = user32.GetDC(0)
        memory = gdi.CreateCompatibleDC(screen)
        bitmap = gdi.CreateCompatibleBitmap(screen, width, height)
        gdi.SelectObject(memory, bitmap)
        gdi.BitBlt(memory, 0, 0, width, height, screen, 0, 0, 0x00CC0020)

        # one GetDIBits call for the whole surface: 32bpp, bottom-up, as BMP wants
        info = self.BITMAPINFOHEADER()
        info.biSize = ctypes.sizeof(self.BITMAPINFOHEADER)
        info.biWidth, info.biHeight = width, height    # positive = bottom-up
        info.biPlanes, info.biBitCount = 1, 32
        size = width * height * 4
        buffer = ctypes.create_string_buffer(size)
        copied = gdi.GetDIBits(memory, bitmap, 0, height, buffer,
                               ctypes.byref(info), 0)

        header = 14 + ctypes.sizeof(self.BITMAPINFOHEADER)
        import struct
        with open(path, "wb") as fh:
            fh.write(b"BM")
            fh.write(struct.pack("<IHHI", header + size, 0, 0, header))
            fh.write(bytes(info))
            fh.write(buffer.raw)

        gdi.DeleteObject(bitmap)
        gdi.DeleteDC(memory)
        user32.ReleaseDC(0, screen)
        if not copied:
            raise RuntimeError("GetDIBits returned no rows")
        console.ok(f"{os.path.getsize(path)} byte BMP -> {path}")
        return {"path": path, "width": width, "height": height}



