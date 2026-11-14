"""Live session control: windows, focus, clipboard, processes.

The ``windows.*`` trade could read the host (browsers, Wi-Fi keys, Run keys)
and type into whatever happened to be focused. This is the missing half:
enumerate the windows on the desktop, find the one you mean by title, bring it
forward, close it, kill its owner — and read or write the clipboard.

Everything goes through ``user32``/``kernel32`` with plain stdlib ``ctypes``, so
there is nothing to install on the target and nothing to drop on disk. The API
object is injectable, which is what makes the logic testable without a desktop.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import sys
from dataclasses import dataclass

__all__ = ["Window", "api", "kernel", "list_windows", "find", "pick",
           "foreground", "focus", "minimise", "maximise", "restore", "close",
           "terminate", "process_name", "clipboard_text",
           "set_clipboard_text", "clear_clipboard", "WM_CLOSE"]

WM_CLOSE = 0x0010
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED = 0x1000
SW_MAXIMISE, SW_MINIMISE, SW_RESTORE = 3, 6, 9


def api():
    """``user32`` on Windows, else ``None``."""
    return ctypes.windll.user32 if os.name == "nt" else None


def kernel():
    """``kernel32`` on Windows, else ``None``."""
    return ctypes.windll.kernel32 if os.name == "nt" else None


def _need(handle, name: str):
    if handle is None:
        raise RuntimeError(f"{name} needs Windows — this is a live session "
                           "call, not an offline parse")
    return handle


def safe_text(text: str, width: int = 0) -> str:
    """A title the current console can print.

    Window titles carry emoji, and a Windows console is usually cp1252 — so a
    ``print`` of the raw title raises ``UnicodeEncodeError`` and takes the whole
    module down with it. This keeps what fits and replaces the rest.
    """
    flat = " ".join(str(text).split())
    if width:
        flat = flat[:width]
    encoding = getattr(sys.stdout, "encoding", "") or "utf-8"
    try:
        flat.encode(encoding)
        return flat
    except (UnicodeEncodeError, LookupError):
        return flat.encode(encoding, "replace").decode(encoding, "replace")


def _declare(function, restype=None, argtypes=None) -> None:
    """Set a ctypes signature, ignoring injected fakes (plain objects)."""
    try:
        if restype is not None:
            function.restype = restype
        if argtypes is not None:
            function.argtypes = argtypes
    except (AttributeError, TypeError):
        pass


def _bind(handle=None, library=None) -> None:
    """Declare the Win32 signatures ``ctypes`` otherwise guesses wrong.

    Two failure modes this fixes, both seen on a 64-bit desktop: a HANDLE
    returned as ``c_int`` is cut in half (an access violation when dereferenced
    — how a clipboard read fails in the field), and a handle passed to a
    function with no ``argtypes`` is truncated the same way (``OverflowError:
    int too long to convert``). Fakes are left alone.
    """
    text_args = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar), ctypes.c_int]
    if handle is not None:
        _declare(handle.EnumWindows)         # the callback needs no coercion
        _declare(handle.GetForegroundWindow, ctypes.c_void_p, [])
        _declare(handle.IsWindowVisible, ctypes.c_bool, [ctypes.c_void_p])
        _declare(handle.IsIconic, ctypes.c_bool, [ctypes.c_void_p])
        _declare(handle.GetWindowTextLengthW, ctypes.c_int, [ctypes.c_void_p])
        _declare(handle.GetWindowTextW, ctypes.c_int, text_args)
        _declare(handle.GetClassNameW, ctypes.c_int, text_args)
        _declare(handle.GetWindowThreadProcessId, wt.DWORD,
                 [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)])
        _declare(handle.GetWindowRect, ctypes.c_bool,
                 [ctypes.c_void_p, ctypes.POINTER(wt.RECT)])
        _declare(handle.ShowWindow, ctypes.c_bool,
                 [ctypes.c_void_p, ctypes.c_int])
        _declare(handle.SetForegroundWindow, ctypes.c_bool, [ctypes.c_void_p])
        _declare(handle.PostMessageW, ctypes.c_bool,
                 [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p,
                  ctypes.c_void_p])
        _declare(handle.OpenClipboard, ctypes.c_bool, [ctypes.c_void_p])
        _declare(handle.GetClipboardData, ctypes.c_void_p, [ctypes.c_uint])
        _declare(handle.SetClipboardData, ctypes.c_void_p,
                 [ctypes.c_uint, ctypes.c_void_p])
    if library is not None:
        _declare(library.GlobalLock, ctypes.c_void_p, [ctypes.c_void_p])
        _declare(library.GlobalUnlock, ctypes.c_bool, [ctypes.c_void_p])
        _declare(library.GlobalAlloc, ctypes.c_void_p,
                 [ctypes.c_uint, ctypes.c_size_t])
        _declare(library.OpenProcess, ctypes.c_void_p,
                 [ctypes.c_uint, ctypes.c_bool, ctypes.c_uint])
        _declare(library.TerminateProcess, ctypes.c_bool,
                 [ctypes.c_void_p, ctypes.c_uint])
        _declare(library.CloseHandle, ctypes.c_bool, [ctypes.c_void_p])
        _declare(library.QueryFullProcessImageNameW, ctypes.c_bool,
                 [ctypes.c_void_p, ctypes.c_uint,
                  ctypes.POINTER(ctypes.c_wchar), ctypes.POINTER(wt.DWORD)])



@dataclass(frozen=True)
class Window:
    """A top-level window, as the desktop sees it."""

    hwnd: int
    title: str = ""
    class_name: str = ""
    pid: int = 0
    rect: tuple[int, int, int, int] = (0, 0, 0, 0)
    visible: bool = True
    minimised: bool = False

    @property
    def width(self) -> int:
        return max(0, self.rect[2] - self.rect[0])

    @property
    def height(self) -> int:
        return max(0, self.rect[3] - self.rect[1])

    @property
    def centre(self) -> tuple[int, int]:
        return ((self.rect[0] + self.rect[2]) // 2,
                (self.rect[1] + self.rect[3]) // 2)

    def matches(self, needle: str, exact: bool = False) -> bool:
        if not needle:
            return True
        if exact:
            return self.title == needle
        return needle.lower() in self.title.lower()

    def to_row(self) -> list[str]:
        x, y = self.centre
        return [str(self.hwnd), safe_text(self.title, 44) or "(untitled)",
                safe_text(self.class_name, 18), f"{self.width}x{self.height}",
                "min" if self.minimised else "ok", str(self.pid), f"{x},{y}"]


def _title(handle, hwnd: int) -> str:
    length = int(handle.GetWindowTextLengthW(hwnd) or 0)
    buffer = ctypes.create_unicode_buffer(max(1, length + 1))
    handle.GetWindowTextW(hwnd, buffer, length + 1)
    return buffer.value


def _class_name(handle, hwnd: int) -> str:
    buffer = ctypes.create_unicode_buffer(256)
    handle.GetClassNameW(hwnd, buffer, 256)
    return buffer.value


def _pid(handle, hwnd: int) -> int:
    pid = wt.DWORD(0)
    handle.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return int(pid.value)


def _rect(handle, hwnd: int) -> tuple[int, int, int, int]:
    box = wt.RECT()
    if not handle.GetWindowRect(hwnd, ctypes.byref(box)):
        return (0, 0, 0, 0)
    return (int(box.left), int(box.top), int(box.right), int(box.bottom))


def list_windows(handle=None, visible_only: bool = True,
                 include_untitled: bool = False) -> list[Window]:
    """Every top-level window, best-effort (a window may vanish mid-walk)."""
    handle = _need(handle if handle is not None else api(), "list_windows")
    _bind(handle)
    found: list[Window] = []
    prototype = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p,
                                   ctypes.c_void_p)

    def _visit(hwnd, _param) -> bool:
        try:
            visible = bool(handle.IsWindowVisible(hwnd))
            if visible_only and not visible:
                return True
            title = _title(handle, hwnd)
            if not title and not include_untitled:
                return True
            found.append(Window(int(hwnd), title, _class_name(handle, hwnd),
                                _pid(handle, hwnd), _rect(handle, hwnd),
                                visible, bool(handle.IsIconic(hwnd))))
        except Exception:                        # noqa: BLE001 - window gone
            return True
        return True

    handle.EnumWindows(prototype(_visit), 0)
    return found


def find(title: str, handle=None, exact: bool = False,
         visible_only: bool = True) -> list[Window]:
    """Windows whose title matches ``title`` (substring unless ``exact``)."""
    return [window for window in list_windows(handle, visible_only)
            if window.matches(title, exact)]


def pick(title: str, handle=None) -> Window | None:
    """The window a human meant: exact title, then prefix, then substring."""
    windows = find(title, handle)
    if not windows:
        return None
    needle = title.lower()

    def rank(window: Window) -> tuple:
        low = window.title.lower()
        tier = 0 if low == needle else 1 if low.startswith(needle) else 2
        return (tier, len(window.title), not window.visible)

    return sorted(windows, key=rank)[0]


def foreground(handle=None) -> Window | None:
    """The window that currently has focus."""
    handle = _need(handle if handle is not None else api(), "foreground")
    _bind(handle)
    hwnd = int(handle.GetForegroundWindow() or 0)
    if not hwnd:
        return None
    return Window(hwnd, _title(handle, hwnd), _class_name(handle, hwnd),
                  _pid(handle, hwnd), _rect(handle, hwnd), True,
                  bool(handle.IsIconic(hwnd)))


def _show(hwnd: int, command: int, handle=None) -> bool:
    handle = _need(handle if handle is not None else api(), "_show")
    return bool(handle.ShowWindow(hwnd, command))


def focus(hwnd: int, handle=None) -> bool:
    """Restore and raise a window, then give it focus."""
    handle = _need(handle if handle is not None else api(), "focus")
    _show(hwnd, SW_RESTORE, handle)
    return bool(handle.SetForegroundWindow(hwnd))


def minimise(hwnd: int, handle=None) -> bool:
    return _show(hwnd, SW_MINIMISE, handle)


def maximise(hwnd: int, handle=None) -> bool:
    return _show(hwnd, SW_MAXIMISE, handle)


def restore(hwnd: int, handle=None) -> bool:
    return _show(hwnd, SW_RESTORE, handle)


def close(hwnd: int, handle=None) -> bool:
    """Ask a window to close (WM_CLOSE) — the polite, save-your-work way."""
    handle = _need(handle if handle is not None else api(), "close")
    return bool(handle.PostMessageW(hwnd, WM_CLOSE, 0, 0))


def terminate(hwnd: int, handle=None, library=None) -> int:
    """Kill the process that owns a window; returns its pid (0 on failure)."""
    handle = _need(handle if handle is not None else api(), "terminate")
    library = _need(library if library is not None else kernel(), "terminate")
    _bind(handle, library)
    pid = _pid(handle, hwnd)
    if not pid:
        return 0
    process = library.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not process:
        return 0
    try:
        library.TerminateProcess(process, 1)
    finally:
        library.CloseHandle(process)
    return pid


def process_name(pid: int, library=None) -> str:
    """Image name for a pid (``""`` when the process is gone/protected)."""
    library = _need(library if library is not None else kernel(),
                    "process_name")
    _bind(None, library)
    process = library.OpenProcess(PROCESS_QUERY_LIMITED, False, int(pid))
    if not process:
        return ""
    try:
        size = wt.DWORD(1024)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not library.QueryFullProcessImageNameW(process, 0, buffer,
                                                  ctypes.byref(size)):
            return ""
        return os.path.basename(buffer.value)
    finally:
        library.CloseHandle(process)


# ---------------------------------------------------------------------------
# clipboard
# ---------------------------------------------------------------------------

def clipboard_text(handle=None, library=None) -> str:
    """Current clipboard text (``""`` when empty or non-text)."""
    handle = _need(handle if handle is not None else api(), "clipboard_text")
    library = _need(library if library is not None else kernel(),
                    "clipboard_text")
    _bind(handle, library)
    if not handle.OpenClipboard(None):
        return ""
    try:
        data = handle.GetClipboardData(CF_UNICODETEXT)
        if not data:
            return ""
        pointer = library.GlobalLock(data)
        if not pointer:
            return ""
        try:
            return ctypes.wstring_at(pointer)
        finally:
            library.GlobalUnlock(data)
    finally:
        handle.CloseClipboard()


def set_clipboard_text(text: str, handle=None, library=None) -> int:
    """Replace the clipboard with ``text``; returns the characters stored."""
    handle = _need(handle if handle is not None else api(),
                   "set_clipboard_text")
    library = _need(library if library is not None else kernel(),
                    "set_clipboard_text")
    _bind(handle, library)
    payload = str(text)
    if not handle.OpenClipboard(None):
        raise RuntimeError("clipboard is held by another process")
    try:
        if not handle.EmptyClipboard():
            raise RuntimeError("EmptyClipboard failed")
        size = (len(payload) + 1) * 2                # UTF-16 + NUL
        block = library.GlobalAlloc(GMEM_MOVEABLE, size)
        if not block:
            raise RuntimeError("GlobalAlloc failed")
        pointer = library.GlobalLock(block)
        if not pointer:
            raise RuntimeError("GlobalLock failed")
        ctypes.memmove(pointer, ctypes.create_unicode_buffer(payload), size)
        library.GlobalUnlock(block)
        if not handle.SetClipboardData(CF_UNICODETEXT, block):
            raise RuntimeError("SetClipboardData failed")
    finally:
        handle.CloseClipboard()
    return len(payload)


def clear_clipboard(handle=None) -> bool:
    """Empty the clipboard (hands it over to the next copy immediately)."""
    handle = _need(handle if handle is not None else api(), "clear_clipboard")
    if not handle.OpenClipboard(None):
        return False
    try:
        return bool(handle.EmptyClipboard())
    finally:
        handle.CloseClipboard()

