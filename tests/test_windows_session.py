"""Live Windows session control: window walks, clipboard, service argv.

No real desktop is needed: ``user32`` and ``kernel32`` are injected, so the
enumeration, the ranking and the clipboard protocol are exercised exactly as
they run — the fake is what a Windows box would answer.
"""

import ctypes
import ctypes.wintypes as wt
import os

import pytest

from omni.windows import services, session
from omni.windows.modules.service import RUN_KEY, Registry

#: the "desktop" the fake API enumerates
DESKTOP = {
    0x10: ("Inbox - Thunderbird", "MozillaWindowClass", 400, True),
    0x20: ("Inbox - Thunderbird (2)", "MozillaWindowClass", 401, True),
    0x30: ("Task Manager", "TaskManagerWindow", 402, True),
    0x40: ("hidden helper", "Tooltip", 403, False),
    0x50: ("", "IME", 404, True),
}


class FakeUser32:
    """The handful of ``user32`` calls the session layer makes."""

    def __init__(self, clipboard: str = ""):
        self.clipboard = clipboard
        self.shown: list[tuple[int, int]] = []
        self.focused: list[int] = []
        self.posted: list[tuple[int, int]] = []
        self.foreground_hwnd = 0x10

    # -- enumeration -------------------------------------------------------
    def EnumWindows(self, callback, extra):          # noqa: N802 - Win32 name
        for hwnd in DESKTOP:
            if not callback(hwnd, extra):
                break

    def IsWindowVisible(self, hwnd):                 # noqa: N802 - Win32 name
        return DESKTOP[hwnd][3]

    def IsIconic(self, hwnd):                        # noqa: N802 - Win32 name
        return hwnd == 0x30

    def GetWindowTextLengthW(self, hwnd):            # noqa: N802 - Win32 name
        return len(DESKTOP[hwnd][0])

    def GetWindowTextW(self, hwnd, buffer, size):    # noqa: N802 - Win32 name
        buffer.value = DESKTOP[hwnd][0]
        return len(buffer.value)

    def GetClassNameW(self, hwnd, buffer, size):     # noqa: N802 - Win32 name
        buffer.value = DESKTOP[hwnd][1]

    def GetWindowThreadProcessId(self, hwnd, pointer):   # noqa: N802
        pointer._obj.value = DESKTOP[hwnd][2]

    def GetWindowRect(self, hwnd, pointer):          # noqa: N802 - Win32 name
        box = pointer._obj
        box.left, box.top = 10 * hwnd, 20
        box.right, box.bottom = 10 * hwnd + 100, 120
        return True

    # -- window actions ----------------------------------------------------
    def ShowWindow(self, hwnd, command):              # noqa: N802 - Win32 name
        self.shown.append((hwnd, command))
        return True

    def SetForegroundWindow(self, hwnd):              # noqa: N802 - Win32 name
        self.focused.append(hwnd)
        return True

    def PostMessageW(self, hwnd, message, wparam, lparam):   # noqa: N802
        self.posted.append((hwnd, message))
        return True

    def GetForegroundWindow(self):                    # noqa: N802 - Win32 name
        return self.foreground_hwnd

    # -- clipboard ---------------------------------------------------------
    def OpenClipboard(self, owner):                   # noqa: N802 - Win32 name
        return True

    def CloseClipboard(self):                         # noqa: N802 - Win32 name
        return True

    def EmptyClipboard(self):                         # noqa: N802 - Win32 name
        self.clipboard = ""
        return True

    def GetClipboardData(self, fmt):                  # noqa: N802 - Win32 name
        return fmt

    def SetClipboardData(self, fmt, handle):          # noqa: N802 - Win32 name
        assert fmt == session.CF_UNICODETEXT
        return handle


class FakeKernel32:
    """GlobalAlloc/GlobalLock plus process termination."""

    def __init__(self, text: str = "", clipboard: str = ""):
        self.text = text
        self.clipboard = clipboard
        self.buffers: list = []
        self.terminated: list[int] = []

    def GlobalLock(self, handle):                      # noqa: N802 - Win32 name
        buffer = ctypes.create_unicode_buffer(self.clipboard)
        self.buffers.append(buffer)
        return ctypes.addressof(buffer)

    def GlobalUnlock(self, handle):                    # noqa: N802 - Win32 name
        return True

    def GlobalAlloc(self, flags, size):                # noqa: N802 - Win32 name
        buffer = ctypes.create_unicode_buffer(size // 2)
        self.buffers.append(buffer)
        return ctypes.addressof(buffer)

    def OpenProcess(self, access, inherit, pid):       # noqa: N802 - Win32 name
        return 1234 if pid else 0

    def TerminateProcess(self, handle, code):           # noqa: N802 - Win32 name
        self.terminated.append(handle)
        return True

    def CloseHandle(self, handle):                     # noqa: N802 - Win32 name
        return True

    def QueryFullProcessImageNameW(self, handle, flags, buffer, size):  # noqa
        buffer.value = r"C:\Program Files\App\app.exe"
        return True



# -- window enumeration ------------------------------------------------------

def test_windows_come_back_with_title_class_pid_and_geometry():
    fake = FakeUser32()
    windows = session.list_windows(fake)
    assert [window.title for window in windows] == [
        "Inbox - Thunderbird", "Inbox - Thunderbird (2)", "Task Manager"]
    first = windows[0]
    assert first.pid == 400 and first.class_name == "MozillaWindowClass"
    assert (first.width, first.height) == (100, 100)
    assert first.centre == (0x10 * 10 + 50, 70)


def test_hidden_and_untitled_windows_are_optional():
    fake = FakeUser32()
    assert len(session.list_windows(fake, visible_only=False)) == 4
    untitled = session.list_windows(fake, include_untitled=True)
    assert any(window.title == "" for window in untitled)


def test_pick_prefers_the_exact_title():
    fake = FakeUser32()
    assert session.pick("Task Manager", fake).hwnd == 0x30
    assert session.pick("inbox", fake).hwnd == 0x10        # shortest match
    assert session.pick("inbox - thunderbird (2)", fake).hwnd == 0x20
    assert session.pick("nothing like this", fake) is None


def test_focus_restores_first_then_raises():
    fake = FakeUser32()
    assert session.focus(0x30, fake) is True
    assert fake.shown == [(0x30, session.SW_RESTORE)]
    assert fake.focused == [0x30]
    session.minimise(0x30, fake)
    session.maximise(0x30, fake)
    assert [command for _, command in fake.shown] == [
        session.SW_RESTORE, session.SW_MINIMISE, session.SW_MAXIMISE]


def test_close_asks_politely_and_kill_goes_through_the_owner_pid():
    fake, kernel = FakeUser32(), FakeKernel32()
    assert session.close(0x20, fake) is True
    assert fake.posted == [(0x20, session.WM_CLOSE)]
    assert session.terminate(0x20, fake, kernel) == 401
    assert kernel.terminated == [1234]


def test_foreground_and_process_names():
    fake, kernel = FakeUser32(), FakeKernel32()
    window = session.foreground(fake)
    assert window is not None and window.hwnd == 0x10
    assert session.process_name(400, kernel) == "app.exe"


def test_the_layer_refuses_to_pretend_off_windows():
    with pytest.raises(RuntimeError):
        session._need(None, "list_windows")
    assert session.Window(1, "x").matches("x") is True


# -- clipboard --------------------------------------------------------------

def test_clipboard_text_is_read_through_the_global_lock():
    fake, kernel = FakeUser32(), FakeKernel32(clipboard="hunter2")
    assert session.clipboard_text(fake, kernel) == "hunter2"


def test_clipboard_set_hands_a_unicode_block_to_windows():
    fake, kernel = FakeUser32(), FakeKernel32()
    assert session.set_clipboard_text("secret", fake, kernel) == 6
    assert session.set_clipboard_text("", fake, kernel) == 0


def test_clipboard_can_be_cleared():
    fake = FakeUser32()
    assert session.clear_clipboard(fake) is True


# -- services ---------------------------------------------------------------

def test_service_argv_is_exact():
    argv = services.create_args("omni", r"C:\payload.exe", "auto", "OMNI")
    assert argv[:5] == ["sc", "create", "omni", "binPath=",
                        r"C:\payload.exe"]
    assert argv[argv.index("start=") + 1] == "auto"
    assert argv[argv.index("DisplayName=") + 1] == "OMNI"
    assert services.delete_args("omni") == ["sc", "delete", "omni"]
    assert services.query_args("") == ["sc", "query"]
    assert services.query_args("omni") == ["sc", "query", "omni"]
    with pytest.raises(ValueError):
        services.create_args("", r"C:\payload.exe")


def test_sc_query_output_is_parsed_into_services():
    text = """
SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_START_NAME : LocalSystem

SERVICE_NAME: omni
        STATE              : 1  STOPPED
"""
    rows = services.parse_query(text)
    assert [row["service_name"] for row in rows] == ["Spooler", "omni"]
    assert rows[0]["state"].startswith("4")
    assert rows[0]["service_start_name"] == "LocalSystem"


def test_hive_saves_use_reg_save_and_land_on_disk(tmp_path, monkeypatch):
    saved = {}

    class Result:
        ok = True
        text = ""

    def fake_run(argv, timeout=120, cwd=None, env=None, input_text=None):
        saved["argv"] = argv
        with open(argv[3], "wb") as fh:
            fh.write(b"SAM")
        return Result()

    monkeypatch.setattr(services.proc, "run", fake_run)
    result = services.save_hives(str(tmp_path), ["sam"])
    assert saved["argv"][:3] == ["reg", "save", r"HKLM\SAM"]
    assert result["sam"].endswith("SAM.hive")
    assert os.path.getsize(result["sam"]) == 3


# -- the modules ------------------------------------------------------------

@pytest.mark.skipif(os.name != "nt", reason="winreg lives on Windows")
def test_registry_paths_split_into_a_hive_and_a_subkey():
    assert Registry.split(RUN_KEY)[1] == RUN_KEY      # bare path = current user
    assert Registry.split(r"HKCU\Software")[1] == r"Software"
    with pytest.raises(ValueError):
        Registry.split("HKXX\\Software")


def test_windows_takeover_modules_are_registered():
    from omni.core.module import registry

    names = {module.NAME for module in registry.all("windows")}
    assert {"windows.window", "windows.clipboard", "windows.service",
            "windows.reg"} <= names


@pytest.mark.skipif(os.name != "nt", reason="the registry lives on Windows")
def test_registry_query_reads_a_real_key():
    report = Registry(ACTION="query", KEY=r"HKCU\Software").run()
    assert isinstance(report["values"], list)
