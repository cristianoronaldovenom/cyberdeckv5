"""TUI rendering + new wifi/windows module tests.

Rendering is exercised through real curses on a pty (Linux), which is the only
way to prove the paint code does not crash; everything else is model-level.
"""

import os

import pytest

from omni.core import tui
from omni.wifi.modules import join
from omni.wifi import iface as iface_mod


# -- registry collectors ----------------------------------------------------

def test_collect_modules_has_every_tab_family():
    found = tui.collect_modules()
    for family, _title, _hint in tui.TABS:
        assert family in found


def test_collect_needs_covers_every_module():
    needs = tui.collect_needs()
    assert "wifi.crack_pure" in needs and "ios.remote" in needs


def test_help_lists_quit_and_run():
    names = {k for k, _v in tui.HELP}
    assert {"q", "o", "c", "/"} <= names


# -- render on a pty --------------------------------------------------------

def _screen():
    """(screen, cleanup) or None when curses/pty is unavailable."""
    try:
        import curses
    except ImportError:
        return None
    try:
        screen = curses.initscr()
    except curses.error:
        return None
    return screen


@pytest.mark.skipif(os.name == "nt", reason="pty is POSIX-only")
def test_dashboard_draws_on_a_pty():
    import pty
    import curses
    master, slave = pty.openpty()
    try:
        screen = curses.initscr()
    except curses.error:
        os.close(master)
        os.close(slave)
        pytest.skip("no curses terminal available")
    try:
        curses.resizeterm(30, 100)
        model = tui.Model(tui.collect_modules())
        model.set_needs(tui.collect_needs())
        dash = tui.Dashboard(screen, model)
        dash.draw()
    finally:
        curses.endwin()
        os.close(master)
        os.close(slave)


@pytest.mark.skipif(os.name == "nt", reason="pty is POSIX-only")
def test_dashboard_tab_bar_highlights_the_active_tab():
    import pty
    import curses
    master, slave = pty.openpty()
    try:
        screen = curses.initscr()
    except curses.error:
        os.close(master)
        os.close(slave)
        pytest.skip("no curses terminal available")
    try:
        curses.resizeterm(30, 120)
        model = tui.Model(tui.collect_modules())
        model.set_needs(tui.collect_needs())
        model.next_tab()
        dash = tui.Dashboard(screen, model)
        dash.draw()
        out = os.read(master, 65536).decode("utf-8", "replace")
        assert "Sub-GHz" in out
    finally:
        curses.endwin()
        os.close(master)
        os.close(slave)


@pytest.mark.skipif(os.name == "nt", reason="no curses on Windows python")
def test_run_dashboard_survives_a_dead_registry(monkeypatch, capsys):
    monkeypatch.setattr(tui.registry, "all", lambda fam=None: [])
    assert tui.run_dashboard() == 1
    assert "registry is empty" in capsys.readouterr().out


# -- wifi.connect / link ----------------------------------------------------

class StubProc:
    def __init__(self):
        self.calls: list[tuple] = []

    def has(self, binary):
        return binary in ("nmcli", "dhcpcd")

    def run(self, argv, timeout=None):
        self.calls.append(tuple(argv))
        return type("R", (), {"ok": True, "out": "", "err": "", "text": ""})


def test_connect_uses_nmcli_when_present(monkeypatch):
    stub = StubProc()
    monkeypatch.setattr(join.proc, "run", stub.run)
    monkeypatch.setattr(join.proc, "has", stub.has)
    monkeypatch.setattr(join, "_which_nmcli", lambda: True)
    monkeypatch.setattr(join.WifiModule, "monitor", lambda self: "wlan0")
    monkeypatch.setattr(join.Connect, "_pick_managed",
                        staticmethod(lambda: "wlan0"))
    monkeypatch.setattr(iface_mod, "link_info",
                        lambda iface: {"ip": "10.0.0.7", "ssid": "Net"})
    result = join.Connect(SSID="Net", PSK="password123").execute()
    assert result["ip"] == "10.0.0.7"
    assert stub.calls[0][:4] == ("nmcli", "device", "wifi", "connect")


def test_connect_appends_hidden_flag(monkeypatch):
    stub = StubProc()
    monkeypatch.setattr(join.proc, "run", stub.run)
    monkeypatch.setattr(join.proc, "has", stub.has)
    monkeypatch.setattr(join, "_which_nmcli", lambda: True)
    monkeypatch.setattr(join.WifiModule, "monitor", lambda self: "wlan0")
    monkeypatch.setattr(join.Connect, "_pick_managed",
                        staticmethod(lambda: "wlan0"))
    monkeypatch.setattr(iface_mod, "link_info", lambda iface: {"ip": ""})
    join.Connect(SSID="Hidden", PSK="password123", HIDDEN="true").execute()
    assert "hidden" in stub.calls[0]


def test_wpa_file_writes_mode_600(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX file modes do not apply on Windows")
    mod = join.WpaFile(SSID="Net", PSK="secret123", PATH=str(tmp_path / "w.conf"))
    result = mod.execute()
    import stat
    mode = stat.S_IMODE(os.stat(result["path"]).st_mode)
    assert mode & 0o077 == 0
    body = open(result["path"], encoding="utf-8").read()
    assert 'ssid="Net"' in body and 'psk="secret123"' in body


def test_wpa_file_open_network_has_no_psk(tmp_path):
    mod = join.WpaFile(SSID="Free", PSK="", PATH=str(tmp_path / "w.conf"))
    body = open(mod.execute()["path"], encoding="utf-8").read()
    assert "key_mgmt=NONE" in body and "psk=" not in body


# -- windows control --------------------------------------------------------

def test_key_codes_cover_common_keys():
    from omni.windows.modules import control
    assert control.KEY_CODES["enter"] == 0x0D
    assert control.KEY_CODES["a"] == ord("A")
    assert control.KEY_CODES["f5"] == 0x74


def test_key_lookup_rejects_unknown():
    from omni.windows.modules import control
    with pytest.raises(ValueError, match="unknown key"):
        control._key("hyper")


def test_windows_modules_refuse_to_run_on_posix(monkeypatch):
    if os.name == "nt":
        pytest.skip("this is a Windows host")
    from omni.windows.modules import control
    mod = control.TypeText(TEXT="x")
    with pytest.raises(RuntimeError, match="not Windows"):
        mod.validate()
