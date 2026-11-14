"""iPhone remote-control tests: preflight gates and console dispatch."""

import pytest

from omni.ios import preflight
from omni.ios.remote import HELP, dispatch
from omni.ios.modules import session


class FakeResult:
    def __init__(self, out="", ok=True):
        self.out = out
        self.err = "" if ok else out
        self.text = out
        self.ok = ok


class FakeClient:
    """Records argv; answers the preflight probes deterministically."""

    def __init__(self, dev_mode=False, ddi=False, paired=True, info=None):
        self.calls: list[tuple] = []
        self.dev_mode = dev_mode
        self.ddi = ddi
        self.paired = paired
        self._info = info if info is not None else {"DeviceName": "iPhone",
                                                    "ProductType": "iPhone14,2"}
        self.rsd = None
        self.tunnel = None

    # -- engine surface --------------------------------------------------
    def run(self, *args, timeout=None):
        self.calls.append(tuple(args))
        if args[:2] == ("amfi", "developer-mode-status"):
            return FakeResult("true" if self.dev_mode else "false")
        if args[:2] == ("mounter", "query-developer-mode-status"):
            return FakeResult("true" if self.ddi else "false")
        return FakeResult("ok")

    def info(self):
        if self._info is None:
            raise RuntimeError("no device")
        return dict(self._info)

    def is_paired(self):
        return self.paired

    # -- control surface (for dispatch tests) ----------------------------
    def tap(self, x, y):
        self.calls.append(("tap", x, y))

    def press_hold(self, x, y, ms):
        self.calls.append(("hold", x, y, ms))

    def swipe(self, *a, **k):
        self.calls.append(("swipe",) + a)

    def scroll(self, direction="down", steps=1):
        self.calls.append(("scroll", direction, steps))
        return steps

    def type_text(self, text):
        self.calls.append(("text", text))

    def key(self, name, count=1):
        self.calls.append(("key", name, count))

    def press_button(self, name):
        self.calls.append(("button", name))

    def wake(self):
        self.calls.append(("wake",))

    def lock(self):
        self.calls.append(("lock",))

    def unlock(self):
        self.calls.append(("unlock",))

    def lock_state(self):
        return "Locked"

    def screenshot(self, path):
        self.calls.append(("shot", path))
        return path

    def apps(self):
        return ["com.apple.mobilesafari", "com.whatsapp.WhatsApp"]

    def launch(self, bundle):
        self.calls.append(("launch", bundle))

    def kill(self, name):
        self.calls.append(("kill", name))
        return [123]

    def clipboard_get(self):
        return "copied-text"

    def clipboard_set(self, text):
        self.calls.append(("clip-set", text))

    def set_location(self, lat, lon):
        self.calls.append(("loc", lat, lon))

    def clear_location(self):
        self.calls.append(("loc-clear",))


# -- preflight --------------------------------------------------------------

def test_diagnose_is_ready_when_everything_is_present():
    report = preflight.diagnose(FakeClient(dev_mode=True, ddi=True))
    assert report.ready
    assert not report.blockers


def test_diagnose_flags_developer_mode_off():
    report = preflight.diagnose(FakeClient(dev_mode=False, ddi=True))
    assert not report.ready
    assert "developer mode" in [g.name for g in report.blockers]


def test_diagnose_flags_missing_developer_image():
    report = preflight.diagnose(FakeClient(dev_mode=True, ddi=False))
    assert "developer image" in [g.name for g in report.blockers]


def test_diagnose_flags_an_unpaired_host():
    report = preflight.diagnose(FakeClient(paired=False, dev_mode=True,
                                           ddi=True))
    gate = next(g for g in report.blockers if g.name == "paired")
    assert "ios.pair" in gate.fix


def test_diagnose_reports_an_invisible_device():
    report = preflight.diagnose(FakeClient(info=None))
    assert not report.ready
    assert report.gates[0].name == "device visible"


def test_tunnel_gate_is_ok_by_default():
    report = preflight.diagnose(FakeClient(dev_mode=True, ddi=True))
    tunnel = next(g for g in report.gates if g.name == "rsd tunnel")
    assert tunnel.ok and "auto" in tunnel.detail


def test_tunnel_gate_notes_explicit_config():
    client = FakeClient(dev_mode=True, ddi=True)
    client.rsd = ("127.0.0.1", "49152")
    report = preflight.diagnose(client)
    tunnel = next(g for g in report.gates if g.name == "rsd tunnel")
    assert "explicitly" in tunnel.detail


def test_bring_up_enables_developer_mode():
    client = FakeClient(dev_mode=False, ddi=True)
    preflight.bring_up(client, fix=True)
    assert ("amfi", "enable-developer-mode") in client.calls


def test_bring_up_mounts_the_developer_image():
    client = FakeClient(dev_mode=True, ddi=False)
    preflight.bring_up(client, fix=True)
    assert ("mounter", "auto-mount") in client.calls


def test_bring_up_without_fix_changes_nothing():
    client = FakeClient(dev_mode=False, ddi=False)
    report = preflight.bring_up(client, fix=False)
    assert not report.ready
    assert ("amfi", "enable-developer-mode") not in client.calls


def test_ready_report_needs_no_fixes():
    client = FakeClient(dev_mode=True, ddi=True)
    preflight.bring_up(client)
    assert ("mounter", "auto-mount") not in client.calls


# -- console dispatch -------------------------------------------------------

def test_help_lists_commands():
    out, quit_now = dispatch(FakeClient(), "help")
    assert not quit_now
    for name, _desc in HELP:
        assert name in out


def test_quit_flag():
    assert dispatch(FakeClient(), "quit")[1] is True
    assert dispatch(FakeClient(), "q")[1] is True


def test_blank_and_comment_lines_are_ignored():
    assert dispatch(FakeClient(), "   ") == ("", False)
    assert dispatch(FakeClient(), "# note") == ("", False)


def test_tap_parses_coordinates():
    client = FakeClient()
    dispatch(client, "tap 100 200")
    assert ("tap", 100, 200) in client.calls


def test_tap_defaults_to_centre():
    client = FakeClient()
    dispatch(client, "tap")
    assert ("tap", 32768, 32768) in client.calls


def test_text_keeps_inner_spaces():
    client = FakeClient()
    dispatch(client, "text hello  world")
    assert ("text", "hello  world") in client.calls


def test_long_uses_a_hold():
    client = FakeClient()
    dispatch(client, "long 10 20 900")
    assert ("hold", 10, 20, 900) in client.calls


def test_swipe_converts_seconds_to_float():
    client = FakeClient()
    dispatch(client, "swipe 1 2 3 4 50")
    assert any(c[0] == "swipe" for c in client.calls)


def test_key_defaults_to_enter():
    client = FakeClient()
    dispatch(client, "key")
    assert ("key", "enter", 1) in client.calls


def test_apps_can_be_filtered():
    out, _ = dispatch(FakeClient(), "apps whats")
    assert "whatsapp" in out.lower()


def test_clip_read_and_write():
    client = FakeClient()
    assert dispatch(client, "clip")[0] == "copied-text"
    dispatch(client, "clip set abc")
    assert ("clip-set", "abc") in client.calls


def test_location_set_and_clear():
    client = FakeClient()
    dispatch(client, "loc 51.5 -0.12")
    assert ("loc", 51.5, -0.12) in client.calls
    dispatch(client, "loc clear")
    assert ("loc-clear",) in client.calls


def test_unknown_command_is_reported():
    out, quit_now = dispatch(FakeClient(), "wibble")
    assert "unknown" in out and not quit_now


def test_shot_uses_a_timestamped_path():
    client = FakeClient()
    out, _ = dispatch(client, "shot")
    assert "saved" in out and any(c[0] == "shot" for c in client.calls)


def test_home_key_uses_the_button():
    client = FakeClient()
    dispatch(client, "app")
    assert ("button", "home") in client.calls


# -- module wiring ----------------------------------------------------------

def test_script_runs_each_command():
    result = session.Remote._run_script(FakeClient(), "tap 1 2; text hi; status")
    assert result["commands"] == 3


def test_script_survives_a_failing_command():
    class Boom(FakeClient):
        def tap(self, x, y):
            raise RuntimeError("nope")

    result = session.Remote._run_script(Boom(), "tap 1 2; text hi")
    assert result["commands"] == 1


def test_script_stops_on_quit():
    result = session.Remote._run_script(FakeClient(), "status; quit; text hi")
    assert result["commands"] == 2


def test_remote_module_has_expected_options():
    names = {o.name for o in session.Remote.OPTIONS}
    assert {"UDID", "SCRIPT", "CHECK"} <= names


def test_up_defaults_to_fixing():
    assert session.Up(FIX="true").get_bool("FIX", True) is True


@pytest.mark.parametrize("gate_state,expected", [
    ("ok", True), ("blocked", False), ("unknown", True),
])
def test_blocked_is_the_only_failing_state(gate_state, expected):
    report = preflight.Report(gates=[preflight.Gate("x", gate_state)])
    assert report.ready is expected
