"""Android control/permission tests: argv shape, not shell strings."""

import pytest

from omni.android import adb as adb_mod
from omni.android.adb import Adb, AdbError
from omni.android.modules import control, perms
from omni.core import proc


class Recorder:
    """Stands in for proc.run, capturing argv and returning canned results."""

    def __init__(self, out: str = "", ok: bool = True):
        self.calls: list[list[str]] = []
        self.out = out
        self.ok = ok

    def __call__(self, argv, timeout=None):
        self.calls.append(list(argv))
        return proc.Result(argv, 0 if self.ok else 1, self.out, "" if self.ok else self.out)

    @property
    def last(self) -> list[str]:
        return self.calls[-1]


@pytest.fixture
def adb(monkeypatch):
    """An Adb client whose subprocess layer is captured."""
    rec = Recorder()
    monkeypatch.setattr(adb_mod.proc, "run", rec)
    client = Adb(binary="adb", serial="XYZ")
    client.recorder = rec
    return client


# -- argv construction ------------------------------------------------------

def test_serial_is_passed_with_dash_s(adb):
    adb.shell("getprop", "ro.product.model")
    assert adb.recorder.last == ["adb", "-s", "XYZ", "shell", "getprop",
                                 "ro.product.model"]


def test_text_escapes_spaces_not_the_whole_argv(adb):
    adb.text("hello world")
    assert adb.recorder.last[-1] == "hello%sworld"


def test_long_press_is_a_zero_distance_swipe(adb):
    adb.long_press(10, 20, 800)
    assert adb.recorder.last[-6:] == ["swipe", "10", "20", "10", "20", "800"]


def test_long_press_has_a_floor(adb):
    adb.long_press(1, 2, 10)
    assert adb.recorder.last[-1] == "400"


def test_scroll_down_drags_upwards(adb):
    adb.scroll("down", steps=1, x=100, y=900, span=500)
    assert adb.recorder.last[-5:] == ["100", "900", "100", "400", "120"]


def test_scroll_up_drags_downwards(adb):
    adb.scroll("up", steps=1, x=100, y=400, span=500)
    assert adb.recorder.last[-5:] == ["100", "400", "100", "900", "120"]


def test_scroll_repeats(adb):
    adb.scroll("down", steps=3)
    assert len(adb.recorder.calls) == 3


def test_touch_stream_uses_motionevent(adb):
    adb.touch_down(5, 6)
    adb.touch_move(7, 8)
    adb.touch_up(9, 10)
    assert [c[6] for c in adb.recorder.calls] == ["DOWN", "MOVE", "UP"]


def test_grant_and_revoke(adb):
    adb.grant("com.app", "android.permission.CAMERA")
    assert adb.recorder.last[-3:] == ["grant", "com.app",
                                     "android.permission.CAMERA"]
    adb.revoke("com.app", "android.permission.CAMERA")
    assert adb.recorder.last[-3:] == ["revoke", "com.app",
                                     "android.permission.CAMERA"]


def test_disable_uses_disable_user_for_user_zero(adb):
    adb.set_enabled("com.bloat", False)
    assert adb.recorder.last[-4:] == ["disable-user", "--user", "0",
                                     "com.bloat"]
    adb.set_enabled("com.bloat", True)
    assert adb.recorder.last[-4] == "enable"


def test_swipe_unlock_swipes_up(adb):
    adb.swipe_unlock()
    assert adb.recorder.last[-2:] == ["700", "200"]


def test_tap_text_uses_uiautomator_bounds(monkeypatch):
    dump = '<node text="Sign in" bounds="[100,200][300,400]" />'
    rec = Recorder(out=dump)
    monkeypatch.setattr(adb_mod.proc, "run", rec)
    Adb(binary="adb", serial="S").tap_text("Sign in")
    # tapped the centre of the matched node
    assert rec.last[-2:] == ["200", "300"]


def test_tap_text_errors_when_missing(monkeypatch):
    monkeypatch.setattr(adb_mod.proc, "run", Recorder(out="<node/>"))
    with pytest.raises(AdbError, match="no UI node"):
        Adb(binary="adb", serial="S").tap_text("Nope")


# -- permission aliases -----------------------------------------------------

def test_resolve_permission_maps_aliases():
    assert perms.resolve_permission("camera") == "android.permission.CAMERA"
    assert perms.resolve_permission("LOCATION") == \
        "android.permission.ACCESS_FINE_LOCATION"


def test_resolve_permission_passes_full_names():
    assert perms.resolve_permission("com.foo.BAR") == "com.foo.BAR"


def test_resolve_permission_rejects_unknown():
    with pytest.raises(ValueError, match="unknown permission"):
        perms.resolve_permission("teleport")
