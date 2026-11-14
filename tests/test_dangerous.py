"""Dangerous-tier tests: blind RF brute, car unlock chain, Android persistence."""

import pytest

from omni.rf import marquee
from omni.rf.modules import brute


def test_brute_covers_the_requested_range():
    mod = brute.Brute(PROTOCOL="CAME", COUNT="4", SAVE="false")
    result = mod.execute()
    assert result["codes"] == 4
    assert result["coverage"] > 0
    assert result["sent"] == 1


def test_brute_reports_full_coverage_for_a_whole_12bit_space():
    result = brute.Brute(PROTOCOL="CAME", COUNT="4096", SAVE="false").execute()
    assert result["coverage"] == 100.0


def test_brute_applies_step_and_start():
    result = brute.Brute(PROTOCOL="CAME", COUNT="3", START="0x10",
                         STEP="2", SAVE="false").execute()
    assert result["bits"] == 12
    assert result["codes"] == 3


def test_brute_rejects_start_outside_the_space():
    with pytest.raises(ValueError, match="does not fit"):
        brute.Brute(PROTOCOL="CAME", START="0x1000").execute()


def test_brute_wraps_past_the_ceiling():
    result = brute.Brute(PROTOCOL="CAME", COUNT="3", START="0xFFF",
                         SAVE="false").execute()
    assert result["codes"] == 3


def test_brute_saves_the_train():
    result = brute.Brute(PROTOCOL="CAME", COUNT="2").execute()
    assert result["saved"].endswith(".sub")


def test_brute_uses_protocol_bit_defaults():
    assert brute.Brute(PROTOCOL="Holtek")._bits() == 40
    assert brute.Brute(PROTOCOL="CAME", BITS="10")._bits() == 10


def test_brute_default_copy_count_is_one():
    slots = marquee.plan([marquee.frame_from_spec("CAME:12:5")], "capture", 1)
    assert len(slots) == 1


# -- car.unlock chain -------------------------------------------------------

from omni.car.modules import unlock as car_unlock
from omni.rf import keeloq_crypto as kq
from omni.rf.keystore import Keystore
from omni.rf.subfile import SubFile

MAN = 0x5A6B7C8D


def _sub(tmp_path, counter=0x2000):
    word = ((1 & 0xF) << 28) | ((0x0A1B2C3 & 0x3FF) << 16) | counter
    fix = ((1 & 0xF) << 28) | (0x0A1B2C3 & 0x0FFFFFFF)
    sub = SubFile()
    sub.protocol, sub.bit, sub.te, sub.frequency = "KeeLoq", 64, 400, 433_920_000
    sub.key = kq.join_frame(fix, kq.keeloq_encrypt(word, MAN))
    path = tmp_path / "cap.sub"
    sub.save(str(path))
    return str(path)


@pytest.fixture
def keystore():
    store = Keystore()
    store.add("TestOEM", MAN)
    return store


def test_unlock_runs_the_whole_chain(tmp_path, keystore, monkeypatch):
    mod = car_unlock.Unlock(SUB=_sub(tmp_path), WINDOW="3")
    monkeypatch.setattr(mod, "keystore", lambda p=None: keystore)
    result = mod.execute()
    assert result["manufacturer"] == "TestOEM"
    assert result["sent"] == 1
    assert result["counters"] == 3


def test_unlock_refuses_without_a_keystore(tmp_path, monkeypatch):
    mod = car_unlock.Unlock(SUB=_sub(tmp_path))
    monkeypatch.setattr(mod, "keystore", lambda p=None: Keystore())
    with pytest.raises(RuntimeError, match="empty keystore"):
        mod.execute()


def test_unlock_rejects_a_fixed_code_capture(tmp_path, keystore, monkeypatch):
    sub = SubFile()
    sub.protocol, sub.bit, sub.key = "Princeton", 24, 0x11
    sub.frequency = 433_920_000
    path = tmp_path / "p.sub"
    sub.save(str(path))
    mod = car_unlock.Unlock(SUB=str(path))
    monkeypatch.setattr(mod, "keystore", lambda p=None: keystore)
    with pytest.raises(ValueError, match="not a rolling-code"):
        mod.execute()


# -- android persistence ----------------------------------------------------

from omni.android.modules import persist


class Rec:
    def __init__(self):
        self.calls = []

    def _r(self, out=""):
        return type("R", (), {"ok": True, "out": out, "err": "", "text": out})

    def shell_result(self, *a, **k):
        self.calls.append(list(a))
        return self._r("")

    def shell(self, *a, **k):
        self.calls.append(list(a))
        return self._r()

    def raw(self, *a, **k):
        self.calls.append(list(a))
        return self._r()

    def text(self, t):
        self.calls.append(["text", t])

    def key(self, c):
        self.calls.append(["key", str(c)])

    def clipboard_get(self):
        return ""


@pytest.fixture
def rec():
    return Rec()


def test_persist_arms_alarm_and_whitelist(rec):
    mod = persist.Persist(PACKAGE="com.x")
    mod.adb = lambda: rec
    result = mod.execute()
    assert result["minutes"] == 15
    flat = [" ".join(c) for c in rec.calls]
    assert any("deviceidle whitelist +com.x" in f for f in flat)
    assert any("cmd alarm set" in f for f in flat)
    assert any("BOOT_COMPLETED" in f for f in flat)


def test_persist_status_reads_alarms(rec):
    mod = persist.Persist(PACKAGE="com.x", ACTION="status")
    mod.adb = lambda: rec
    result = mod.execute()
    assert result["entries"] == 0


def test_persist_remove_stops_the_app(rec):
    mod = persist.Persist(PACKAGE="com.x", ACTION="remove")
    mod.adb = lambda: rec
    mod.execute()
    assert any("force-stop" in " ".join(c) for c in rec.calls)


def test_creds_parses_ssids_and_psks_from_a_store(rec):
    store = ('<string name="SSID">Home</string>'
             '<string name="PreSharedKey">hunter2</string>')
    rec.shell_result = lambda *a, **k: rec._r(store)
    mod = persist.Creds()
    mod.adb = lambda: rec
    result = mod.execute()
    assert "Home" in result["ssids"]
    assert "hunter2" in result["psks"]


def test_creds_warns_when_the_store_is_unreadable(rec):
    mod = persist.Creds()
    mod.adb = lambda: rec
    result = mod.execute()
    assert "wifi" not in result
