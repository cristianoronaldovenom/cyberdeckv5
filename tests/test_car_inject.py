"""Counter-prediction injection tests (car family)."""

import pytest

from omni.car.modules import inject as car_inject
from omni.rf import keeloq_crypto as kq
from omni.rf.keystore import Keystore
from omni.rf.subfile import SubFile

MAN = 0x5A6B7C8D
SERIAL = 0x0A1B2C3


def _frame(button: int = 1, counter: int = 0x2000) -> int:
    word = ((button & 0xF) << 28) | ((SERIAL & 0x3FF) << 16) | (counter & 0xFFFF)
    fix = ((button & 0xF) << 28) | (SERIAL & 0x0FFFFFFF)
    return kq.join_frame(fix, kq.keeloq_encrypt(word, MAN))


def _sub(counter: int = 0x2000, protocol: str = "KeeLoq") -> SubFile:
    sub = SubFile()
    sub.protocol = protocol
    sub.bit, sub.te, sub.frequency = 64, 400, 433_920_000
    sub.key = _frame(counter=counter)
    return sub


@pytest.fixture
def keystore():
    store = Keystore()
    store.add("TestOEM", MAN)
    return store


@pytest.fixture
def module(tmp_path, keystore, monkeypatch):
    def build(**opts):
        path = tmp_path / "cap.sub"
        _sub().save(str(path))
        mod = car_inject.CounterInject(SUB=str(path), **opts)
        monkeypatch.setattr(mod, "keystore", lambda p=None: keystore)
        return mod
    return build


def test_counter_inject_fires_a_predicted_window(module):
    result = module(WINDOW="4", SAVE="false").execute()
    assert result["sent"] == 1
    assert len(result["counters"]) == 4
    assert result["frames"] == 4
    assert result["demo"] is True
    assert result["air_ms"] > 0


def test_counter_inject_writes_the_train(module):
    result = module(WINDOW="2").execute()
    assert result["saved"].endswith(".sub")
    loaded = SubFile.load(result["saved"])
    assert loaded.protocol == "RAW"


def test_counter_inject_honours_start_and_step(module, keystore):
    from omni.car import analysis
    mod = module(WINDOW="2", START="0x4000", STEP="2", SAVE="false")
    result = mod.execute()
    _subs, expected = analysis.sweep(mod.load_sub(), keystore, start=0x4000,
                                     count=2, step=2)
    assert result["counters"] == expected
    assert expected[0] > 0x4000


def test_counter_inject_without_key_reports_nothing(tmp_path, monkeypatch):
    path = tmp_path / "cap.sub"
    _sub().save(str(path))
    mod = car_inject.CounterInject(SUB=str(path), WINDOW="2")
    monkeypatch.setattr(mod, "keystore", lambda p=None: Keystore())
    result = mod.execute()
    assert result["sent"] == 0
    assert result["counters"] == []


def test_counter_inject_rejects_non_keeloq(tmp_path, keystore, monkeypatch):
    path = tmp_path / "p.sub"
    sub = SubFile()
    sub.protocol, sub.bit, sub.key = "Princeton", 24, 0x11
    sub.frequency = 433_920_000
    sub.save(str(path))
    mod = car_inject.CounterInject(SUB=str(path))
    monkeypatch.setattr(mod, "keystore", lambda p=None: keystore)
    with pytest.raises(ValueError, match="needs a KeeLoq capture"):
        mod.execute()


def test_counter_inject_requires_sub():
    with pytest.raises(ValueError, match="missing required option"):
        car_inject.CounterInject().load_sub()
