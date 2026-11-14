"""Car-key tests: profile DB, frame analysis, and a real KeeLoq round-trip."""

import pytest

from omni.car import analysis, vehicles
from omni.rf import keeloq_crypto as kq
from omni.rf.keystore import Keystore
from omni.rf.subfile import SubFile

MAN_KEY = 0x5A6B7C8D


def _frame(button: int = 1, serial: int = 0x0A1B2C3, counter: int = 0x1234,
           man: int = MAN_KEY) -> int:
    word = ((button & 0xF) << 28) | ((serial & 0x3FF) << 16) | (counter & 0xFFFF)
    fix = ((button & 0xF) << 28) | (serial & 0x0FFFFFFF)
    return kq.join_frame(fix, kq.keeloq_encrypt(word, man))


# -- profile database -------------------------------------------------------

def test_profiles_cover_major_brands():
    brands = vehicles.brands()
    for brand in ("Audi", "BMW", "Mercedes", "Volkswagen", "Ford", "Toyota"):
        assert brand in brands


def test_profiles_are_frozen_and_deduped():
    with pytest.raises(Exception):
        vehicles.PROFILES[0].model = "changed"
    labels = [p.label for p in vehicles.PROFILES]
    assert len(labels) == len(set(labels))


def test_by_frequency_finds_candidates():
    hits = vehicles.for_frequency(433_920_000)
    assert hits
    assert all(abs(p.freq - 433_920_000) <= 1_000_000 for p in hits)


def test_for_frequency_ignores_far_away_bands():
    assert vehicles.for_frequency(446_000_000) == []


def test_search_matches_protocol_and_note():
    assert vehicles.search("keeloq")
    assert vehicles.search("trivially clonable")


def test_by_brand_is_case_insensitive():
    assert vehicles.by_brand("audi") == vehicles.by_brand("Audi")


def test_profile_rows_are_jsonable():
    row = vehicles.PROFILES[0].to_row()
    assert set(row) == {"brand", "model", "freq", "preset", "protocol",
                        "coding", "buttons", "region", "note"}


# -- frame analysis ---------------------------------------------------------

def test_analyze_frame_splits_button_and_serial():
    out = analysis.analyze_frame(*kq.split_frame(_frame(button=2,
                                                        serial=0x0FFFFFF)),
                                 keystore=None)
    assert out["button"] == 2
    assert out["serial"] == "0x0FFFFFF"
    assert out["manufacturer"] is None
    assert out["verdict"] == analysis.VERDICT_HOPPING_UNKNOWN


def test_manufacturer_search_recovers_key_and_counter():
    store = Keystore()
    store.add("TestOEM", MAN_KEY)
    out = analysis.analyze_frame(*kq.split_frame(_frame(counter=0x1234)), store)
    assert out["manufacturer"] == "TestOEM"
    assert out["counter"] == 0x1234
    assert out["verdict"] == analysis.VERDICT_HOPPING_KNOWN


def test_manufacturer_search_misses_with_wrong_key():
    store = Keystore()
    store.add("Wrong", 0x11111111)
    out = analysis.analyze_frame(*kq.split_frame(_frame()), store)
    assert out["manufacturer"] is None


def test_counter_chain_predicts_matching_encryptions():
    fix, hop = kq.split_frame(_frame(counter=0x1234))
    rows = analysis.counter_chain(fix, hop, MAN_KEY, count=3)
    assert len(rows) == 3
    # re-decrypting each prediction must yield the predicted counter
    for row in rows:
        _b, _s, cnt = kq.parse_decrypt(
            kq.keeloq_decrypt(int(row["hop"], 16), MAN_KEY))
        assert cnt == row["counter"]


# -- verdicts ---------------------------------------------------------------

@pytest.mark.parametrize("coding,known,expected", [
    ("fixed", False, analysis.VERDICT_FIXED),
    ("fixed", True, analysis.VERDICT_FIXED),
    ("ble", False, analysis.VERDICT_FIXED),
    ("hopping", True, analysis.VERDICT_HOPPING_KNOWN),
    ("hopping", False, analysis.VERDICT_HOPPING_UNKNOWN),
])
def test_verdict(coding, known, expected):
    assert analysis.verdict(coding, known) == expected


# -- .sub analysis and sweep ------------------------------------------------

def _sub(button=1, counter=0x2000, manufacture=None) -> SubFile:
    sub = SubFile()
    sub.protocol = "KeeLoq"
    sub.bit = 64
    sub.te = 400
    sub.frequency = 433_920_000
    sub.key = _frame(button=button, counter=counter)
    sub.manufacture = manufacture
    return sub


def test_analyze_sub_on_raw_capture():
    sub = SubFile()
    sub.filetype = "Flipper SubGhz RAW File"
    sub.raw_data = [400, -800, 400]
    out = analysis.analyze_sub(sub)
    assert out["raw"] is True
    assert "replay as-is" in out["verdict"]


def test_analyze_sub_without_keystore_still_reports_frame():
    out = analysis.analyze_sub(_sub(), None, ["Audi"])
    assert out["button"] == 1
    assert out["brands"] == ["Audi"]
    assert "Audi" in out["verdict"]


def test_sweep_generates_sequential_counters():
    store = Keystore()
    store.add("TestOEM", MAN_KEY)
    subs, counters = analysis.sweep(_sub(counter=0x2000), store, count=4, mode=0)
    assert len(subs) == 4
    assert counters == [0x2001, 0x2002, 0x2003, 0x2004]


def test_sweep_default_mode_jumps_by_0x3333():
    store = Keystore()
    store.add("TestOEM", MAN_KEY)
    _subs, counters = analysis.sweep(_sub(counter=0x2000), store, count=2)
    assert counters == [0x2000 + 0x3333, 0x2000 + 0x6666]


def test_sweep_step_skips_counters():
    store = Keystore()
    store.add("TestOEM", MAN_KEY)
    subs, counters = analysis.sweep(_sub(counter=0x2000), store, count=3,
                                    step=3, mode=0)
    assert counters == [0x2003, 0x2006, 0x2009]
    assert len(subs) == len(counters)


def test_sweep_respects_explicit_start():
    store = Keystore()
    store.add("TestOEM", MAN_KEY)
    _subs, counters = analysis.sweep(_sub(manufacture="TestOEM"), store,
                                     start=0x4000, count=2, mode=0)
    assert counters == [0x4001, 0x4002]


def test_sweep_marks_manufacturer_on_autodetect():
    store = Keystore()
    store.add("TestOEM", MAN_KEY)
    sub = _sub(counter=0x2000)
    analysis.sweep(sub, store, count=1)
    assert sub.manufacture == "TestOEM"


def test_sweep_without_key_replays_capture():
    subs, counters = analysis.sweep(_sub(), None, count=2)
    assert counters == []
    assert len(subs) == 2


def test_write_subs_persists_files(tmp_path):
    paths = analysis.write_subs([_sub()], str(tmp_path), prefix="t")
    assert len(paths) == 1
    loaded = SubFile.load(paths[0])
    assert loaded.protocol == "KeeLoq"


def test_keystore_load_missing_path_is_empty():
    assert len(analysis.load_keystore("does-not-exist.txt")) == 0
