"""RF marquee/injection tests: framing, planning, timing and round-trips."""

import pytest

from omni.rf import marquee
from omni.rf.modules import inject, rolljam
from omni.rf.protocols import PrincetonEncoder
from omni.rf.subfile import SubFile


def _frame(**kw):
    base = dict(protocol="Princeton", data=0xABC123, bits=24, te=390)
    base.update(kw)
    return marquee.Frame(**base)


# -- frame parsing ----------------------------------------------------------

def test_frame_from_spec_defaults():
    frame = marquee.frame_from_spec("Princeton:24:ABC123")
    assert frame.protocol == "Princeton"
    assert frame.bits == 24
    assert frame.data == 0xABC123
    assert frame.frequency == 433_920_000
    assert frame.te == 390          # protocol default


def test_frame_from_spec_full_form():
    frame = marquee.frame_from_spec("CAME:12:5A5:315000000:320:20")
    assert frame.frequency == 315_000_000
    assert frame.te == 320
    assert frame.guard == 20


def test_frame_from_spec_rejects_unknown_protocol():
    with pytest.raises(ValueError, match="unknown protocol"):
        marquee.frame_from_spec("Wibble:12:5A5")


def test_frame_from_spec_rejects_short_form():
    with pytest.raises(ValueError, match="bad frame spec"):
        marquee.frame_from_spec("Princeton:24")


def test_frame_rejects_data_wider_than_bits():
    with pytest.raises(ValueError, match="does not fit"):
        _frame(bits=8, data=0x1FF)


def test_frame_te_has_a_floor():
    assert _frame(te=10).te == 100


# -- synthesis --------------------------------------------------------------

def test_levels_match_the_real_encoder():
    frame = _frame()
    expected = PrincetonEncoder(data=frame.data, data_count_bit=frame.bits,
                               te=frame.te,
                               guard_time=frame.guard).build_upload()
    assert frame.levels() == expected


def test_frame_ms_counts_the_guard():
    # 4 TE per bit, one closing TE, then the 30-period guard
    assert _frame().frame_ms() == pytest.approx((24 * 4 + 1 + 30) * 390 / 1000.0)


# -- planning ---------------------------------------------------------------

def test_plan_head_first_fires_newest_capture():
    frames = [_frame(data=1, bits=24), _frame(data=2, bits=24)]
    slots = marquee.plan(frames, "head-first", copies=1)
    assert [s.frame.data for s in slots] == [2, 1]


def test_plan_capture_keeps_order_and_repeats():
    frames = [_frame(data=1, bits=24), _frame(data=2, bits=24)]
    slots = marquee.plan(frames, "capture", copies=2)
    assert [s.frame.data for s in slots] == [1, 1, 2, 2]
    assert [s.copy for s in slots] == [1, 2, 1, 2]


def test_plan_rejects_unknown_order():
    with pytest.raises(ValueError, match="order must be"):
        marquee.plan([_frame()], "sideways")


def test_plan_clamps_copies_to_one():
    assert len(marquee.plan([_frame()], "capture", copies=0)) == 1


# -- timing -----------------------------------------------------------------

def test_clamp_gap_bounds():
    assert marquee.clamp_gap(-50) == 0
    assert marquee.clamp_gap(50) == 50
    assert marquee.clamp_gap(99_999) == marquee.GAP_MAX_MS
    assert marquee.clamp_gap(None) == 0


def test_timing_reports_both_on_air_and_dead_time():
    slots = marquee.plan([_frame()], "capture", copies=2)
    budget = marquee.timing(slots, gap_ms=10)
    assert budget["frames"] == 1
    assert budget["copies"] == 2
    assert budget["dead_ms"] == 20
    assert budget["total_ms"] == pytest.approx(budget["frame_ms"] + 20)


def test_check_headroom_flags_mixed_protocols_and_te():
    report = marquee.check_headroom([_frame(te=900),
                                     _frame(protocol="CAME", te=320,
                                            data=0x5A5, bits=12)])
    assert report["verdict"] == "loose"
    assert report["widest_guard_ms"] > 20
    assert any("protocol" in n for n in report["notes"])
    assert any("TE" in n for n in report["notes"])


def test_check_headroom_calls_a_single_frame_tight():
    assert marquee.check_headroom([_frame()])["verdict"] == "tight"


# -- .sub flattening and plan files -----------------------------------------

def test_to_sub_produces_playable_raw():
    slots = marquee.plan([_frame()], "capture", copies=2)
    sub = marquee.to_sub(slots, gap_ms=5)
    assert sub.protocol == "RAW"
    assert sub.frequency == 433_920_000
    # 50 levels per frame (2 per bit + closing pair) plus one gap each
    assert len(sub.raw_data) == 2 * (24 * 2 + 2) + 2


def test_to_sub_round_trips_through_the_engine():
    from omni.rf.subfile import raw_durations_to_levels
    slots = marquee.plan([_frame()], "capture", copies=1)
    sub = marquee.to_sub(slots)
    assert raw_durations_to_levels(sub.raw_data) == _frame().levels()


def test_save_and_load_frames_round_trip(tmp_path):
    path = tmp_path / "plan.marquee"
    original = [_frame(), _frame(protocol="CAME", data=0x5A5, bits=12, te=320)]
    marquee.save_frames(original, str(path))
    loaded = marquee.load_frames_file(str(path))
    assert [f.data for f in loaded] == [f.data for f in original]
    assert [f.protocol for f in loaded] == [f.protocol for f in original]
    assert loaded[1].te == 320


def test_load_frames_reads_specs_and_files(tmp_path):
    sub = SubFile()
    sub.protocol, sub.bit, sub.key, sub.te = "Princeton", 24, 0x11, 390
    sub.frequency = 433_920_000
    sub.save(str(tmp_path / "cap.sub"))
    frames = marquee.load_frames([str(tmp_path / "cap.sub"),
                                  "CAME:12:5A5"])
    assert len(frames) == 2


def test_load_frames_reads_a_directory(tmp_path):
    sub = SubFile()
    sub.protocol, sub.bit, sub.key = "Princeton", 24, 0x11
    sub.frequency = 433_920_000
    sub.save(str(tmp_path / "a.sub"))
    assert len(marquee.load_frames(str(tmp_path))) == 1


def test_load_frames_on_raw_capture_errors(tmp_path):
    raw = SubFile()
    raw.protocol = "RAW"
    raw.raw_data = [400, -800]
    raw.save(str(tmp_path / "raw.sub"))
    with pytest.raises(ValueError, match="RAW capture"):
        marquee.load_frames(str(tmp_path / "raw.sub"))


def test_load_frames_without_arguments_errors():
    with pytest.raises(ValueError, match="no frames"):
        marquee.load_frames([])


def test_load_frames_glob_miss_errors():
    with pytest.raises(FileNotFoundError, match="no match"):
        marquee.load_frames(["nothing-here-*.sub"])


# -- module wiring ----------------------------------------------------------

def test_inject_module_fires_and_saves(monkeypatch):
    mod = inject.Inject(FILES="Princeton:24:ABC123", COPIES="2")
    result = mod.execute()
    assert result["sent"] == 1
    assert result["frames"] == 1
    assert result["copies"] == 2
    assert result["demo"] is True
    assert result["saved"].endswith(".sub")
    assert result["verdict"] == "tight"


def test_inject_module_honours_overrides():
    mod = inject.Inject(FILES="Princeton:24:ABC123", FREQ="315000000",
                        PRESET="AM270", SAVE="false")
    result = mod.execute()
    assert result["saved"] == ""


def test_rolljam_module_exposes_duty_cycle_options():
    names = {o.name for o in rolljam.RollJam.OPTIONS}
    assert {"JAM_MS", "LISTEN_MS", "SECONDS"} <= names


def test_rolljam_without_capture_reports_zero():
    result = rolljam.RollJam(FREQ="433920000", SECONDS="1").execute()
    assert result["captured"] == 0
    assert result["sent"] == 0
    assert result["cycles"] >= 1
