"""Multi-band fob survey: band plans, capture conversion, ranking, frame maths.

No radio: the planning and scoring are pure functions, the capture is a stub
that looks like a decoder result, and ``car.hunt`` is run in demo mode so the
hop loop itself is exercised.
"""

import pytest

from omni.car import survey
from omni.car.modules.frame import Frame
from omni.car.modules.hunt import Hunt

F_315 = 315_000_000
F_433 = 433_920_000


class Press:
    """Stands in for a decoder result (same fields the RX engine emits)."""

    protocol_name = "Princeton"
    data = 0xABCDEF
    data_count_bit = 24
    te = 390


def test_band_frequencies_walk_the_regions():
    assert survey.band_frequencies("all") == [F_315, F_433,
                                              434_420_000, 868_350_000]
    assert survey.band_frequencies("eu") == [F_433]
    assert survey.band_frequencies("433.92,868.35") == [F_433, 868_350_000]
    with pytest.raises(ValueError):
        survey.band_frequencies("mars")


def test_hop_plan_clips_to_the_requested_window():
    plan = survey.hop_plan([F_315, F_433], 1.0, 250)
    assert [freq for freq, _ in plan] == [F_315, F_433, F_315, F_433]
    assert sum(dwell for _, dwell in plan) == pytest.approx(1.0)
    short = survey.hop_plan([F_433], 0.3, 200)
    assert sum(dwell for _, dwell in short) == pytest.approx(0.3)
    with pytest.raises(ValueError):
        survey.hop_plan([], 1.0)


def test_a_press_becomes_a_sub_the_rest_of_the_trade_understands():
    sub = survey.sub_from_press(Press(), F_433, "AM650")
    assert sub is not None
    assert (sub.protocol, sub.bit, sub.frequency) == ("Princeton", 24, F_433)
    assert sub.key == 0xABCDEF and sub.guard_time == 30


def test_short_decodes_are_not_remotes():
    class Short(Press):
        data_count_bit = 8

    assert survey.sub_from_press(Short(), F_433) is None
    assert survey.sub_from_press(None, F_433) is None


def test_scoring_prefers_a_recovered_manufacturer_key():
    known = survey.score({"manufacturer": "VW", "counter": 12})
    button = survey.score({"button": 2})
    raw = survey.score({"raw": True})
    assert known > button > raw
    assert known == 110


def test_rank_puts_the_attackable_capture_first():
    ranked = survey.rank([
        {"frequency": F_433, "raw": True},
        {"frequency": F_315, "manufacturer": "Ford", "counter": 9},
        {"frequency": 868_350_000, "button": 1},
    ])
    assert ranked[0]["frequency"] == F_315 and ranked[0]["score"] == 110
    assert ranked[-1]["frequency"] == F_433
    assert [row[0] for row in survey.rows(ranked)] == ["315.000", "868.350",
                                                       "433.920"]


def test_frame_module_decodes_a_split_without_a_key():
    fix = (0x2 << 28) | 0x1234          # button 2, serial 0x1234
    hop = 0x12345678
    report = Frame(**{"fix": hex(fix), "hop": hex(hop)}).run()
    assert report["button"] == 2 and report["serial"] == 0x1234
    assert report["fix"] == f"0x{fix:08X}"
    assert report["chain"] == []        # no manufacturer key for this frame


def test_frame_module_needs_a_capture_or_the_two_halves():
    with pytest.raises(ValueError):
        Frame(**{"fix": "0x0", "hop": "0x0"}).run()


def test_hunt_runs_the_hop_loop_in_demo_mode():
    report = Hunt(**{"seconds": "1", "region": "eu", "dwell_ms": "200",
                     "report": "false", "save": "false"}).run()
    assert report["demo"] is True
    assert report["presses"] == 0        # a mock radio hears nothing
    assert report["hops"] >= 5           # the window has a 2s floor


def test_car_modules_are_registered():
    from omni.core.module import registry

    names = {module.NAME for module in registry.all("car")}
    assert {"car.hunt", "car.frame"} <= names
