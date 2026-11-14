"""Antenna tuner + wideband hunt tests: sweeps, scoring, peak picking."""

import pytest

from omni.rf import tuner
from omni.rf.modules import hunt, tune as tune_mod


# -- RSSI scoring -----------------------------------------------------------

def test_score_rssi_rewards_the_best_sample():
    best, mean, spread = tuner.score_rssi([-90.0, -70.0, -80.0])
    assert best == -70.0
    assert mean == pytest.approx(-80.0)
    assert spread == pytest.approx(20.0)


def test_score_rssi_handles_no_samples():
    assert tuner.score_rssi([]) == (-200.0, -200.0, 0.0)


def test_tune_point_labels_are_readable():
    point = tuner.TunePoint(60, 0x00, 0x00)
    assert "max" in point.label() and "lna-on" in point.label()
    assert "+60kHz" in point.label()


# -- candidate space --------------------------------------------------------

def test_points_cover_offsets_and_gain_steps():
    mod = tune_mod.Tune(FREQ="433920000", SPAN_KHZ="60", STEPS="3")
    points = mod.points()
    # 3 offsets x 4 gains x 2 lna states
    assert len(points) == 24
    assert {p.offset_khz for p in points} == {-60, 0, 60}


def test_points_with_a_single_step_is_centre_only():
    points = tune_mod.Tune(FREQ="433920000", STEPS="1").points()
    assert {p.offset_khz for p in points} == {0}


def test_zero_span_stays_on_frequency():
    points = tune_mod.Tune(FREQ="433920000", SPAN_KHZ="0", STEPS="5").points()
    assert {p.offset_khz for p in points} == {0}


def test_tune_leaves_a_trim_file(monkeypatch):
    result = tune_mod.Tune(FREQ="433920000", STEPS="1").execute()
    assert result["saved"].endswith(".txt")
    assert result["tested"] == 8
    with open(result["saved"], "r", encoding="utf-8") as fh:
        assert "agcctrl2=" in fh.read()


def test_tune_reports_a_best_setting():
    result = tune_mod.Tune(FREQ="433920000", STEPS="1").execute()
    assert result["best"]
    assert "kHz" in result["best"]
    assert result["demo"] is True


# -- band plans -------------------------------------------------------------

def test_band_plan_expands_all_plans():
    for plan in hunt.BANDS:
        freqs = hunt.band_plan(plan)
        assert freqs and all(isinstance(f, int) for f in freqs)
        assert freqs == sorted(freqs)


def test_band_plan_rejects_unknown():
    with pytest.raises(ValueError, match="unknown plan"):
        hunt.band_plan("mars")


def test_band_plan_covers_the_known_ism_bands():
    for plan in ("433", "315", "868", "915"):
        assert hunt.band_plan(plan)


# -- peak detection ---------------------------------------------------------

def test_find_peaks_picks_signals_over_the_floor():
    samples = {f: -90.0 for f in range(10)}
    samples[5] = -60.0
    peaks = hunt.find_peaks(samples, margin=10)
    assert peaks and peaks[0][0] == 5


def test_find_peaks_is_silent_on_a_flat_floor():
    assert hunt.find_peaks({f: -80.0 for f in range(10)}, margin=4) == []


def test_find_peaks_sorts_hottest_first_and_limits():
    samples = {f: -80.0 for f in range(6)}
    samples[1], samples[2], samples[3] = -50.0, -70.0, -60.0
    peaks = hunt.find_peaks(samples, margin=1, limit=2)
    assert [p[0] for p in peaks] == [1, 3]


def test_find_peaks_on_empty_input():
    assert hunt.find_peaks({}) == []


# -- hunt wiring ------------------------------------------------------------

def test_hunt_sweeps_and_reports(monkeypatch):
    result = hunt.Hunt(PLAN="315", SECONDS="3", DWELL_MS="4",
                       LOCK_SECONDS="1").execute()
    assert result["sweeps"] >= 1
    assert isinstance(result["locked"], list)
    assert result["demo"] is True


def test_hunt_makes_its_output_dir():
    result = hunt.Hunt(PLAN="315", SECONDS="3", DWELL_MS="4",
                       LOCK_SECONDS="1").execute()
    import os
    assert os.path.isdir(result["dir"])
