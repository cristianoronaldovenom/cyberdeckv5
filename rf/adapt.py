"""Closed-loop CC1101 front-end control: automatic frequency and gain trim.

:mod:`omni.rf.tuner` calibrates *once*, against a carrier you have already
found. This keeps adjusting while the radio listens:

* it tracks the noise floor, so "is anything there" stays a measured answer;
* when a carrier appears it walks the frequency trim towards the actual peak
  (AFC) — a cheap antenna and a long cable shift resonance away from nominal;
* it picks the gain step that is loudest *without* clipping (AGC), and turns
  the LNA on when maximum gain still is not enough.

Every move has to beat the current setting by ``HYSTERESIS_DB``, so the radio
settles instead of chattering between two adjacent values. Only knobs that
leave the timing registers alone are touched — ``FREQ2/1/0`` through
:meth:`~omni.rf.cc1101.CC1101.set_frequency`, ``AGCCTRL2`` (front-end gain)
and ``AGCCTRL0`` (LNA/AGC) — so a preset stays decodable while it runs.
"""

from __future__ import annotations

import time

from omni.rf.tuner import AGCCTRL0, AGCCTRL2, GAINS, LNAS

__all__ = ["Adjustment", "AutoFront", "noise_floor", "gain_label", "lna_label",
           "MARGIN_DB", "HYSTERESIS_DB", "SATURATION_DBM"]

#: dB over the tracked floor before a signal counts as "there"
MARGIN_DB = 4.0
#: dB a candidate must win by before the radio is retuned
HYSTERESIS_DB = 2.0
#: above this the front end is compressing and wants attenuation
SATURATION_DBM = -22.0


def noise_floor(samples: list[float]) -> float:
    """Median of a sample set — one carrier in the window does not move it."""
    if not samples:
        return -200.0
    ordered = sorted(samples)
    return ordered[len(ordered) // 2]


def gain_label(value: int) -> str:
    return next((name for reg, name in GAINS if reg == value), str(value))


def lna_label(value: int) -> str:
    return next((name for reg, name in LNAS if reg == value), str(value))


class Adjustment:
    """One front-end move, with the measurement that justified it."""

    __slots__ = ("kind", "before", "after", "rssi", "reason", "at")

    def __init__(self, kind: str, before: str, after: str, rssi: float,
                 reason: str, at: float | None = None):
        self.kind, self.before, self.after = kind, before, after
        self.rssi, self.reason = rssi, reason
        self.at = time.time() if at is None else at

    def row(self) -> list[str]:
        return [self.kind, f"{self.before} -> {self.after}",
                f"{self.rssi:.1f}", self.reason]

    def as_dict(self) -> dict:
        return {"kind": self.kind, "before": self.before, "after": self.after,
                "rssi": round(self.rssi, 1), "reason": self.reason,
                "at": round(self.at, 3)}


class AutoFront:
    """Keeps a CC1101 on the carrier: AFC inside the span, AGC on RSSI."""

    def __init__(self, radio, freq: int, span_khz: int = 120,
                 step_khz: int | None = None,
                 hysteresis: float = HYSTERESIS_DB,
                 margin: float = MARGIN_DB,
                 saturation: float = SATURATION_DBM,
                 dwell: int = 3, pause: float = 0.0):
        self.radio = radio
        self.freq = int(freq)
        self.span_khz = max(0, int(span_khz))
        self.step_khz = max(1, int(step_khz or max(5, self.span_khz // 4)))
        self.hysteresis = float(hysteresis)
        self.margin = float(margin)
        self.saturation = float(saturation)
        self.dwell = max(1, int(dwell))
        self.pause = max(0.0, float(pause))
        self.offset_khz = 0
        self.gain = GAINS[0][0]           # stock: maximum gain
        self.lna = LNAS[0][0]             # stock: LNA on
        self.stock_offset = self.offset_khz
        self.stock_gain = self.gain
        self.stock_lna = self.lna
        self.floor = -200.0
        self.rssi = -200.0
        self.cycles = 0
        self.adjustments: list[Adjustment] = []
        self._quiet = 0                    # quiet samples behind the floor

    # -- hardware ----------------------------------------------------------
    def program(self) -> None:
        """Write the current setting to the chip and listen on it."""
        self.radio.spi.wreg(AGCCTRL2, self.gain)
        self.radio.spi.wreg(AGCCTRL0, self.lna)
        self.radio.set_frequency(self.freq + self.offset_khz * 1000)
        self.radio.start_rx()

    def sample(self) -> float:
        """Best of ``DWELL`` RSSI reads at the current setting."""
        best = -200.0
        self.radio.start_rx()
        for _ in range(self.dwell):
            try:
                best = max(best, float(self.radio.get_rssi_dbm()))
            except Exception:                # noqa: BLE001 - mock noise
                continue
            if self.pause:
                time.sleep(self.pause)
        return best

    def _probe(self, offset_khz: int, gain: int, lna: int) -> float:
        """Measure a candidate setting (``program`` puts the winner back)."""
        self.radio.spi.wreg(AGCCTRL2, gain)
        self.radio.spi.wreg(AGCCTRL0, lna)
        self.radio.set_frequency(self.freq + offset_khz * 1000)
        return self.sample()

    def _clamp(self, offset_khz: int) -> int:
        return max(-self.span_khz, min(self.span_khz, offset_khz))

    # -- the loop ----------------------------------------------------------
    def step(self) -> list[Adjustment]:
        """One pass: measure, then at most one AFC and one AGC move."""
        self.cycles += 1
        self.program()
        level = self.sample()
        self.rssi = level
        if self.floor <= -200.0:                 # first pass: this *is* the floor
            self.floor, self._quiet = level, 1
            return []
        if level < self.floor + self.margin:
            # quiet window: the floor is the running average of quiet samples,
            # so a carrier cannot drag it up and hide itself
            self.floor = self.floor * 0.6 + level * 0.4
            self._quiet += 1
            return []
        made: list[Adjustment] = []
        for move in (self.tune_frequency(), self.tune_gain(self.rssi)):
            if move is not None:
                made.append(move)
        self.program()                           # the chip follows the decision
        self.adjustments += made
        return made

    def tune_frequency(self) -> Adjustment | None:
        """Hill-climb the trim towards the real peak (AFC)."""
        if self.span_khz <= 0:
            return None
        best_offset, best_level = self.offset_khz, self.rssi
        for delta in (-self.step_khz, self.step_khz):
            offset = self._clamp(self.offset_khz + delta)
            if offset == self.offset_khz:
                continue
            level = self._probe(offset, self.gain, self.lna)
            if level > best_level + self.hysteresis:
                best_offset, best_level = offset, level
        self.program()
        if best_offset == self.offset_khz:
            return None
        move = Adjustment("afc", f"{self.offset_khz:+d}kHz",
                          f"{best_offset:+d}kHz", best_level,
                          f"{best_level - self.rssi:+.1f} dB on the trim")
        self.offset_khz, self.rssi = best_offset, best_level
        return move

    def tune_gain(self, level: float) -> Adjustment | None:
        """Pick the gain step that is loud without clipping (AGC)."""
        if level >= self.saturation:            # front end compressing
            louder = [reg for reg, _ in GAINS if reg > self.gain]
            if not louder:
                return None
            target = min(louder)
            measured = self._probe(self.offset_khz, target, self.lna)
            self.program()
            before = gain_label(self.gain)
            self.gain, self.rssi = target, measured
            return Adjustment("gain", before, gain_label(target), measured,
                              f"{level:.0f} dBm is clipping — attenuate")

        quieter = [reg for reg, _ in GAINS if reg < self.gain]
        if quieter:
            target = max(quieter)
            measured = self._probe(self.offset_khz, target, self.lna)
            self.program()
            if measured <= level + self.hysteresis:
                return None
            before = gain_label(self.gain)
            self.gain, self.rssi = target, measured
            return Adjustment("gain", before, gain_label(target), measured,
                              f"{measured - level:+.1f} dB more signal")
        if self.lna == LNAS[0][0]:              # already at maximum gain
            return None
        target = LNAS[0][0]
        measured = self._probe(self.offset_khz, self.gain, target)
        self.program()
        if measured <= level + self.hysteresis:
            return None
        before = lna_label(self.lna)
        self.lna, self.rssi = target, measured
        return Adjustment("lna", before, lna_label(target), measured,
                          f"gain is maxed — {measured - level:+.1f} dB from LNA")

    # -- books -------------------------------------------------------------
    def restore(self) -> None:
        """Put the stock front-end setting back."""
        self.offset_khz = self.stock_offset
        self.gain, self.lna = self.stock_gain, self.stock_lna
        self.program()

    def state(self) -> dict:
        """What the controller currently holds, ready for a report."""
        return {"freq": self.freq, "offset_khz": self.offset_khz,
                "gain": gain_label(self.gain), "gain_reg": self.gain,
                "lna": lna_label(self.lna), "lna_reg": self.lna,
                "floor": round(self.floor, 1), "rssi": round(self.rssi, 1),
                "cycles": self.cycles, "moves": len(self.adjustments),
                "span_khz": self.span_khz}
