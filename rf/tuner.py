"""Adaptive CC1101 front-end tuning: gain, AGC and frequency trim.

The CC1101 has a *measured* front end, not a fixed one. A preset is a starting
point; the radio still has to be trimmed to the actual antenna and band or the
receive floor swamps genuine frames. This calibrates the front end the way SDR
operators do — sweep, measure RSSI, keep the best — but on the chip's own knobs:

* **frequency trim** in ±`SPAN_KHZ` steps, because a cheap antenna and a long
  cable shift resonance far from nominal;
* **front-end gain** (``AGCCTRL2``) in legal steps;
* **low-noise amplifier** (``AGCCTRL0``) on/off.

Each candidate is sampled `DWELL` times and scored; the winner is left
programmed and reported. Timing registers are untouched, so decoding stays
valid.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.rf.modules._base import RfModule

__all__ = ["TunePoint", "AGCCTRL2", "AGCCTRL0", "GAINS", "LNAS", "score_rssi"]

#: AGCCTRL2 bit field: 0 = max gain, 7 = max attenuation.
AGCCTRL2 = 0x17
#: AGCCTRL0: low-noise amplifier / AGC behaviour.
AGCCTRL0 = 0x1B

#: gain steps to try (register value, human label)
GAINS = ((0x00, "max"), (0x02, "high"), (0x04, "mid"), (0x07, "low"))
#: LNA settings: 0 = LNA enabled and AGC free, 3 = LNA off
LNAS = ((0x00, "lna-on"), (0x03, "lna-off"))


def score_rssi(samples: list[float]) -> tuple[float, float, float]:
    """(best, mean, spread) for a sample set — best favours a clear signal."""
    if not samples:
        return -200.0, -200.0, 0.0
    ordered = sorted(samples)
    return ordered[-1], sum(samples) / len(samples), ordered[-1] - ordered[0]


class TunePoint:
    """One candidate front-end setting plus its measurements."""

    __slots__ = ("offset_khz", "gain", "lna", "samples", "score", "mean")

    def __init__(self, offset_khz: int, gain: int, lna: int):
        self.offset_khz = offset_khz
        self.gain = gain
        self.lna = lna
        self.samples: list[float] = []
        self.score = -200.0
        self.mean = -200.0

    def sample(self, radio, freq: int, dwell: int, pause: float) -> None:
        radio.set_frequency(freq + self.offset_khz * 1000)
        radio.start_rx()
        time.sleep(max(0.0, pause))
        for _ in range(max(1, dwell)):
            try:
                self.samples.append(radio.get_rssi_dbm())
            except Exception:                   # noqa: BLE001 - mock noise
                pass
            time.sleep(0.01)
        self.score, self.mean, _spread = score_rssi(self.samples)

    def label(self) -> str:
        gain = next((n for v, n in GAINS if v == self.gain), str(self.gain))
        lna = next((n for v, n in LNAS if v == self.lna), str(self.lna))
        return f"{self.offset_khz:+d}kHz {gain} {lna}"

