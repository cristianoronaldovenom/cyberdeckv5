"""rf.tune module — thin wrapper over the omni.rf.tuner calibration engine."""

from __future__ import annotations

import os

from omni.core import config, console
from omni.core.module import Option
from omni.rf.modules._base import RfModule
from omni.rf.tuner import AGCCTRL0, AGCCTRL2, GAINS, LNAS, TunePoint

__all__ = ["Tune"]


class Tune(RfModule):
    NAME = "rf.tune"
    DESCRIPTION = "Calibrate antenna gain, LNA and frequency trim on measured RSSI"
    OPTIONS = (Option("FREQ", "carrier to tune on", "", required=True),
               Option("PRESET", "modem preset", "AM650"),
               Option("SPAN_KHZ", "trim range either side of FREQ", "120"),
               Option("STEPS", "trim steps across the span", "9"),
               Option("DWELL", "RSSI samples per candidate", "5"),
               Option("APPLY", "leave the best setting programmed", "true",
                      choices=("true", "false")),
               Option("SAVE", "write the winning trim to the loot dir", "true",
                      choices=("true", "false")))

    def points(self) -> list[TunePoint]:
        span = max(0, self.get_int("SPAN_KHZ", 120))
        steps = max(1, self.get_int("STEPS", 9))
        if steps == 1:
            offsets = [0]
        else:
            offsets = sorted({round(-span + (2 * span) * i / (steps - 1))
                              for i in range(steps)})
        return [TunePoint(int(off), gain, lna)
                for off in offsets for gain, _ in GAINS for lna, _ in LNAS]

    def execute(self) -> dict:
        freq = self.freq()
        preset = self.preset()
        rig = self.rig()
        points = self.points()
        rows: list[list[str]] = []
        try:
            rig.radio.load_preset(preset)
            rig.radio.set_frequency(freq)
            rig.radio.start_rx()
            dwell = max(1, self.get_int("DWELL", 5))
            console.info(f"probing {len(points)} front-end settings on "
                         f"{freq / 1e6:.3f} MHz — keep the antenna still")
            for point in points:
                rig.radio.spi.wreg(AGCCTRL2, point.gain)
                rig.radio.spi.wreg(AGCCTRL0, point.lna)
                point.sample(rig.radio, freq, dwell, 0.02)
                rows.append([point.label(), f"{point.score:.1f}"])
            rig.radio.idle()

            points.sort(key=lambda p: (-p.score, abs(p.offset_khz)))
            best = points[0]
            baseline = next((p for p in points
                             if p.offset_khz == 0 and p.gain == 0x00
                             and p.lna == 0x00), None)
            gain_db = (best.score - baseline.score) if baseline else 0.0
            console.table(["setting", "best dBm"], rows[:12])
            console.ok(f"best: {best.label()} at {best.score:.1f} dBm "
                       f"({gain_db:+.1f} dB vs stock)")

            if self.get_bool("APPLY", True):
                rig.radio.load_preset(preset)
                rig.radio.spi.wreg(AGCCTRL2, best.gain)
                rig.radio.spi.wreg(AGCCTRL0, best.lna)
                rig.radio.set_frequency(freq + best.offset_khz * 1000)
                console.info("winning trim left programmed on the radio")

            path = ""
            if self.get_bool("SAVE", True):
                path = os.path.join(config.output_dir("rf/tune"),
                                    f"trim_{freq}.txt")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "a", encoding="utf-8", newline="\n") as fh:
                    fh.write(f"freq={freq}\toffset_khz={best.offset_khz}\t"
                             f"agcctrl2={best.gain:#04x}\t"
                             f"agcctrl0={best.lna:#04x}\t"
                             f"rssi={best.score:.1f}\tgain_db={gain_db:+.1f}\n")
            return {"best": best.label(), "offset_khz": best.offset_khz,
                    "rssi": round(best.score, 1), "gain_db": round(gain_db, 1),
                    "tested": len(rows), "saved": path, "demo": rig.demo}
        finally:
            try:
                rig.radio.idle()
            finally:
                rig.close()
