"""Wideband hunting: sweep the regional bands, lock onto activity, decode.

`rf.sniff` needs to be told a frequency. This *finds* them the way an Unleashed
sweep does — but with the CC1101's own RSSI as the detector, so it works on a
bare Pi with no SDR:

1. sweep every frequency in the band plan, dwelling briefly and scoring energy;
2. rank the discoveries and park on the hottest ones;
3. run the full decode stack while parked, then re-sweep so a fob that moves
   band is not lost.

This is the difference between "listening on 433.92" and "listening for
anything within range".
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.rf.modules._base import RfModule
from omni.rf.subfile import SubFile

__all__ = ["Hunt", "BANDS", "band_plan", "find_peaks"]

#: named regional bands -> tuples of (low, high, step) in Hz
BANDS = {
    "eu": ((433_050_000, 434_790_000, 300_000),
           (868_000_000, 868_600_000, 200_000)),
    "us": ((314_900_000, 315_000_000, 100_000),
           (433_050_000, 434_790_000, 300_000),
           (915_000_000, 916_000_000, 250_000)),
    "world": ((300_000_000, 348_000_000, 400_000),
              (387_000_000, 464_000_000, 400_000),
              (779_000_000, 928_000_000, 400_000)),
    "433": ((433_050_000, 434_790_000, 200_000),),
    "315": ((314_900_000, 315_000_000, 50_000),),
    "868": ((868_000_000, 868_600_000, 100_000),),
    "915": ((915_000_000, 916_000_000, 100_000),),
}

#: energy above this many dB over the floor counts as a hit
HIT_MARGIN_DB = 4.0


def band_plan(plan: str) -> list[int]:
    """Expand a named band plan into a frequency list."""
    if plan not in BANDS:
        raise ValueError(f"unknown plan {plan!r} — use one of "
                         f"{', '.join(sorted(BANDS))}")
    freqs: list[int] = []
    for low, high, step in BANDS[plan]:
        current = low
        while current <= high:
            freqs.append(current)
            current += step
    return freqs


def find_peaks(samples: dict[int, float], margin: float = HIT_MARGIN_DB,
               limit: int = 8) -> list[tuple[int, float]]:
    """Frequencies standing `margin` dB above the median noise floor."""
    if not samples:
        return []
    values = sorted(samples.values())
    floor = values[len(values) // 2]
    hits = [(f, level) for f, level in samples.items()
            if level >= floor + margin]
    hits.sort(key=lambda pair: -pair[1])
    return hits[:limit]


class Hunt(RfModule):
    NAME = "rf.hunt"
    DESCRIPTION = "Sweep the band plan, lock onto the hottest signal and decode"
    OPTIONS = (Option("PLAN", "band plan to sweep", "eu",
                      choices=tuple(sorted(BANDS))),
               Option("PRESET", "modem preset", "AM650"),
               Option("SECONDS", "total hunting time", "60"),
               Option("DWELL_MS", "listen time per sweep step", "12"),
               Option("LOCK_SECONDS", "time parked on a discovery", "8"),
               Option("MARGIN", "dB over the noise floor to count as a hit",
                      "4"),
               Option("OUT", "output directory"))

    def _sweep(self, radio, freqs: list[int], dwell_ms: int) -> dict[int, float]:
        """Passive energy sweep; returns {freq: best dBm}."""
        found: dict[int, float] = {}
        for freq in freqs:
            try:
                radio.set_frequency(freq)
                radio.start_rx()
                time.sleep(dwell_ms / 1000.0)
                level = radio.get_rssi_dbm()
            except Exception:                   # noqa: BLE001 - mock noise
                continue
            found[freq] = max(found.get(freq, -200.0), level)
        return found

    def execute(self) -> dict:
        freqs = band_plan(self.get("PLAN"))
        preset = self.preset()
        outdir = os.path.expanduser(self.get("OUT") or
                                    config.output_dir("rf/hunt"))
        os.makedirs(outdir, exist_ok=True)
        rig = self.rig()
        captured: list[str] = []
        locked: list[int] = []
        rx = rig.rx()
        margin = float(self.get("MARGIN") or HIT_MARGIN_DB)

        def _on_found(result) -> None:
            freq = int(rig.radio.frequency)
            path = os.path.join(outdir, f"{freq // 1000}_"
                                        f"{result.protocol_name}_"
                                        f"{time.strftime('%H%M%S')}.sub")
            sub = SubFile()
            sub.frequency = freq
            sub.preset_name = preset.short
            sub.protocol = result.protocol_name
            sub.bit = result.data_count_bit
            sub.key = result.data
            sub.te = int(result.te or 400)
            sub.manufacture = (result.manufacture_name
                               if result.manufacture_name != "Unknown" else None)
            sub.seed = result.seed or 0
            sub.save(path)
            captured.append(path)
            console.ok(f"{result.protocol_name} on {freq / 1e6:.3f} MHz -> "
                       f"{os.path.basename(path)}")

        dwell = max(4, self.get_int("DWELL_MS", 12))
        lock_seconds = max(1, self.get_int("LOCK_SECONDS", 8))
        deadline = time.time() + max(2, self.get_int("SECONDS", 60))
        cycles = 0
        try:
            rx.on_found(_on_found)
            while time.time() < deadline:
                rig.radio.load_preset(preset)
                peaks = find_peaks(self._sweep(rig.radio, freqs, dwell), margin)
                cycles += 1
                if not peaks:
                    console.info(f"sweep {cycles}: quiet across "
                                 f"{len(freqs)} frequenc(ies)")
                    continue
                console.ok(f"sweep {cycles}: {len(peaks)} peak(s), hottest "
                           f"{peaks[0][0] / 1e6:.3f} MHz @ {peaks[0][1]:.1f} dBm")
                for freq, _level in peaks:
                    if time.time() >= deadline:
                        break
                    rx.start(preset, freq, on_found=_on_found)
                    if freq not in locked:
                        locked.append(freq)
                    console.info(f"parked on {freq / 1e6:.3f} MHz for "
                                 f"{lock_seconds}s")
                    end = min(deadline, time.time() + lock_seconds)
                    while time.time() < end:
                        time.sleep(0.2)
                    rx.stop()
            console.ok(f"{len(captured)} frame(s) from {len(locked)} "
                       f"band(s) across {cycles} sweep(s) -> {outdir}")
            return {"captured": captured, "locked": sorted(locked),
                    "sweeps": cycles, "dir": outdir, "demo": rig.demo}
        finally:
            try:
                rx.stop()
            finally:
                rig.close()
