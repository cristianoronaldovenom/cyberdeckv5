"""rf.auto — keep the CC1101 adjusted while it listens (live AFC + AGC).

``rf.tune`` answers "what is the best setting for this carrier", once, before
you know whether the carrier is even there. This one keeps adjusting while the
radio runs: it learns the noise floor, notices a signal, walks the frequency
trim onto the real peak and picks the gain step that is loudest without
clipping — with hysteresis, so it settles instead of chattering.

It reports every move and leaves the winner programmed, so ``rf.sniff`` or
``rf.hunt`` can carry on from a radio that is actually pointed at the signal.
"""

from __future__ import annotations

import json
import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.rf.adapt import AutoFront
from omni.rf.modules._base import RfModule

__all__ = ["Auto"]


class Auto(RfModule):
    NAME = "rf.auto"
    DESCRIPTION = "Continuously self-adjusting CC1101 front end (AFC + AGC)"
    OPTIONS = (Option("FREQ", "carrier to hold (default: rf.default_frequency)"),
               Option("PRESET", "modem preset", "AM650"),
               Option("SECONDS", "how long to keep adapting", "15"),
               Option("CYCLES", "stop after N passes (0 = run for SECONDS)",
                      "0"),
               Option("INTERVAL", "seconds between passes", "1"),
               Option("SPAN_KHZ", "AFC trim range either side", "120"),
               Option("HYSTERESIS", "dB a new setting must win by", "2"),
               Option("MARGIN", "dB over the floor that counts as a signal", "4"),
               Option("APPLY", "leave the winning setting programmed", "true",
                      choices=("true", "false")),
               Option("SAVE", "write the trim to the loot dir", "true",
                      choices=("true", "false")))

    def execute(self) -> dict:
        freq = self.freq()
        preset = self.preset()
        rig = self.rig()
        front = AutoFront(rig.radio, freq,
                          span_khz=self.get_int("SPAN_KHZ", 120),
                          hysteresis=float(self.get("HYSTERESIS") or 2.0),
                          margin=float(self.get("MARGIN") or 4.0),
                          dwell=3, pause=0.01)
        interval = max(0.05, float(self.get("INTERVAL") or 1.0))
        deadline = time.time() + max(1, self.get_int("SECONDS", 15))
        passes = max(0, self.get_int("CYCLES", 0))
        try:
            rig.radio.load_preset(preset)
            console.info(f"auto-adjusting {freq / 1e6:.3f} MHz "
                         f"({preset.short}) — span ±{front.span_khz} kHz")
            while time.time() < deadline and (not passes
                                              or front.cycles < passes):
                for move in front.step():
                    console.ok(f"{move.kind:<4} {move.before} -> {move.after}"
                               f"  {move.rssi:.1f} dBm  ({move.reason})")
                time.sleep(interval)
        finally:
            try:
                if self.get_bool("APPLY", True):
                    front.program()
                else:
                    front.restore()
            finally:
                try:
                    rig.radio.idle()
                finally:
                    rig.close()

        state = front.state()
        console.table(["adjustment", "from -> to", "dBm", "why"],
                      [move.row() for move in front.adjustments] or
                      [["none", "stock", f"{state['rssi']:.1f}",
                        "no signal above the floor"]])
        console.ok(f"settled on {state['offset_khz']:+d} kHz, gain "
                   f"{state['gain']}, {state['lna']} "
                   f"(floor {state['floor']:.0f} dBm) after {state['cycles']} "
                   f"pass(es)")

        path = ""
        if self.get_bool("SAVE", True):
            folder = config.output_dir("rf/auto")
            path = os.path.join(folder, f"trim_{freq}.json")
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                json.dump({"state": state,
                           "moves": [m.as_dict() for m in front.adjustments]},
                          fh, indent=2)
                fh.write("\n")
        return {**state, "saved": path, "demo": rig.demo}
