"""Marquee injection: fill the air with a pre-built, exactly-timed frame train."""

from __future__ import annotations

import os

from omni.core import config, console
from omni.core.module import Option
from omni.rf import marquee
from omni.rf.modules._base import RfModule

__all__ = ["Inject"]


class Inject(RfModule):
    NAME = "rf.inject"
    DESCRIPTION = "Re-synthesize captured frames and fire one tight timed train"
    OPTIONS = (Option("FILES", "specs / .sub / .marquee / directory / glob",
                      "", required=True),
               Option("COPIES", "back-to-back copies per frame (marquee burst)",
                      "3"),
               Option("GAP", "extra dead air between bursts, ms", "0"),
               Option("ORDER", "head-first fires the newest capture first",
                      "head-first", choices=marquee.ORDERS),
               Option("ROUNDS", "repeat the whole train N times", "1"),
               Option("FREQ", "override carrier for every frame"),
               Option("PRESET", "override modem preset for every frame"),
               Option("SAVE", "keep the flattened one-file .sub", "true",
                      choices=("true", "false")))

    def frames(self) -> list[marquee.Frame]:
        frames = marquee.load_frames(self.get("FILES"))
        freq, preset = self.get("FREQ"), self.get("PRESET")
        for frame in frames:
            if freq:
                frame.frequency = int(freq)
            if preset:
                frame.preset = preset
        return frames

    def execute(self) -> dict:
        frames = self.frames()
        slots = marquee.plan(frames, self.get("ORDER"),
                             self.get_int("COPIES", 3))
        gap = marquee.clamp_gap(self.get_int("GAP", 0))
        budget = marquee.timing(slots, gap)
        head = marquee.check_headroom(frames)
        console.table(["#", "proto", "frame", "te", "copy", "air"],
                      marquee.describe(slots, budget))
        if head["notes"]:
            for note in head["notes"]:
                console.warn(note)

        sub = marquee.to_sub(slots, gap)
        saved = ""
        if self.get_bool("SAVE", True):
            protos = sorted({s.frame.protocol for s in slots})
            tag = protos[0].replace(" ", "") if len(protos) == 1 else "multi"
            saved = os.path.join(
                config.output_dir("rf/inject"),
                f"marquee_{int(sub.frequency / 1000)}_{len(slots)}x{tag}.sub")
            sub.save(saved)

        rig = self.rig()
        rounds = max(1, self.get_int("ROUNDS", 1))
        try:
            tx = rig.tx()
            sent = 0
            for _ in range(rounds):
                sent += tx.send_subfile(sub)
        finally:
            rig.close()
        console.ok(f"{sent} burst(s) — {budget['total_ms']:.0f} ms of air "
                   f"for {budget['frames']} frame(s)")
        if saved:
            console.info(f"plan kept: {saved}")
        return {"sent": sent, "frames": budget["frames"],
                "copies": budget["copies"], "gap_ms": gap,
                "air_ms": budget["total_ms"], "saved": saved,
                "verdict": head["verdict"], "demo": rig.demo}
