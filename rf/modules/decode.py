"""Raw decoding of a captured frame and jamming (carrier hold)."""

from __future__ import annotations

import os
import time

from omni.core import console
from omni.core.module import Option
from omni.core.util import parse_int
from omni.rf import keeloq_crypto as kq
from omni.rf.modules._base import RfModule
from omni.rf.subfile import SubFile

__all__ = ["Decode", "Jam"]


class Decode(RfModule):
    NAME = "rf.decode"
    DESCRIPTION = "Decode a .sub or hex frame into protocol fields"
    OPTIONS = (Option("SUB", ".sub file to decode"),
               Option("HEX", "raw 64-bit KeeLoq frame in hex"),
               Option("KEYSTORE", "manufacturer keystore path"))

    def execute(self) -> dict:
        if self.get("HEX"):
            frame = parse_int(self.get("HEX"))
            fix, hop = kq.split_frame(frame)
            return self._report_fixhop(fix, hop)
        if not self.get("SUB"):
            raise ValueError("need SUB or HEX")
        from omni.car import analysis
        sub = SubFile.load(os.path.expanduser(self.get("SUB")))
        if sub.is_raw:
            console.warn("RAW file: no protocol fields, use rf.replay instead")
            return {"raw": True, "samples": len(sub.raw_data)}
        fix, hop = kq.split_frame(sub.key)
        if sub.protocol != "KeeLoq":
            console.kv([("protocol", sub.protocol), ("bits", sub.bit),
                        ("data", f"0x{sub.key:X}"), ("te", sub.te)])
            return {"protocol": sub.protocol, "data": sub.key,
                    "bits": sub.bit, "te": sub.te}
        store = analysis.load_keystore(self.get("KEYSTORE") or None)
        out = analysis.analyze_frame(fix, hop, store)
        self._print(out)
        return out

    def _report_fixhop(self, fix: int, hop: int) -> dict:
        from omni.car import analysis
        store = analysis.load_keystore(self.get("KEYSTORE") or None)
        out = analysis.analyze_frame(fix, hop, store)
        self._print(out)
        return out

    def _print(self, out: dict) -> None:
        btn, serial = kq.parse_fix(int(out["fix"], 16))
        console.kv([("serial", f"0x{serial:07X}"), ("button", f"0x{btn:X}"),
                    ("counter", out["counter"]),
                    ("manufacturer", out["manufacturer"])])
        console.info(out["verdict"])


class Jam(RfModule):
    NAME = "rf.jam"
    DESCRIPTION = "Hold the carrier to jam a band (dead-time / RX denial)"
    OPTIONS = (Option("FREQ", "carrier in Hz", "", required=True),
               Option("PRESET", "modem preset", "AM650"),
               Option("SECONDS", "hold time", "30"))

    def execute(self) -> dict:
        rig = self.rig()
        try:
            rig.radio.load_preset(self.preset())
            rig.radio.set_frequency(self.freq())
            started = time.time()
            rig.radio.start_tx()
            console.info(f"carrier on {self.freq() / 1e6:.3f} MHz — "
                         f"{self.get_int('SECONDS', 30)}s")
            try:
                time.sleep(max(1, self.get_int("SECONDS", 30)))
            except KeyboardInterrupt:
                pass
            finally:
                rig.radio.idle()
            return {"seconds": round(time.time() - started, 1),
                    "freq": self.freq(), "demo": rig.demo}
        finally:
            rig.close()
