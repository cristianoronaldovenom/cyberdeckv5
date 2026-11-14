"""Sniff and replay raw Sub-GHz traffic, and replay .sub files."""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.core.util import slug
from omni.rf.subfile import SubFile
from omni.rf.modules._base import RfModule

__all__ = ["Sniff", "Replay", "Send"]


class Sniff(RfModule):
    NAME = "rf.sniff"
    DESCRIPTION = "Listen on a frequency and record every decoded frame as .sub"
    OPTIONS = (Option("FREQ", "carrier in Hz"),
               Option("PRESET", "modem preset", "AM650"),
               Option("SECONDS", "listen time", "30"),
               Option("HOP", "comma-separated frequencies to hop"),
               Option("OUT", "output directory"))

    def execute(self) -> dict:
        from omni.rf.protocols import DecoderResult  # noqa: F401 - doc hint
        rig = self.rig()
        outdir = os.path.expanduser(self.get("OUT") or
                                    config.output_dir("rf/sniff"))
        os.makedirs(outdir, exist_ok=True)
        found: list[str] = []
        rx = rig.rx()

        def _on_found(result) -> None:
            path = os.path.join(outdir, slug(f"{self.freq()}_{result.protocol_name}")
                               + f"_{time.strftime('%H%M%S')}.sub")
            sub = SubFile()
            sub.frequency = self.freq()
            sub.preset_name = self.preset().name
            sub.protocol = result.protocol_name
            sub.bit = result.data_count_bit
            sub.key = result.data
            sub.te = int(result.te or 400)
            sub.manufacture = (result.manufacture_name
                               if result.manufacture_name != "Unknown" else None)
            sub.seed = result.seed or 0
            sub.save(path)
            found.append(path)
            console.ok(f"{result.protocol_name} captured -> {os.path.basename(path)}")
            if config.get_value("verbose"):
                for line in result.summary().splitlines():
                    console.debug(line)

        hops = [int(v) for v in self.get("HOP").replace(" ", "").split(",") if v]
        try:
            if hops:
                rx.start_hopping(self.preset(), hops, on_found=_on_found)
            else:
                rx.start(self.preset(), self.freq(), on_found=_on_found)
            console.info(f"listening for {self.get_int('SECONDS', 30)}s — Ctrl-C to stop")
            deadline = time.time() + max(1, self.get_int("SECONDS", 30))
            while time.time() < deadline:
                time.sleep(0.2)
        except KeyboardInterrupt:
            pass
        finally:
            rx.stop()
            rig.close()
        console.info(f"{len(found)} frame(s) in {outdir}")
        return {"captured": found, "dir": outdir, "demo": rig.demo}


class Replay(RfModule):
    NAME = "rf.replay"
    DESCRIPTION = "Transmit a .sub file (or every .sub in a directory)"
    OPTIONS = (Option("SUB", ".sub file or directory", "", required=True),
               Option("REPEAT", "transmissions per file"),
               Option("LIMIT", "max files from a directory", "25"))

    def execute(self) -> dict:
        target = os.path.expanduser(self.get("SUB"))
        if os.path.isdir(target):
            names = sorted(n for n in os.listdir(target) if n.endswith(".sub"))
            subs = [SubFile.load(os.path.join(target, n))
                    for n in names[:max(1, self.get_int("LIMIT", 25))]]
        elif os.path.exists(target):
            subs = [SubFile.load(target)]
        else:
            raise FileNotFoundError(f"no such .sub: {target}")
        repeat = self.get_int("REPEAT", int(config.get_value("rf.repeat", 3)))
        rig = self.rig()
        try:
            tx = rig.tx()
            sent = sum(tx.send_subfile(sub) for sub in subs for _ in range(repeat))
            console.ok(f"{sent} transmission(s) over {len(subs)} file(s)")
            return {"files": len(subs), "sent": sent, "demo": rig.demo}
        finally:
            rig.close()


class Send(RfModule):
    NAME = "rf.send"
    DESCRIPTION = "Send a raw hex frame at a frequency (Princeton/CAME style)"
    OPTIONS = (Option("FREQ", "carrier in Hz", "", required=True),
               Option("HEX", "frame in hex", "", required=True),
               Option("PROTOCOL", "protocol", "Princeton",
                      choices=("Princeton", "CAME", "Nice FLO")),
               Option("BITS", "frame bit length", ""),
               Option("PRESET", "modem preset", "AM650"),
               Option("REPEAT", "transmissions", "3"))

    def execute(self) -> dict:
        from omni.rf.protocols import CameEncoder, NiceFloEncoder, PrincetonEncoder
        encoders = {"Princeton": (PrincetonEncoder, 24, 390),
                    "CAME": (CameEncoder, 12, 320),
                    "Nice FLO": (NiceFloEncoder, 12, 500)}
        cls, default_bits, te = encoders[self.get("PROTOCOL")]
        bits = self.get_int("BITS", default_bits)
        data = int(self.get("HEX").replace(" ", ""), 16)
        if data >= (1 << bits):
            raise ValueError(f"0x{data:X} does not fit in {bits} bit")
        encoder = cls(data=data, data_count_bit=bits, te=te)
        rig = self.rig()
        try:
            sent = rig.tx().send(self.preset(), self.freq(),
                                 encoder.build_upload(),
                                 repeat=self.get_int("REPEAT", 3))
            console.ok(f"{sent} frame(s) sent (0x{data:0{max(1, bits // 4)}X})")
            return {"sent": sent, "data": data, "bits": bits, "demo": rig.demo}
        finally:
            rig.close()
