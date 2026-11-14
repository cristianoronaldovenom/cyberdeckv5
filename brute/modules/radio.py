"""Radio-side brute force: symbol/PIN space sprayed over the CC1101."""

from __future__ import annotations

from omni.brute import space
from omni.core import config, console
from omni.core.module import Option
from omni.core.util import parse_int
from omni.brute.modules._base import BruteModule

__all__ = ["Pin", "Codes"]


class Pin(BruteModule):
    NAME = "brute.pin"
    DESCRIPTION = "Spray numeric PINs over the radio (gate/garage receivers)"
    OPTIONS = (Option("LENGTH", "PIN length", "4", required=True),
               Option("PROTOCOL", "Radio protocol", "Princeton",
                      choices=("Princeton", "CAME", "Nice FLO")),
               Option("FREQ", "carrier in Hz", "433920000"),
               Option("PRESET", "modem preset", "AM650"),
               Option("START", "first code", "0"),
               Option("COUNT", "how many codes", "200"),
               Option("REPEAT", "transmissions per code", "2"))

    def execute(self) -> dict:
        from omni.rf.presets import preset_by_name
        from omni.rf.bruteforce import BruteForcer
        from omni.rf.rig import open_rig

        length = max(1, self.get_int("LENGTH", 4))
        total = 10 ** length
        start = parse_int(self.get("START"), 0) or 0
        count = min(self.get_int("COUNT", 200), total)
        if count < total:
            console.warn(f"brute-forcing {count:,} of {total:,} "
                         f"({count / total:.1%} of the space)")
        else:
            console.info(f"full keyspace: {total:,} codes")
        rig = open_rig()
        try:
            tx = rig.tx()
            bruter = BruteForcer(tx)
            codes = (int(c) for c in space.numeric(length, start, start + count))
            sent = bruter.run_codes(
                preset_by_name(self.get("PRESET")), self.get_int("FREQ"),
                self.get("PROTOCOL"), codes,
                repeat_per_code=self.get_int("REPEAT", 2),
                progress=lambda done, all_: _tick(done, all_))
            console.ok(f"{sent:,} code(s) transmitted")
            return {"sent": sent, "length": length, "demo": rig.demo}
        finally:
            rig.close()


class Codes(BruteModule):
    NAME = "brute.codes"
    DESCRIPTION = "Spray an arbitrary mask of fixed-code alarms over the radio"
    OPTIONS = (Option("MASK", "hashcat-style mask of digits/hex", "",
                      required=True),
               Option("PROTOCOL", "Radio protocol", "Princeton",
                      choices=("Princeton", "CAME", "Nice FLO")),
               Option("FREQ", "carrier in Hz", "433920000"),
               Option("PRESET", "modem preset", "AM650"),
               Option("COUNT", "max codes", "500"),
               Option("REPEAT", "transmissions per code", "2"))

    def execute(self) -> dict:
        from omni.rf.presets import preset_by_name
        from omni.rf.bruteforce import BruteForcer
        from omni.rf.rig import open_rig

        bare = self.get("MASK").replace("?d", "0").replace("?h", "0")
        base = int(bare, 10) if bare.isdigit() else 0
        codes = [int(c) for c in space.cap(space.mask(self.get("MASK")),
                                           self.get_int("COUNT", 500))]
        console.info(f"{len(codes):,} code(s) from mask {self.get('MASK')}")
        rig = open_rig()
        try:
            bruter = BruteForcer(rig.tx())
            sent = bruter.run_codes(preset_by_name(self.get("PRESET")),
                                    self.get_int("FREQ"), self.get("PROTOCOL"),
                                    codes,
                                    repeat_per_code=self.get_int("REPEAT", 2))
            console.ok(f"{sent:,} code(s) transmitted")
            return {"sent": sent, "first": base, "demo": rig.demo}
        finally:
            rig.close()


def _tick(done: int, total: int) -> bool:
    if done % 25 == 0 or done == total:
        console.info(f"  {done:,}/{total:,}")
    return False
