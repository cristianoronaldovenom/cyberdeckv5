"""Frame maths: decode one KeeLoq frame, then predict what comes after it.

``car.analyze`` says *what* a capture is and ``car.inject`` acts on it; this is
the inspection step between them. Give it a capture (or a raw fix/hop pair)
plus a keystore entry, and it prints the button, the serial, the decoded
counter and the encrypted wire values for the next presses — the numbers to
look at when an attack does not land and the reason is not obvious.

``car.frame`` also works the other way round: with an explicit ``ENTRY`` and
``SEED`` it derives the manufacturer key and *proves* the split by re-encoding
the captured counter back to the same hop word.
"""

from __future__ import annotations

from omni.car import analysis
from omni.car.modules._base import CarModule
from omni.core import console
from omni.core.module import Option
from omni.core.util import parse_int
from omni.rf import keeloq_crypto as kq

__all__ = ["Frame", "MODES"]


#: counter step modes: 1 = increment, 2 = the OEM "normal" mode
MODES = {"1": 1, "2": 2}


class Frame(CarModule):
    NAME = "car.frame"
    DESCRIPTION = "Decode one KeeLoq frame and predict the next N wire values"
    OPTIONS = (Option("SUB", "captured .sub (or give FIX and HOP)"),
               Option("FIX", "fixed part, hex or dec"),
               Option("HOP", "hopping part, hex or dec"),
               Option("ENTRY", "exact keystore entry name"),
               Option("SEED", "serial seed for the entry (hex or dec)", "0"),
               Option("KEYSTORE", "manufacturer keystore path"),
               Option("COUNT", "how many future counters to show", "4"),
               Option("MODE", "counter mode", "2", choices=("1", "2")))

    def parts(self) -> tuple[int, int]:
        """The frame as ``(fix, hop)``, from SUB or from FIX/HOP."""
        if self.get("SUB"):
            sub = self.load_sub()
            if not sub.key:
                raise ValueError("the .sub has no decoded key — it is a raw "
                                 "capture, so there is nothing to split")
            return kq.split_frame(sub.key)
        fix, hop = parse_int(self.get("FIX")), parse_int(self.get("HOP"))
        if not fix or not hop:
            raise ValueError("give SUB, or both FIX and HOP")
        return fix & kq.MASK32, hop & kq.MASK32

    def execute(self) -> dict:
        fix, hop = self.parts()
        button, serial = kq.parse_fix(fix)
        seed = parse_int(self.get("SEED"), 0)
        store = self.keystore(self.get("KEYSTORE") or None)
        console.kv([("fix", f"0x{fix:08X}"), ("hop", f"0x{hop:08X}"),
                    ("button", f"0x{button:X}"),
                    ("serial", f"0x{serial:07X}")])

        entry = self.get("ENTRY").strip()
        if entry:
            key, counter = analysis.resolve(entry, fix, hop, seed, store)
            if key is None:
                console.warn(f"no keystore entry named {entry!r} — check "
                             f"assets/keeloq_keys.txt")
        else:
            found = analysis.analyze_frame(fix, hop, store)
            key, counter = (None, found.get("counter"))
            if found.get("manufacturer"):
                key, counter = analysis.resolve(found["manufacturer"], fix,
                                                hop, seed, store)
                entry = found["manufacturer"]
                console.info(f"matched keystore entry {entry!r}")

        result: dict = {"fix": f"0x{fix:08X}", "hop": f"0x{hop:08X}",
                        "button": button, "serial": serial,
                        "counter": counter, "entry": entry, "chain": []}
        if key is None:
            console.warn("manufacturer key unknown — counter maths need one "
                         "(supply ENTRY= and the right SEED=)")
            return result

        console.ok(f"manufacturer key 0x{key:08X}"
                   + (f" — counter 0x{counter:04X}" if counter is not None
                      else " — counter not decodable with this seed"))
        mode = MODES.get(self.get("MODE"), 2)
        chain = analysis.counter_chain(fix, hop, key,
                                       max(1, self.get_int("COUNT", 4)), mode)
        console.table(["n", "counter", "hop word", "wire"],
                      [[str(index + 1), f"0x{row['counter']:04X}",
                        row["hop"], row["wire"]]
                       for index, row in enumerate(chain)])
        result["chain"] = chain
        result["mount"] = f"0x{key:08X}"
        return result
