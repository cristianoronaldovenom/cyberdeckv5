"""CAME 12-bit gate/barrier protocol (te 320 us)."""

from __future__ import annotations

from omni.rf.protocols.base import DecoderResult, PwmDecoder, ProtocolEncoder


class CameEncoder(ProtocolEncoder):
    def __init__(self, data: int = 0, data_count_bit: int = 12, te: int = 320,
                 guard_time: int = 30):
        self.data = data
        self.data_count_bit = data_count_bit
        self.te = te
        self.guard_time = guard_time

    def build_upload(self) -> list[tuple[bool, int]]:
        levels: list[tuple[bool, int]] = []
        te = self.te
        for i in reversed(range(self.data_count_bit)):
            if (self.data >> i) & 1:
                levels += [(True, 3 * te), (False, te)]
            else:
                levels += [(True, te), (False, 3 * te)]
        levels += [(True, te), (False, self.guard_time * te)]
        return levels


class CameDecoder(PwmDecoder):
    NAME = "CAME"
    TE = 320
    BITS = 12
    ONE = (3, 1)
    ZERO = (1, 3)
    RATIO = 3
