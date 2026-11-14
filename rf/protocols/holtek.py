"""Holtek HT6P20-style 40-bit protocol (1T/2T shape, te 600 us)."""

from __future__ import annotations

from omni.rf.protocols.base import PwmDecoder, ProtocolEncoder


class HoltekEncoder(ProtocolEncoder):
    """'1' = HIGH 1T / LOW 2T, '0' = HIGH 2T / LOW 1T (3T per bit)."""

    def __init__(self, data: int = 0, data_count_bit: int = 40, te: int = 600,
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
                levels += [(True, te), (False, 2 * te)]
            else:
                levels += [(True, 2 * te), (False, te)]
        levels += [(True, te), (False, self.guard_time * te)]
        return levels


class HoltekDecoder(PwmDecoder):
    NAME = "Holtek"
    TE = 600
    BITS = 40
    ONE = (1, 2)
    ZERO = (2, 1)
    RATIO = 2
