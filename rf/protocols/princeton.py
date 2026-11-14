"""Princeton (EV1527-style) 24-bit PWM protocol."""

from __future__ import annotations

from omni.rf.protocols.base import DecoderResult, PwmDecoder, ProtocolEncoder


class PrincetonEncoder(ProtocolEncoder):
    """'1' = HIGH 3T / LOW 1T, '0' = HIGH 1T / LOW 3T, 4T per bit."""

    def __init__(self, data: int = 0, data_count_bit: int = 24, te: int = 390,
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


class PrincetonDecoder(PwmDecoder):
    NAME = "Princeton"
    TE = 390
    BITS = 24
    ONE = (3, 1)
    ZERO = (1, 3)
    RATIO = 3

    def _make_result(self, data: int, te: float) -> DecoderResult:
        return DecoderResult("Princeton", data, 24, te=te,
                             extra={"guard_time": 30})
