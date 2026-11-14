"""Decoder results and shared PWM encoder/decoder machinery."""

from __future__ import annotations


class DecoderResult:
    """A decoded frame, protocol-agnostic."""

    def __init__(self, protocol_name: str, data: int, data_count_bit: int,
                 te: float = 0, serial=None, btn=None, cnt=None, seed=None,
                 manufacture_name: str = "Unknown", extra: dict | None = None):
        self.protocol_name = protocol_name
        self.data = data
        self.data_count_bit = data_count_bit
        self.te = te
        self.serial = serial
        self.btn = btn
        self.cnt = cnt
        self.seed = seed
        self.manufacture_name = manufacture_name
        self.extra = extra or {}

    def summary(self) -> str:
        width = max(1, (self.data_count_bit + 3) // 4)
        lines = [
            f"  Protocol : {self.protocol_name}  ({self.data_count_bit} bit)",
            f"  Data     : 0x{self.data:0{width}X}",
            f"  TE       : {int(self.te)} us",
        ]
        if self.protocol_name == "KeeLoq":
            lines += [
                f"  Btn      : 0x{self.btn:X}",
                f"  Serial   : 0x{self.serial:07X}",
                f"  Counter  : 0x{self.cnt:04X}",
                f"  MF       : {self.manufacture_name}",
            ]
            if self.seed:
                lines.append(f"  Seed     : 0x{self.seed:08X}")
        return "\n".join(lines)

    def __repr__(self):
        return (f"DecoderResult({self.protocol_name}, data=0x{self.data:X}, "
                f"cnt={self.cnt!r}, mf={self.manufacture_name!r})")


class ProtocolEncoder:
    """Base class for level-train encoders."""

    def build_upload(self) -> list[tuple[bool, int]]:
        raise NotImplementedError


class PwmDecoder:
    """Shared PWM (short/long pulse pair) decoder state machine.

    Subclasses declare the frame shape:
      TE       nominal short-pulse length in us
      BITS     frame length in bits
      ONE/ZERO (high_units, low_units) per bit value
      RATIO    long-pulse / short-pulse ratio implied by the shape
    Frames are terminated by a long LOW guard (>= GUARD_UNITS * TE).
    """

    NAME = "?"
    TE = 400
    BITS = 24
    ONE = (3, 1)
    ZERO = (1, 3)
    RATIO = 3
    GUARD_UNITS = 8
    TE_TOL = 0.12
    PAIR_TOL = 0.35
    REPEAT_RULE = True  # two identical consecutive frames required

    def __init__(self):
        self._reset()

    def _reset(self) -> None:
        self._bits: list[int] = []
        self._pending: int | None = None
        self._te_sum = 0.0
        self._te_n = 0
        self._last: int | None = None
        self._last_reported: int | None = None

    # -- API --------------------------------------------------------------
    def feed(self, level, duration: int):
        """Feed one (level, duration_us) event; returns a DecoderResult on report."""
        if level:
            self._pending = int(duration)
            return None
        if self._pending is None:
            return None  # idle low / guard with no pending high
        high = self._pending
        self._pending = None
        if int(duration) >= self.GUARD_UNITS * self.TE:
            return self._finish()
        bit = self._classify(high, int(duration))
        if bit is None:
            self._bad_pair()
            return None
        self._bits.append(bit)
        if len(self._bits) > self.BITS:
            self._bad_pair()
        return None

    # -- internals ----------------------------------------------------------
    def _te_est(self) -> float:
        return self._te_sum / self._te_n if self._te_n else float(self.TE)

    def _classify(self, high: int, low: int):
        short, long_ = min(high, low), max(high, low)
        lo = self.TE * (1 - self.TE_TOL)
        hi = self.TE * (1 + self.TE_TOL)
        if short < lo or short > hi:
            return None
        if abs(long_ - self.RATIO * short) > self.PAIR_TOL * short:
            return None
        self._te_sum += short
        self._te_n += 1
        one_long_high = self.ONE[0] > self.ONE[1]
        return 1 if ((high > low) == one_long_high) else 0

    def _bad_pair(self) -> None:
        self._bits = []
        self._te_sum = 0.0
        self._te_n = 0

    def _finish(self):
        bits, self._bits = self._bits, []
        self._te_sum, self._te_n = 0.0, 0
        if len(bits) != self.BITS:
            return None
        data = 0
        for b in bits:
            data = (data << 1) | b
        te = self._te_est()
        if not self.REPEAT_RULE:
            return self._make_result(data, te)
        if self._last is not None and self._last == data:
            if self._last_reported != data:
                self._last_reported = data
                return self._make_result(data, te)
        else:
            self._last = data
        return None

    def _make_result(self, data: int, te: float) -> DecoderResult:
        return DecoderResult(self.NAME, data, self.BITS, te=te)
