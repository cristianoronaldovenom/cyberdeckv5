"""KeeLoq: encoder, decoder, counter modes 0-7 and frame upload builder.

KeeLoq wire format (HCS301-style): the 64-bit frame (FIX, 32 bits, then
hopping code, 32 bits) is transmitted LSB-first, i.e. the wire carries the
bit-reversed frame — exactly like the Flipper firmware. On air each bit is
'1' = HIGH 1T / LOW 2T, '0' = HIGH 2T / LOW 1T, te = 400 us, with a long-low
guard before and after the frame.
"""

from __future__ import annotations

from omni.rf import keeloq_crypto as kq
from omni.rf.keystore import (PARALLEL_THRESHOLD, KeySearcher,
                          manufacturer_key, resolve_man)
from omni.rf.protocols.base import DecoderResult, PwmDecoder
from omni.rf.util import reverse_key

TE = 400
GUARD = 30

# OFEX attack cycle: 0000 -> 0001 -> FFFE -> FFFF -> 0000 ...
_OFEX_CYCLE = (0x0000, 0x0001, 0xFFFE, 0xFFFF)
_OFEX_MULT = -0x7FFFFFFF


def _ofex_next(cnt: int) -> int:
    if cnt in _OFEX_CYCLE:
        return _OFEX_CYCLE[(_OFEX_CYCLE.index(cnt) + 1) % len(_OFEX_CYCLE)]
    return (cnt + 1) & 0xFFFF


def next_counter(cnt: int, mode: int = 0, counter_mult: int = 1) -> int:
    """Rolling-counter manipulation, firmware counter modes 0-7.

      0: standard increment (+ counter_mult; OFEX mult cycles 0/1/FFFE/FFFF)
      1: OFEX pattern
      2: +0x3333 jumps (wraps to 0 on overflow)
      3/4: +1, but bit-15-set counters count down inside the low 15 bits
      5: decrement
      6: freeze
      7: +2
    """
    cnt &= 0xFFFF
    if mode == 0:
        if counter_mult == _OFEX_MULT:
            return _ofex_next(cnt)
        return (cnt + counter_mult) & 0xFFFF
    if mode == 1:
        return _ofex_next(cnt)
    if mode == 2:
        total = cnt + 0x3333
        return 0 if total > 0xFFFF else total
    if mode in (3, 4):
        if cnt & 0x8000:
            return ((cnt & 0x7FFF) - 1) & 0xFFFF
        return (cnt + 1) & 0xFFFF
    if mode == 5:
        return (cnt - 1) & 0xFFFF
    if mode == 6:
        return cnt
    return (cnt + 2) & 0xFFFF


def build_keeloq_upload(fix: int, hop: int, te: int = TE,
                        guard: int = GUARD) -> list[tuple[bool, int]]:
    """Build the level train for a 64-bit KeeLoq frame (fix then hop).

    The frame goes out LSB-first (wire = bit-reversed frame), matching real
    HCS301 transmitters and the Flipper firmware.
    """
    frame = kq.join_frame(fix, hop)
    wire = reverse_key(frame, 64)
    levels: list[tuple[bool, int]] = [(False, guard * te)]

    for i in reversed(range(64)):
        if (wire >> i) & 1:
            levels.append((True, te))
            levels.append((False, 2 * te))
        else:
            levels.append((True, 2 * te))
            levels.append((False, te))

    levels += [(True, te), (False, guard * te)]
    return levels


class KeeLoqEncoder:
    """Builds KeeLoq frames; get_upload() advances the rolling counter."""

    def __init__(self, keystore=None, te: int = TE, repeat: int = 3,
                 counter_mult: int = 1):
        self.keystore = keystore
        self.te = te
        self.repeat = repeat
        self.counter_mult = counter_mult
        self.serial = 0
        self.btn = 0
        self.cnt = 0
        self.manufacture_name = None
        self.counter_mode = 0
        self.seed = 0
        self._fallback_hop = 0
        self.fix = 0
        self.hop = 0
        self.data = 0

    def set_frame(self, serial: int = 0, btn: int = 0, cnt: int = 0,
                  manufacture_name: str | None = None, counter_mode: int = 0,
                  seed: int = 0) -> None:
        self.serial = serial & 0x0FFFFFFF
        self.btn = btn & 0xF
        self.cnt = cnt & 0xFFFF
        self.manufacture_name = manufacture_name
        self.counter_mode = counter_mode
        self.seed = seed
        self._apply()

    def set_raw_frame(self, fix: int, hop: int) -> None:
        """Replay mode: emit an exact captured fix/hop pair."""
        self._fallback_hop = hop & 0xFFFFFFFF
        self.fix = fix & 0xFFFFFFFF
        self.hop = self._fallback_hop
        self.data = kq.join_frame(self.fix, self.hop)

    def _man_key(self):
        entry = self.keystore.get(self.manufacture_name) \
            if (self.keystore and self.manufacture_name) else None
        if entry is None:
            return None
        return manufacturer_key(entry, self.fix, self.seed)

    def _apply(self) -> None:
        self.fix = ((self.btn & 0xF) << 28) | (self.serial & 0x0FFFFFFF)
        man = self._man_key()
        if man is None:
            self.hop = self._fallback_hop & 0xFFFFFFFF
        else:
            word = (((self.btn & 0xF) << 28) | ((self.serial & 0x3FF) << 16)
                    | (self.cnt & 0xFFFF))
            self.hop = kq.keeloq_encrypt(word, man)
        self.data = kq.join_frame(self.fix, self.hop)

    def get_upload(self):
        """Advance the counter (per counter_mode), then build the frame."""
        self.cnt = next_counter(self.cnt, self.counter_mode, self.counter_mult)
        self._apply()
        return build_keeloq_upload(self.fix, self.hop, self.te), self.repeat

    def build_upload(self) -> list[tuple[bool, int]]:
        return build_keeloq_upload(self.fix, self.hop, self.te)


class KeeLoqDecoder(PwmDecoder):
    NAME = "KeeLoq"
    TE = TE
    BITS = 64
    ONE = (1, 2)
    ZERO = (2, 1)
    RATIO = 2
    REPEAT_RULE = False  # hopping codes differ per frame

    def __init__(self, keystore=None):
        super().__init__()
        self.keystore = keystore
        self._searcher = None  # lazy multi-core searcher (big keystores)

    def close(self):
        if self._searcher is not None:
            self._searcher.close()
            self._searcher = None

    def _identify(self, fix: int, hop: int):
        """Try every manufacturer key; a match must reproduce btn+serial10."""
        btn, serial = kq.parse_fix(fix)
        if self.keystore is None:
            return "Unknown", btn, serial, 0, 0

        # big keystore -> shard the search across all CPU cores (Pi power)
        if len(self.keystore) >= PARALLEL_THRESHOLD:
            if self._searcher is None:
                self._searcher = KeySearcher(self.keystore)
            hit = self._searcher.find(fix, hop)
            if hit is not None:
                return (hit[0], btn, serial, hit[1], int(hit[2] or 0))
            return "Unknown", btn, serial, 0, 0

        for entry in self.keystore.entries():
            _man, dec = resolve_man(entry, fix, hop,
                                    getattr(entry, "seed", 0))
            if dec is not None:
                return (entry.name, btn, serial, dec & 0xFFFF,
                        int(getattr(entry, "seed", 0) or 0))
        return "Unknown", btn, serial, 0, 0

    def _make_result(self, data: int, te: float) -> DecoderResult:
        # the wire carries the frame LSB-first -> restore logical order
        return self.make_result_from_data(reverse_key(data, 64), te=te)

    def make_result_from_data(self, data: int, te: float = 0) -> DecoderResult:
        fix, hop = kq.split_frame(data)
        btn, serial = kq.parse_fix(fix)

        # firmware parity: headerless AN-Motors / HCS101 remotes
        if (hop >> 24) == ((hop >> 16) & 0xFF) and \
                (fix >> 28) == ((hop >> 12) & 0xF) and (hop & 0xFFF) == 0x404:
            return DecoderResult("KeeLoq", data, 64, te=te, serial=serial,
                                btn=btn, cnt=(hop >> 16) & 0xFFFF, seed=0,
                                manufacture_name="AN-Motors")
        if (hop & 0xFFF) == 0x000 and (fix >> 28) == ((hop >> 12) & 0xF):
            return DecoderResult("KeeLoq", data, 64, te=te, serial=serial,
                                btn=btn, cnt=(hop >> 16) & 0xFFFF, seed=0,
                                manufacture_name="HCS101")

        name, btn, serial, cnt, seed = self._identify(fix, hop)
        return DecoderResult("KeeLoq", data, 64, te=te, serial=serial,
                            btn=btn, cnt=cnt, seed=seed, manufacture_name=name)

