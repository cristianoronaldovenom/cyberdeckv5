"""KeeLoq manufacturer key store — drop-in compatible with Flipper keystores.

Two line formats are understood:

  ours    :  Name:KeyHex[:type[:seed]]        e.g.  MyBrand:0x1122334455667788:normal
  Flipper :  KeyHex:LEARNING:Name             e.g.  1122334455667788:2:MyBrand

Flipper LEARNING codes: 1 simple, 2 normal, 3 secure, 4 magic_xor,
5/6/7 magic_serial_type1/2/3 (extended), 0 auto (key + reversed key).
Header lines (Filetype:/Version:/Encryption:/IV:) and encrypted blobs are
skipped, so a whole plaintext `keeloq_mfcodes_user` file can be dropped in.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

from omni.rf import keeloq_crypto as kq
from omni.rf.util import reverse_key

# Flipper learning-code -> our type name
FLIPPER_LEARNING = {
    "1": "simple",
    "2": "normal",
    "3": "secure",
    "4": "magic_xor",
    "5": "magic_serial1",
    "6": "magic_serial2",
    "7": "magic_serial3",
    "0": "auto",
}

_KNOWN_TYPES = set(FLIPPER_LEARNING.values()) | {"simple"}


def manufacturer_keys(entry, fix: int, seed: int = 0) -> list[int]:
    """All candidate working keys for an entry (learning-type aware)."""
    key = int(getattr(entry, "key", 0)) & 0xFFFFFFFFFFFFFFFF
    ltype = (getattr(entry, "type", "simple") or "simple").lower()
    fix &= 0xFFFFFFFF
    if ltype == "normal":
        return [kq.normal_learning(fix, key)]
    if ltype == "secure":
        return [kq.secure_learning(fix, int(getattr(entry, "seed", 0) or seed), key)]
    if ltype == "magic_xor":
        return [kq.magic_xor_type1_learning(fix, key)]
    if ltype == "magic_serial1":
        return [kq.magic_serial_type1_learning(fix, key)]
    if ltype == "magic_serial2":
        return [kq.magic_serial_type2_learning(fix, key)]
    if ltype == "magic_serial3":
        return [kq.magic_serial_type3_learning(fix, key)]
    if ltype == "auto":  # try the key and its bit-reversal
        return [key, reverse_key(key)]
    return [key]


def manufacturer_key(entry, fix: int, seed: int = 0) -> int:
    """Primary candidate key (first of manufacturer_keys)."""
    return manufacturer_keys(entry, fix, seed)[0]


def resolve_man(entry, fix: int, hop: int, seed: int = 0):
    """Find the working key by validating btn+serial10 on the decrypted hop.

    Returns (man_key, decrypted_word) or (None, None).
    """
    btn, serial = kq.parse_fix(fix)
    for cand in manufacturer_keys(entry, fix, seed):
        dec = kq.keeloq_decrypt(hop, cand)
        if ((dec >> 28) & 0xF) == btn and \
                ((dec >> 16) & 0x3FF) == (serial & 0x3FF):
            return cand, dec
    return None, None


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# multi-core manufacturer-key search (the Pi has cores — use them)
# ---------------------------------------------------------------------------

# search in parallel once the keystore is bigger than this (a Pi 3 has 4
# cores, a Pi 5 has 4 fast ones; the Flipper's STM32 does one key at a time)
PARALLEL_THRESHOLD = 256


def _search_shard(args):
    """Worker: try a shard of (name, key, type, seed) tuples against a hop."""
    shard, fix, hop, seed = args
    hits = []
    for name, key, ltype, eseed in shard:
        entry = SimpleNamespace(name=name, key=key, type=ltype, seed=eseed)
        _man, dec = resolve_man(entry, fix, hop, seed)
        if dec is not None:
            hits.append((name, dec & 0xFFFF, int(eseed or 0)))
    return hits


class KeySearcher:
    """Finds the manufacturer of a captured hop — uses every CPU core.

    Small keystores (or 1-core machines) fall back to the plain sequential
    loop; big community databases get sharded across a worker pool.
    """

    def __init__(self, keystore=None, workers=None, threshold=None):
        self.keystore = keystore
        cpu = os.cpu_count() or 1
        self.workers = workers if workers is not None else max(1, min(cpu, 8))
        self.threshold = PARALLEL_THRESHOLD if threshold is None else threshold
        self._pool = None

    # -- public ------------------------------------------------------------
    def find(self, fix: int, hop: int, seed: int = 0):
        """(name, counter, seed) of the matching entry, or None."""
        entries = self.keystore.entries() if self.keystore else []
        if not entries:
            return None
        if len(entries) < self.threshold or self.workers <= 1 \
                or (os.cpu_count() or 1) < 2:
            shard = [(e.name, int(e.key), getattr(e, "type", "simple"),
                      int(getattr(e, "seed", 0) or 0)) for e in entries]
            hits = _search_shard((shard, fix, hop, seed))
            return hits[0] if hits else None
        try:
            if self._pool is None:
                import multiprocessing
                self._pool = multiprocessing.Pool(self.workers)
            shards = self._shards(entries)
            jobs = [(shard, fix, hop, seed) for shard in shards]
            for hits in self._pool.map(_search_shard, jobs):
                if hits:
                    return hits[0]
            return None
        except Exception:
            # any pool trouble -> plain sequential fallback, always correct
            shard = [(e.name, int(e.key), getattr(e, "type", "simple"),
                      int(getattr(e, "seed", 0) or 0)) for e in entries]
            hits = _search_shard((shard, fix, hop, seed))
            return hits[0] if hits else None

    def close(self):
        if self._pool is not None:
            try:
                self._pool.terminate()
                self._pool.join()
            except Exception:
                pass
            self._pool = None

    # -- internals -----------------------------------------------------------
    def _shards(self, entries):
        shards = [[] for _ in range(self.workers)]
        for i, e in enumerate(entries):
            shards[i % self.workers].append(
                (e.name, int(e.key), getattr(e, "type", "simple"),
                 int(getattr(e, "seed", 0) or 0)))
        return [s for s in shards if s]


class Keystore:
    """Name -> manufacturer key mapping with learning metadata."""

    def __init__(self):
        self._entries: dict[str, object] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, name: str) -> bool:
        return name in self._entries

    def get(self, name: str):
        if not name:
            return None
        return self._entries.get(name)

    def entries(self):
        return list(self._entries.values())

    def add(self, name: str, key: int, ltype: str = "simple", seed: int = 0):
        self._entries[name] = SimpleNamespace(name=name, key=int(key),
                                             type=ltype, seed=seed)
        return self._entries[name]

    def load(self, path: str) -> int:
        """Load keystore lines (ours or Flipper format); returns entry count."""
        loaded = 0
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    continue  # encrypted-blob / raw hex line
                parts = [p.strip() for p in line.split(":")]
                if len(parts) < 2:
                    continue
                head = parts[0]
                # Flipper keystore header lines
                if head in ("Filetype", "Version", "Encryption", "IV"):
                    continue
                # Flipper format:  KeyHex:LEARNING:Name
                if len(parts) >= 3 and _is_hex(head) and len(head) == 16 \
                        and parts[1].isdigit():
                    key = int(head, 16)
                    ltype = FLIPPER_LEARNING.get(parts[1], "simple")
                    name = parts[2] or f"MF-{head[:8]}"
                    self.add(name, key, ltype)
                    loaded += 1
                    continue
                # our format:  Name:KeyHex[:type[:seed]]
                name = head
                try:
                    key = int(parts[1], 16)
                except ValueError:
                    continue
                ltype = parts[2].lower() if len(parts) > 2 and parts[2] \
                    else "simple"
                if ltype not in _KNOWN_TYPES:
                    ltype = "simple"
                seed = int(parts[3], 0) if len(parts) > 3 and parts[3] else 0
                self.add(name, key, ltype, seed)
                loaded += 1
        return loaded
