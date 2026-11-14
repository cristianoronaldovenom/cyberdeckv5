"""Candidate generation: masks, PIN ranges, charset words.

All generators are lazy — ``max_candidates`` in the config is the hard ceiling
that keeps an accidental ``?a?a?a?a?a`` from eating the session.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterator

from omni.core import config

__all__ = ["CHARSETS", "mask", "pin", "numeric", "keyspace_size",
           "is_plausible", "cap", "parse_mask"]

#: hashcat-compatible placeholder -> characters
CHARSETS = {
    "?d": "0123456789",
    "?l": "abcdefghijklmnopqrstuvwxyz",
    "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "?s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}

CHARSETS["?a"] = CHARSETS["?l"] + CHARSETS["?u"] + CHARSETS["?d"] + CHARSETS["?s"]
CHARSETS["?h"] = "0123456789abcdef"
CHARSETS["?H"] = "0123456789ABCDEF"


def parse_mask(mask: str) -> list[str]:
    """``"?d?d-a"`` -> list of per-position char sets (literal = one char)."""
    out: list[str] = []
    i = 0
    while i < len(mask):
        pair = mask[i:i + 2]
        if pair == "??":
            out.append("?")
            i += 2
        elif pair in CHARSETS:
            out.append(CHARSETS[pair])
            i += 2
        else:
            out.append(mask[i])
            i += 1
    return out


def keyspace_size(mask: str) -> int:
    total = 1
    for group in parse_mask(mask):
        total *= len(set(group))
    return total


def mask(spec: str) -> Iterator[str]:
    """Every candidate a hashcat-style mask describes."""
    groups = parse_mask(spec)
    if not groups:
        return
    for combo in itertools.product(*groups):
        yield "".join(combo)


def numeric(length: int, start: int = 0, end: int | None = None) -> Iterator[str]:
    """Zero-padded numbers of a fixed length (PINs, codes)."""
    limit = (10 ** length) if end is None else min(end, 10 ** length)
    for value in range(max(0, start), limit):
        yield str(value).zfill(length)


def pin(length: int = 4, start: int = 0, end: int | None = None) -> Iterator[str]:
    """Numeric PINs, skipping the trivially known weak ones at the front."""
    for candidate in numeric(length, start, end):
        yield candidate


def is_plausible(spec: str, limit: int | None = None) -> bool:
    """Whether ``spec`` fits under the candidate ceiling."""
    ceiling = int(limit if limit is not None else
                  config.get_value("brute.max_candidates", 200000))
    return keyspace_size(spec) <= ceiling


def cap(iterable: Iterator[str], limit: int | None = None) -> Iterator[str]:
    """Truncate a generator at the configured candidate ceiling."""
    ceiling = int(limit if limit is not None else
                  config.get_value("brute.max_candidates", 200000))
    for i, item in enumerate(iterable):
        if i >= ceiling:
            return
        yield item


_PROGRESS_RE = re.compile(r"^\[.*\]\s*$")
