"""Wordlist loading and mutation (leetspeak, case, suffixes, digits)."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator

from omni.core import config

__all__ = ["load", "mutate", "LEET", "SUFFIXES", "read_words", "is_wordlist"]

LEET = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7", "g": "9"}
SUFFIXES = ("", "1", "12", "123", "!", "!!", "01", "2024", "2025", "2026")

_SPLIT_RE = re.compile(r"[\s,;]+")


def is_wordlist(path: str) -> bool:
    return os.path.isfile(os.path.expanduser(path))


def read_words(path: str, limit: int | None = None) -> Iterator[str]:
    """Stream a wordlist file, skipping blanks and comments."""
    limit = int(limit if limit is not None else
                config.get_value("brute.max_candidates", 200000))
    expanded = os.path.expanduser(path)
    if not os.path.isfile(expanded):
        raise FileNotFoundError(f"no such wordlist: {expanded}")
    seen = 0
    with open(expanded, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            yield word
            seen += 1
            if seen >= limit:
                return


def load(source: str, limit: int | None = None) -> Iterator[str]:
    """Candidates from a wordlist path or an inline comma-separated list."""
    source = (source or "").strip()
    if not source:
        return
    if is_wordlist(source):
        yield from read_words(source, limit)
        return
    for word in _SPLIT_RE.split(source):
        if word:
            yield word


def _leet(word: str) -> str:
    return "".join(LEET.get(ch.lower(), ch) if ch.isalpha() else ch
                   for ch in word.lower())


def mutate(words, leet: bool = True, suffixes=SUFFIXES,
           limit: int | None = None) -> Iterator[str]:
    """Expand words with case variants, leet swaps and numeric suffixes.

    Ordering puts the cheapest guesses first (original, capitalised, upper,
    then leet, each with the suffix list), which is what makes short
    interactive runs land anything at all.
    """
    ceiling = int(limit if limit is not None else
                  config.get_value("brute.max_candidates", 200000))
    emitted: set[str] = set()
    count = 0
    for word in words:
        base = word.strip()
        if not base:
            continue
        forms = [base, base.capitalize(), base.upper()]
        if leet:
            forms += [_leet(base), _leet(base).capitalize()]
        for form in forms:
            for suffix in suffixes:
                candidate = form + suffix
                if candidate in emitted:
                    continue
                emitted.add(candidate)
                yield candidate
                count += 1
                if count >= ceiling:
                    return
