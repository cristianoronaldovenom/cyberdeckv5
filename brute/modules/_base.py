"""Shared plumbing for brute modules."""

from __future__ import annotations

from omni.brute import space, words
from omni.core.module import Module

__all__ = ["BruteModule"]


class BruteModule(Module):
    """Base class with candidate-source resolution helpers."""

    FAMILY = "brute"

    def candidates(self, mask: str, wordlist: str, inline: str,
                   mutate: bool, limit: int | None = None):
        """Resolve a candidate iterator from MASK > WORDLIST > INLINE."""
        if mask:
            return space.cap(space.mask(mask), limit)
        source = wordlist or inline
        if not source:
            raise ValueError("need one of MASK, WORDLIST or INLINE")
        stream = words.load(source)
        if mutate:
            stream = words.mutate(stream, limit=limit)
        return space.cap(stream, limit)
