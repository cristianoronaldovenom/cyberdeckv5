"""Shared plumbing for radio modules."""

from __future__ import annotations

from omni.core.module import Module

__all__ = ["RadioModule"]


class RadioModule(Module):
    """Base class: family tag only — each module declares its own ``NEEDS``."""

    FAMILY = "radio"
