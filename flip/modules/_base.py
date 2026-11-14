"""Shared plumbing for Flipper modules — every module works offline on files."""

from __future__ import annotations

from omni.core import config
from omni.core.module import Module

__all__ = ["FlipModule", "capture_dir"]


def capture_dir(kind: str) -> str:
    """Where captures land: config output root + flip/<kind>."""
    return config.output_dir(f"flip/{kind}")


class FlipModule(Module):
    """Base class: file-only trade, no device required."""

    FAMILY = "flip"
    NEEDS: tuple[str, ...] = ()
