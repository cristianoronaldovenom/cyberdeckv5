"""Shared plumbing for mobile modules."""

from __future__ import annotations

from omni.core import config
from omni.core.module import Module

__all__ = ["MobileModule"]


class MobileModule(Module):
    """Base class for APK-side modules. Outputs land in ``mobile/`` loot."""

    FAMILY = "mobile"

    def out_dir(self, sub: str = "") -> str:
        return config.output_dir(f"mobile/{sub}")

