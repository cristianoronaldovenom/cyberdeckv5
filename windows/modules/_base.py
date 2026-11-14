"""Shared plumbing for the Windows modules."""

from __future__ import annotations

from omni.core.module import Module

__all__ = ["WindowsModule"]


class WindowsModule(Module):
    """Base class: refuses to run away from Windows."""

    FAMILY = "windows"

    def validate(self) -> None:
        super().validate()
        import os
        if os.name != "nt":
            raise RuntimeError(
                "host is not Windows — these act on the machine they run on "
                "(the target, a Windows VM, or an RDP session)")
