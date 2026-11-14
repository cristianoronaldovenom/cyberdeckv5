"""Shared plumbing for the android modules."""

from __future__ import annotations

from omni.android.adb import Adb
from omni.core import console, proc
from omni.core.module import Module

__all__ = ["AndroidModule"]


class AndroidModule(Module):
    """Base class: resolves a device before ``execute`` runs."""

    FAMILY = "android"
    NEEDS: tuple[str, ...] = ("adb",)

    def adb(self) -> Adb:
        client = Adb()
        if not client.available():
            raise proc.ToolMissing(f"'{client.binary}' not found — "
                                   + proc.install_hint("adb"))
        if client.device() is None:
            picked = client.pick()
            if picked is None:
                raise RuntimeError("no device selected — run  use android.devices")
        return client

    def validate(self) -> None:
        super().validate()
        client = Adb()
        if not client.available():
            console.warn(f"'{client.binary}' not found — "
                         + proc.install_hint("adb"))
            return
        if client.device() is None and len(client.devices()) > 1 and not client.serial:
            console.warn("several devices attached; using the first usable one")
