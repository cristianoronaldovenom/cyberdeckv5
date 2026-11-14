"""Shared plumbing for the iOS modules."""

from __future__ import annotations

from omni.core import console, proc
from omni.core.module import Module
from omni.ios.device import BackendError, Ios

__all__ = ["IosModule"]


class IosModule(Module):
    """Base class: builds a client and enforces developer-mode prerequisites."""

    FAMILY = "ios"
    NEEDS: tuple[str, ...] = ("pymobiledevice3",)

    def client(self) -> Ios:
        client = Ios(udid=self.get("UDID") or None,
                     tunnel=self.get("TUNNEL") or None)
        try:
            client.backend
        except BackendError as exc:
            raise proc.ToolMissing(str(exc)) from exc
        if not client.udid:
            console.warn("no UDID given — pymobiledevice3 will pick a device")
        return client

    def validate(self) -> None:
        super().validate()
        probe = Ios()
        if not (probe.have_pmd3() or probe.have_limd()):
            raise proc.ToolMissing(
                "no iOS backend installed — " + proc.install_hint("pymobiledevice3")
                + " (or install libimobiledevice)")
