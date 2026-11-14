"""Shared plumbing for the wireless modules."""

from __future__ import annotations

from omni.core.module import Module
from omni.wifi import iface as iface_mod

__all__ = ["WifiModule"]


class WifiModule(Module):
    """Base class: every wireless module needs a monitor interface.

    :meth:`monitor` puts the adapter in monitor mode on demand and returns the
    interface name; :meth:`restore` is best-effort cleanup for shells.
    """

    FAMILY = "wifi"
    NEEDS: tuple[str, ...] = ()

    def monitor(self) -> str:
        base = iface_mod.pick(self.get("IFACE") or None)
        return iface_mod.set_monitor(base)

    def restore(self, mon: str) -> None:
        try:
            iface_mod.set_managed(mon)
        except Exception:  # noqa: BLE001 - cleanup only
            pass
