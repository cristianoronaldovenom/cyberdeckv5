"""Elevation for the Windows-only trades.

Administrator rights are needed for DPAPI browser secrets of other users, some
service/registry actions and raw sockets. The helper is all-or-nothing and
never raises: if UAC is declined the caller keeps running unelevated.
"""

from __future__ import annotations

import ctypes
import os
import sys

from omni.core import console

__all__ = ["is_admin", "can_elevate", "relaunch", "ensure"]


def is_admin() -> bool:
    """True when this process already has administrator rights."""
    if os.name != "nt":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def can_elevate() -> bool:
    return os.name == "nt" and not is_admin()


def relaunch(argv: list[str] | None = None) -> bool:
    """Start a new elevated copy; True when it was handed over.

    A declined UAC prompt returns False, so the caller can continue in the
    current window instead of making the user start over.
    """
    if not can_elevate():
        return False
    argv = list(argv or sys.argv)
    exe = sys.executable
    params = " ".join(f'"{a}"' if " " in a else a for a in argv[1:])
    if getattr(sys, "frozen", False):
        exe = sys.executable
        params = " ".join(f'"{a}"' if " " in a else a for a in argv[1:])
    else:
        # python -m omni.cli ... : re-use the same interpreter and module
        params = "-m omni.cli " + params
    try:
        code = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, params, os.getcwd(), 1)
    except (AttributeError, OSError):
        return False
    return int(code) > 32


def ensure(argv: list[str] | None = None) -> bool:
    """Hand over to an elevated copy when it looks useful; True if it did."""
    if not can_elevate():
        return False
    if relaunch(argv):
        return True
    console.warn("continuing without administrator rights")
    return False
