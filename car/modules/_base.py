"""Shared plumbing for car-key modules: rig + keystore + sub loading."""

from __future__ import annotations

import os

from omni.car import analysis
from omni.core import console
from omni.core.module import Module
from omni.rf.rig import Rig, open_rig
from omni.rf.subfile import SubFile

__all__ = ["CarModule"]


class CarModule(Module):
    """Base class: opens a rig, loads the keystore and the target .sub."""

    FAMILY = "car"

    def rig(self, keystore=None) -> Rig:
        return open_rig(keystore)

    def keystore(self, path: str | None = None):
        store = analysis.load_keystore(path)
        if len(store) == 0:
            console.warn("keystore empty: no manufacturer-key search possible "
                         "(see assets/keeloq_keys.txt)")
        else:
            console.info(f"{len(store)} manufacturer key(s) loaded")
        return store

    def load_sub(self, path: str | None = None) -> SubFile:
        target = path or self.get("SUB")
        if not target:
            raise ValueError("missing required option: SUB")
        target = os.path.expanduser(target)
        if not os.path.exists(target):
            raise FileNotFoundError(f"no such .sub file: {target}")
        return SubFile.load(target)
