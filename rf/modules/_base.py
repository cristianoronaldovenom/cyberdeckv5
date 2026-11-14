"""Shared plumbing for sub-GHz radio modules."""

from __future__ import annotations

from omni.core import config
from omni.core.module import Module
from omni.rf.keystore import Keystore
from omni.rf.presets import preset_by_name
from omni.rf.rig import Rig, open_rig

__all__ = ["RfModule"]


class RfModule(Module):
    """Base class: opens a rig (mock-degrading) and resolves presets."""

    FAMILY = "rf"

    def rig(self, keystore: Keystore | None = None) -> Rig:
        return open_rig(keystore)

    def preset(self):
        return preset_by_name(self.get("PRESET") or
                              str(config.get_value("rf.default_preset", "AM650")))

    def freq(self) -> int:
        return self.get_int("FREQ") or int(
            config.get_value("rf.default_frequency", 433_920_000))
