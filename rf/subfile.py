"""Flipper Zero .sub file reader/writer (decoded key files and RAW files)."""

from __future__ import annotations

import os

from omni.rf.presets import custom_preset_from_bytes, preset_by_name

_FULL_TO_SHORT = {
    "FuriHalSubGhzPresetOok650Async": "AM650",
    "FuriHalSubGhzPresetOok270Async": "AM270",
    "FuriHalSubGhzPreset2FSKDev238Async": "FM238",
    "FuriHalSubGhzPreset2FSKDev476Async": "FM476",
    "FuriHalSubGhzPreset2FSKDev120Async": "FM120",
    "FuriHalSubGhzPresetMSK99Async": "MSK99",
    "FuriHalSubGhzPresetGFSK9Async": "GFSK9",
}


def raw_durations_to_levels(durations):
    """[400, -800, ...] -> [(True, 400), (False, 800), ...]"""
    return [(d > 0, abs(d)) for d in durations]


def levels_to_raw_durations(levels):
    return [d if lvl else -d for lvl, d in levels]


class SubFile:
    """One Flipper .sub file (decoded or RAW)."""

    def __init__(self):
        self.filetype = "Flipper SubGhz Key File"
        self.frequency = 433_920_000
        self.preset_name = "FuriHalSubGhzPresetOok650Async"
        self.protocol = "RAW"
        self.bit = 0
        self.key = 0
        self.te = 0
        self.manufacture = None
        self.seed = 0
        self.counter_mode = None
        self.repeat = 1
        self.guard_time = None
        self.raw_data: list[int] = []
        self.custom_preset_bytes: list[int] | None = None

    # -- helpers -----------------------------------------------------------
    @property
    def is_raw(self) -> bool:
        return self.filetype == "Flipper SubGhz RAW File" or \
            (not self.protocol or self.protocol == "RAW")

    def preset_short(self) -> str:
        return _FULL_TO_SHORT.get(self.preset_name, self.preset_name or "")

    def preset(self):
        if self.custom_preset_bytes:
            return custom_preset_from_bytes(self.custom_preset_bytes)
        return preset_by_name(self.preset_name)

    def copy(self) -> "SubFile":
        other = SubFile()
        for field in ("filetype", "frequency", "preset_name", "protocol",
                      "bit", "key", "te", "manufacture", "seed",
                      "counter_mode", "repeat", "guard_time"):
            setattr(other, field, getattr(self, field))
        other.raw_data = list(self.raw_data)
        other.custom_preset_bytes = list(self.custom_preset_bytes) \
            if self.custom_preset_bytes else None
        return other

    # -- serialization -------------------------------------------------------
    def save(self, path: str) -> None:
        lines = [
            f"Filetype: {self.filetype}",
            "Version: 1",
            f"Frequency: {int(self.frequency)}",
            f"Preset: {self.preset_name}",
        ]
        if self.custom_preset_bytes:
            lines.append("CustomPreset: " +
                         " ".join(f"{b:02X}" for b in self.custom_preset_bytes))
        if self.is_raw:
            lines.append("RAW: " + " ".join(str(d) for d in self.raw_data))
        else:
            nbytes = max(1, (self.bit + 7) // 8)
            lines += [
                f"Protocol: {self.protocol}",
                f"Bit: {int(self.bit)}",
                "Key: " + " ".join(f"{b:02X}" for b in
                                  int(self.key).to_bytes(nbytes, "big")),
            ]
            if self.te:
                lines.append(f"TE: {int(self.te)}")
            if self.manufacture:
                lines.append(f"Manufacture: {self.manufacture}")
            if self.seed:
                lines.append("Seed: " + " ".join(
                    f"{b:02X}" for b in int(self.seed).to_bytes(4, "big")))
            if self.counter_mode is not None:
                lines.append(f"CounterMode: {int(self.counter_mode)}")
            if self.repeat:
                lines.append(f"Repeat: {int(self.repeat)}")
            if self.guard_time is not None:
                lines.append(f"GuardTime: {int(self.guard_time)}")
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")

    @classmethod
    def load(cls, path: str) -> "SubFile":
        sub = cls()
        raw_line = None
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                if key == "Filetype":
                    sub.filetype = value
                elif key == "Frequency":
                    sub.frequency = int(value)
                elif key == "Preset":
                    sub.preset_name = value
                elif key == "CustomPreset":
                    sub.custom_preset_bytes = [int(b, 16)
                                               for b in value.split()]
                elif key == "Protocol":
                    sub.protocol = value
                elif key == "Bit":
                    sub.bit = int(value)
                elif key == "Key":
                    sub.key = int.from_bytes(
                        bytes.fromhex(value.replace(" ", "")), "big")
                elif key == "TE":
                    sub.te = int(value)
                elif key == "Manufacture":
                    sub.manufacture = value
                elif key == "Seed":
                    sub.seed = int.from_bytes(
                        bytes.fromhex(value.replace(" ", "")), "big")
                elif key == "CounterMode":
                    sub.counter_mode = int(value)
                elif key == "Repeat":
                    sub.repeat = int(value)
                elif key == "GuardTime":
                    sub.guard_time = int(value)
                elif key == "RAW":
                    raw_line = value
        if sub.filetype == "Flipper SubGhz RAW File" and raw_line is not None:
            sub.raw_data = [int(d) for d in raw_line.split()]
            sub.protocol = "RAW"
        return sub

    def info_lines(self) -> list[str]:
        lines = [
            f"type    : {self.filetype}",
            f"freq    : {self.frequency / 1e6:.3f} MHz",
            f"preset  : {self.preset_name} ({self.preset_short()})",
        ]
        if self.is_raw:
            total_ms = sum(abs(d) for d in self.raw_data) / 1000
            lines.append(f"raw     : {len(self.raw_data)} samples "
                         f"({total_ms:.1f} ms)")
        else:
            lines += [
                f"protocol: {self.protocol}",
                f"bits    : {self.bit}",
                f"key     : 0x{self.key:X}",
            ]
            if self.te:
                lines.append(f"te      : {self.te} us")
            if self.manufacture:
                lines.append(f"mf      : {self.manufacture}")
            if self.seed:
                lines.append(f"seed    : 0x{self.seed:08X}")
            if self.counter_mode is not None:
                lines.append(f"cmode   : {self.counter_mode}")
            if self.repeat:
                lines.append(f"repeat  : {self.repeat}")
        return lines


def load(path: str) -> SubFile:
    """Read a .sub file (module-level convenience)."""
    return SubFile.load(path)

