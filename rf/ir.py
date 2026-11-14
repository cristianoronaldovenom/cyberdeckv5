"""Infrared — Flipper-style TV/AC/projector remote control.

Protocols: NEC (encode+decode), Samsung32, RC5, Sony SIRC (encode).
Transmission goes out on a Pi GPIO pin into an IR LED with a 38 kHz
carrier (modulate()). Flipper `.ir` raw files are read/written 1:1.
"""

from __future__ import annotations

import os

CARRIER = 38_000
LED_PIN_DEFAULT = 17


# ---------------------------------------------------------------------------
# protocol encoders — (level, duration_us) pairs; HIGH = IR burst
# ---------------------------------------------------------------------------

def nec_levels(address: int, command: int,
              gap_us: int = 40_000) -> list[tuple[bool, int]]:
    """NEC 32-bit: addr, ~addr, cmd, ~cmd — 9 ms lead, 4.5 ms space."""
    frame = (((address & 0xFF) << 24) | ((~address & 0xFF) << 16)
             | ((command & 0xFF) << 8) | (~command & 0xFF))
    levels = [(True, 9000), (False, 4500)]
    for i in reversed(range(32)):
        if (frame >> i) & 1:
            levels += [(True, 560), (False, 1690)]
        else:
            levels += [(True, 560), (False, 560)]
    levels += [(True, 560), (False, gap_us)]
    return levels


def samsung_levels(address: int, command: int,
                  gap_us: int = 40_000) -> list[tuple[bool, int]]:
    """Samsung32: 4.5 ms lead, 550/1600 bits (NEC-ish layout)."""
    frame = (((address & 0xFF) << 24) | ((~address & 0xFF) << 16)
             | ((command & 0xFF) << 8) | (~command & 0xFF))
    levels = [(True, 4500), (False, 4500)]
    for i in reversed(range(32)):
        if (frame >> i) & 1:
            levels += [(True, 550), (False, 1600)]
        else:
            levels += [(True, 550), (False, 550)]
    levels += [(True, 550), (False, gap_us)]
    return levels


def rc5_levels(toggle: int, address: int, command: int,
               te: int = 889) -> list[tuple[bool, int]]:
    """RC5 14-bit Manchester: 2 start bits, toggle, 5-bit addr, 6-bit cmd."""
    bits = [1, 1, toggle & 1] \
        + [(address >> i) & 1 for i in range(4, -1, -1)] \
        + [(command >> i) & 1 for i in range(5, -1, -1)]
    levels: list[tuple[bool, int]] = []
    for b in bits:
        if b:  # '1' = space then burst
            levels += [(False, te), (True, te)]
        else:
            levels += [(True, te), (False, te)]
    return levels


def sirc_levels(address: int, command: int,
                te: int = 600) -> list[tuple[bool, int]]:
    """Sony SIRC 12-bit (7 cmd + 5 addr, LSB first), 2.4 ms header."""
    bits = [(command >> i) & 1 for i in range(7)] \
        + [(address >> i) & 1 for i in range(5)]
    levels = [(True, 2400), (False, te)]
    for b in bits:
        if b:
            levels += [(True, 2 * te), (False, te)]
        else:
            levels += [(True, te), (False, te)]
    levels += [(False, 10_000)]
    return levels


# ---------------------------------------------------------------------------
# NEC decoder
# ---------------------------------------------------------------------------

def _near(value: int, target: int, tol: float) -> bool:
    return abs(value - target) <= target * tol


def decode_nec(levels) -> tuple[int, int] | None:
    """Decode a full NEC frame from (level, duration) pairs."""
    levels = list(levels)
    if len(levels) < 68:
        return None
    i = 0

    def take():
        nonlocal i
        lvl, dur = levels[i]
        i += 1
        return lvl, int(dur)

    lvl, dur = take()
    if not lvl or not _near(dur, 9000, 0.30):
        return None
    lvl, dur = take()
    if lvl or not _near(dur, 4500, 0.30):
        return None
    bits = 0
    for _ in range(32):
        lvl, dur = take()
        if not lvl or not _near(dur, 560, 0.40):
            return None
        lvl, dur = take()
        if lvl:
            return None
        bits = (bits << 1) | (1 if dur > 1100 else 0)
    addr = (bits >> 24) & 0xFF
    inv = (bits >> 16) & 0xFF
    cmd = (bits >> 8) & 0xFF
    icmd = bits & 0xFF
    if (addr ^ inv) != 0xFF or (cmd ^ icmd) != 0xFF:
        return None  # integrity check failed
    return addr, cmd

# ---------------------------------------------------------------------------
# carrier modulation + blaster
# ---------------------------------------------------------------------------

def modulate(levels, freq: int = CARRIER) -> list[tuple[bool, int]]:
    """Expand HIGH bursts into a `freq` Hz carrier (26 us period at 38 kHz)."""
    half = max(2, int(1_000_000 // freq // 2))
    out: list[tuple[bool, int]] = []
    for lvl, dur in levels:
        dur = int(dur)
        if not lvl:
            out.append((False, dur))
            continue
        sent = 0
        while sent < dur:
            chunk = min(half, dur - sent)
            out.append((True, chunk))
            sent += chunk
            if sent < dur:
                chunk = min(half, dur - sent)
                out.append((False, chunk))
                sent += chunk
    return out


class IrBlaster:
    """Sends IR level trains through a GPIO backend + IR LED."""

    def __init__(self, gpio, pin: int, carrier: int = CARRIER,
                 modulate_real: bool = True):
        self.gpio = gpio
        self.pin = pin
        self.carrier = carrier
        self.modulate_real = modulate_real

    def send(self, levels, count: int = 1) -> int:
        wave = levels
        if self.modulate_real and not getattr(self.gpio, "is_mock", False):
            wave = modulate(levels, self.carrier)
        for _ in range(max(1, count)):
            self.gpio.send_wave(self.pin, wave)
        return max(1, count)


# ---------------------------------------------------------------------------
# Flipper .ir raw files
# ---------------------------------------------------------------------------

def levels_to_durations(levels) -> list[int]:
    """[(level, us)] -> Flipper raw signed durations [9000, -4500, ...]."""
    return [d if lvl else -d for lvl, d in levels]


def durations_to_levels(durations) -> list[tuple[bool, int]]:
    return [(d > 0, abs(d)) for d in durations]


class IrFile:
    """Flipper IR raw file (`Type: raw`)."""

    def __init__(self, name: str = "UNNAMED", frequency: int = CARRIER,
                 duty: float = 0.33, data: list[int] | None = None):
        self.name = name
        self.frequency = frequency
        self.duty = duty
        self.data = list(data or [])

    @classmethod
    def from_levels(cls, levels, name: str = "UNNAMED",
                   frequency: int = CARRIER) -> "IrFile":
        return cls(name, frequency, 0.33, levels_to_durations(levels))

    def levels(self) -> list[tuple[bool, int]]:
        return durations_to_levels(self.data)

    def save(self, path: str) -> str:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("Filetype: Flipper IR file\n"
                     "Version: 1\n"
                     "#\n"
                     f"Name: {self.name}\n"
                     "Type: raw\n"
                     f"Frequency: {int(self.frequency)}\n"
                     f"Duty cycle: {self.duty:.6f}\n"
                     "Data: " + " ".join(str(d) for d in self.data) + "\n")
        return path

    @classmethod
    def load(cls, path: str) -> "IrFile":
        irf = cls()
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if ":" not in line or line.startswith("#"):
                    continue
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                if key == "Name":
                    irf.name = value
                elif key == "Frequency":
                    irf.frequency = int(value)
                elif key == "Duty cycle":
                    irf.duty = float(value)
                elif key == "Data":
                    irf.data = [int(d) for d in value.split()]
        return irf

