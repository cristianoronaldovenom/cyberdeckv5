"""iButton / 1-Wire — DS1990A "Dallas" touch keys (intercoms, gates).

The DS1990A is 8 bytes: family 0x01 + 48-bit serial + Dallas CRC8.
Flipper `.ibtn` files are read/written 1:1.
"""

from __future__ import annotations

import os

FAMILY_DS1990A = 0x01


def crc8(data: bytes) -> int:
    """Dallas/Maxim CRC8 (poly 0x31, init 0, LSB-first)."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc >> 1) ^ 0x8C) if (crc & 1) else (crc >> 1)
    return crc


def ds1990a_key(serial48: int) -> bytes:
    """Build a valid DS1990A ROM: 01 <48-bit serial> <CRC8>."""
    serial48 &= 0xFFFFFFFFFFFF
    rom = bytes([FAMILY_DS1990A]) + serial48.to_bytes(6, "big")
    return rom + bytes([crc8(rom)])


def parse_key(text: str) -> bytes | None:
    """Parse '01:123456789ABC:CD' or raw hex into 8 bytes (CRC checked)."""
    text = text.strip()
    if ":" in text:
        parts = text.split(":")
        if len(parts) != 3:
            return None
        try:
            family = int(parts[0], 16)
            serial = int(parts[1], 16)
            crc = int(parts[2], 16)
        except ValueError:
            return None
        rom = bytes([family]) + serial.to_bytes(6, "big")
        if crc8(rom) != crc:
            return None
        return rom + bytes([crc])
    hexpart = text.replace(" ", "")
    if len(hexpart) != 16:
        return None
    try:
        rom = bytes.fromhex(hexpart)
    except ValueError:
        return None
    if crc8(rom[:7]) != rom[7]:
        return None
    return rom


def key_str(rom: bytes) -> str:
    serial = int.from_bytes(rom[1:7], "big")
    return f"{rom[0]:02X}:{serial:012X}:{rom[7]:02X}"


class IbtnFile:
    """Flipper iButton file (`Device type: DS1990A`)."""

    def __init__(self, rom: bytes | None = None):
        self.rom = bytes(rom or ds1990a_key(0))

    def save(self, path: str) -> str:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("Filetype: Flipper iButton file\n"
                     "Version: 1\n"
                     "Device type: DS1990A\n"
                     "Data: " + " ".join(f"{b:02X}" for b in self.rom) + "\n")
        return path

    @classmethod
    def load(cls, path: str) -> "IbtnFile":
        rom = None
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip().startswith("Data:"):
                    blob = line.split(":", 1)[1].strip()
                    rom = bytes.fromhex(blob.replace(" ", ""))
                    break
        return cls(rom)

    def valid(self) -> bool:
        return len(self.rom) == 8 and crc8(self.rom[:7]) == self.rom[7]
