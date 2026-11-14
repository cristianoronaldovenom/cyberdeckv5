"""Firmware-exact CC1101 radio presets (register-for-register ports of the
Flipper's furi_hal_subghz configurations)."""

from __future__ import annotations

from omni.rf.util import frequency_to_registers  # noqa: F401  (re-export)


class Preset:
    """A named CC1101 register configuration + PATABLE."""

    def __init__(self, name: str, short: str, modulation: str,
                 registers: dict[int, int], patable: list[int]):
        self.name = name
        self.short = short
        self.modulation = modulation
        self.registers = dict(registers)
        self.patable = list(patable) + [0] * (8 - len(patable))

    def __repr__(self) -> str:
        return f"<Preset {self.short} {self.modulation}>"


def _ook(bw_reg: int) -> dict[int, int]:
    """Common OOK/ASK async-serial registers; MDMCFG4 selects RX BW."""
    return {
        0x02: 0x0D,  # IOCFG0: async serial data (GDO0)
        0x03: 0x47,  # FIFOTHR
        0x07: 0x04,  # PKTCTRL1
        0x08: 0x32,  # PKTCTRL0
        0x0B: 0x06,  # FSCTRL1
        0x10: bw_reg,  # MDMCFG4 (RX bandwidth)
        0x11: 0x32,  # MDMCFG3
        0x12: 0x30,  # MDMCFG2: ASK/OOK
        0x13: 0x22,  # MDMCFG1
        0x14: 0xF8,  # MDMCFG0
        0x17: 0x0E,  # MCSM1
        0x18: 0x1C,  # MCSM0
        0x19: 0x16,  # FOCCFG
        0x1B: 0x43,  # AGCCTRL2
        0x1C: 0x40,  # AGCCTRL1
        0x1D: 0x91,  # AGCCTRL0
        0x21: 0x56,  # FREND1
        0x22: 0x10,  # FREND0
        0x23: 0xA9,  # FSCAL3
        0x24: 0x0A,  # FSCAL2
        0x25: 0x00,  # FSCAL1
        0x26: 0x11,  # FSCAL0
    }


def _fsk(deviatn: int, mdmcfg2: int = 0x04) -> dict[int, int]:
    """Common 2-FSK async-serial registers; DEVIATN selects deviation."""
    regs = _ook(0x17)
    regs[0x12] = mdmcfg2  # MDMCFG2: 2-FSK / GFSK / MSK
    regs[0x15] = deviatn  # DEVIATN
    regs[0x16] = 0x07      # MCSM2
    return regs


_OOK_PATABLE = [0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
_FSK_PATABLE = [0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00]

AM650 = Preset("FuriHalSubGhzPresetOok650Async", "AM650", "ASK/OOK",
              _ook(0x17), _OOK_PATABLE)          # 650 kHz RX BW
AM270 = Preset("FuriHalSubGhzPresetOok270Async", "AM270", "ASK/OOK",
              _ook(0x67), _OOK_PATABLE)          # 270 kHz RX BW
FM238 = Preset("FuriHalSubGhzPreset2FSKDev238Async", "FM238", "2-FSK",
               _fsk(0x23), _FSK_PATABLE)          # 25.4 kHz deviation
FM476 = Preset("FuriHalSubGhzPreset2FSKDev476Async", "FM476", "2-FSK",
               _fsk(0x47), _FSK_PATABLE)          # 47.6 kHz deviation (Kia/Hyundai)
FM120 = Preset("FuriHalSubGhzPreset2FSKDev120Async", "FM120", "2-FSK",
               _fsk(0x35), _FSK_PATABLE)          # ~120 kHz deviation
MSK99 = Preset("FuriHalSubGhzPresetMSK99Async", "MSK99", "MSK",
                _fsk(0x00, 0x73), _FSK_PATABLE)   # MSK 99.97 kBaud
GFSK9 = Preset("FuriHalSubGhzPresetGFSK9Async", "GFSK9", "GFSK",
               _fsk(0x34, 0x10), _FSK_PATABLE)    # GFSK 9.999 kBaud

PRESETS: dict[str, Preset] = {
    p.short: p for p in (AM650, AM270, FM238, FM476, FM120, MSK99, GFSK9)
}

_FULL_NAME_TO_PRESET = {p.name: p for p in PRESETS.values()}


def default_preset() -> Preset:
    return AM650


def preset_by_name(name: str | None = None) -> Preset:
    """Resolve a preset by short name, full Flipper name, or default."""
    if name is None:
        return default_preset()
    if name in PRESETS:
        return PRESETS[name]
    p = _FULL_NAME_TO_PRESET.get(name)
    if p is not None:
        return p
    for p_ in PRESETS.values():
        if p_.name == name or p_.short == name:
            return p_
    return default_preset()


def custom_preset_from_bytes(blob: list[int]) -> Preset:
    """Parse a Flipper custom-preset byte blob.

    reg/val pairs until the 00 00 terminator, then 8 PATABLE bytes.
    """
    registers: dict[int, int] = {}
    i = 0
    while i + 1 < len(blob):
        addr, val = blob[i], blob[i + 1]
        if addr == 0 and val == 0:
            i += 2
            break
        registers[addr] = val
        i += 2
    patable = list(blob[i:i + 8])
    return Preset("FuriHalSubGhzPresetCustom", "CUSTOM", "custom",
                 registers, patable)
