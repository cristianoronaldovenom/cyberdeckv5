"""Shared helpers: frequency math, key reversal, TX-range policing."""

from __future__ import annotations

XTAL = 26_000_000  # CC1101 crystal

# Flipper / firmware standard sub-GHz frequencies — broad coverage across
# all regions (US 315, EU 433/868, AS 312/318/426, KR 920-ish, JP 310/312 ...)
COMMON_FREQUENCIES = [
    303_875_000, 307_800_000, 310_000_000, 312_000_000, 313_850_000,
    315_000_000, 318_000_000, 345_000_000, 348_000_000, 350_000_000,
    355_000_000, 390_000_000, 418_000_000, 426_750_000, 430_000_000,
    433_075_000, 433_220_000, 433_420_000, 433_920_000, 434_075_000,
    434_420_000, 434_775_000, 464_000_000, 480_000_000, 779_000_000,
    868_350_000, 868_950_000, 915_000_000, 925_000_000, 928_000_000,
    943_000_000, 950_000_000,
]

# bands where transmission is allowed (default + Unleashed extended ranges)
DEFAULT_TX_RANGES = [
    (300_000_000, 348_000_000),
    (387_000_000, 464_800_000),
    (779_000_000, 928_000_000),
]
EXTENDED_RANGES = DEFAULT_TX_RANGES + [
    (281_000_000, 361_000_000),
    (378_000_000, 481_000_000),
    (749_000_000, 962_000_000),
]


def frequency_to_registers(freq: int) -> tuple[int, int, int]:
    """Firmware-exact CC1101 FREQ2/1/0 math (truncated).

    value = freq * 0x10000 / 26 MHz, split into three bytes.
    """
    freq = int(freq)
    value = (freq << 16) // XTAL
    return (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF


def registers_to_frequency(f2: int, f1: int, f0: int) -> float:
    """Inverse of frequency_to_registers (real frequency in Hz)."""
    value = ((f2 & 0xFF) << 16) | ((f1 & 0xFF) << 8) | (f0 & 0xFF)
    return (value * XTAL) / 65536.0


def reverse_key(key: int, bits: int = 64) -> int:
    """Bit-reverse a key (KeeLoq decrypt uses the reversed encrypt key)."""
    out = 0
    for i in range(bits):
        out = (out << 1) | ((key >> i) & 1)
    return out


def is_tx_allowed(freq: int, extended: bool = False) -> bool:
    """True if freq is inside an allowed band."""
    ranges = EXTENDED_RANGES if extended else DEFAULT_TX_RANGES
    return any(lo <= freq <= hi for lo, hi in ranges)


def format_freq(freq: int) -> str:
    return f"{freq / 1e6:.3f} MHz"
