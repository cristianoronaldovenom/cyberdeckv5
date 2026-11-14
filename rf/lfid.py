"""125 kHz LF RFID — EM4100, the classic hotel/gate access-card format.

* EM4100 64-bit matrix codec (9 header bits, 10x(4 data + parity), 4
  column parity, stop bit) with Manchester edge stream for capture/decode
* RDM6300 UART reader (the cheap Pi-friendly 125 kHz module)
* Flipper-compatible `.rfid` key files
"""

from __future__ import annotations

import os

BIT_US = 512          # 64 RF cycles @ 125 kHz
HALF_US = BIT_US // 2  # Manchester half-bit
_WIEGAND_NONE = 26    # common facility+card Wiegand view of a 40-bit id


# ---------------------------------------------------------------------------
# EM4100 matrix codec
# ---------------------------------------------------------------------------

def em4100_bits(card_id: int) -> list[int]:
    """64 wire bits (MSB first) for a 40-bit EM4100 card id."""
    card_id &= 0xFFFFFFFFFF
    bits = [1] * 9
    col = [0, 0, 0, 0]
    for row in range(10):
        nib = (card_id >> (36 - 4 * row)) & 0xF
        parity = 0
        for j in range(4):
            b = (nib >> (3 - j)) & 1
            bits.append(b)
            col[j] ^= b
            parity ^= b
        bits.append(parity)
    bits += col
    bits.append(0)
    return bits[:64]


def em4100_id_from_bits(bits: list[int]) -> int | None:
    """Extract the 40-bit card id from 64 wire bits (parity-tolerant)."""
    if len(bits) < 64:
        return None
    if any(b != 1 for b in bits[:9]) or bits[63] != 0:
        return None
    card = 0
    for row in range(10):
        for j in range(4):
            card = (card << 1) | (1 if bits[9 + row * 5 + j] else 0)
    return card


def manchester_edges(bits: list[int],
                     half_us: int = HALF_US) -> list[tuple[bool, int]]:
    """'1' = LOW then HIGH half-bit, '0' = HIGH then LOW half-bit."""
    edges: list[tuple[bool, int]] = []
    for b in bits:
        if b:
            edges += [(False, half_us), (True, half_us)]
        else:
            edges += [(True, half_us), (False, half_us)]
    return edges


def decode_manchester_levels(levels) -> list[int]:
    """Pair up half-bit edges into bits; resyncs on bad pairs."""
    levels = list(levels)
    bits: list[int] = []
    i = 0
    while i + 1 < len(levels):
        l1, d1 = levels[i]
        l2, d2 = levels[i + 1]
        if bool(l1) != bool(l2) and d1 >= HALF_US * 0.5 and d2 >= HALF_US * 0.5:
            # '1' = LOW then HIGH half-bit, '0' = HIGH then LOW
            bits.append(1 if not l1 else 0)
            i += 2
        else:
            i += 1  # invalid pair -> resync one edge
    return bits


def decode_em4100_levels(levels) -> int | None:
    """Full capture path: edge stream -> 40-bit EM4100 id (or None)."""
    return em4100_id_from_bits(decode_manchester_levels(levels))


# ---------------------------------------------------------------------------
# Flipper .rfid key files
# ---------------------------------------------------------------------------

def save_rfid(path: str, card_id: int) -> str:
    """Write a Flipper-compatible EM4100 .rfid key file."""
    data = "".join(str(b) for b in em4100_bits(card_id))
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("Filetype: Flipper RFID Key\n"
                 "Version: 1\n"
                 "Key type: EM4100\n"
                 f"Data: {data}\n")
    return path


def load_rfid(path: str) -> int | None:
    """Read an EM4100 .rfid key file back into a 40-bit id."""
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip().lower().startswith("data:"):
                blob = line.split(":", 1)[1].strip()
                try:
                    bits = [int(c) for c in blob if c in "01"]
                except ValueError:
                    return None
                return em4100_id_from_bits(bits)
    return None


# ---------------------------------------------------------------------------
# RDM6300 UART reader (real hardware)
# ---------------------------------------------------------------------------

class Rdm6300:
    """RDM6300 125 kHz reader: 14-byte ASCII frames over 9600 baud UART."""

    def __init__(self, port: str | None = None, baud: int = 9600):
        self.ser = None
        if port:
            import serial  # pyserial, only needed for real hardware
            self.ser = serial.Serial(port, baud, timeout=1)

    def read_card(self, timeout: float = 3.0) -> int | None:
        """Blocking read; returns the 40-bit card id or None."""
        if self.ser is None:
            return None
        import time
        deadline = time.monotonic() + timeout
        buf = b""
        while time.monotonic() < deadline:
            buf += self.ser.read(64)
            while b"\x02" in buf and b"\x03" in buf:
                s = buf.index(b"\x02")
                e = buf.index(b"\x03")
                if e < s:
                    buf = buf[s + 1:]
                    continue
                frame = buf[s + 1:e]
                buf = buf[e + 1:]
                hexpart = bytes(c for c in frame
                                if chr(c) in "0123456789abcdefABCDEF")
                if len(hexpart) >= 10:
                    try:
                        return int(hexpart[:10], 16)
                    except ValueError:
                        continue
        return None

    def close(self):
        if self.ser is not None:
            self.ser.close()


def card_id_str(card_id: int) -> str:
    return f"{card_id & 0xFFFFFFFFFF:010X}"


def wiegand_view(card_id: int) -> tuple[int, int]:
    """(facility, card) as a 26-bit Wiegand would split the 40-bit id."""
    card_id &= 0xFFFFFFFFFF
    return (card_id >> 24) & 0xFF, card_id & 0xFFFFFF
