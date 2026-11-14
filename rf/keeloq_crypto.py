"""KeeLoq crypto — firmware-exact port of keeloq_common.c.

Cipher: 528-round NLFSR with NLF 0x3A5C742E, exactly the taps/bit order the
Flipper firmware uses, so manufacturer keys from the community databases
identify real transmitters. Learning types: simple, normal, secure,
magic_xor_type1 and magic_serial_type1/2/3.
"""

from __future__ import annotations

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
NLF = 0x3A5C742E
ROUNDS = 528


def _bit(x: int, n: int) -> int:
    return (x >> n) & 1


def _g5(x: int, a: int, b: int, c: int, d: int, e: int) -> int:
    return (_bit(x, a) + _bit(x, b) * 2 + _bit(x, c) * 4
            + _bit(x, d) * 8 + _bit(x, e) * 16)


def keeloq_encrypt(data: int, key: int) -> int:
    """Simple Learning encrypt (firmware-exact)."""
    x = data & MASK32
    key &= MASK64
    for r in range(ROUNDS):
        nb = (_bit(x, 0) ^ _bit(x, 16) ^ _bit(key, r & 63)
              ^ _bit(NLF, _g5(x, 1, 9, 20, 26, 31)))
        x = ((x >> 1) ^ (nb << 31)) & MASK32
    return x


def keeloq_decrypt(data: int, key: int) -> int:
    """Simple Learning decrypt (firmware-exact inverse)."""
    x = data & MASK32
    key &= MASK64
    for r in range(ROUNDS):
        nb = (_bit(x, 31) ^ _bit(x, 15) ^ _bit(key, (15 - r) & 63)
              ^ _bit(NLF, _g5(x, 0, 8, 19, 25, 30)))
        x = ((x << 1) ^ nb) & MASK32
    return x


# ---------------------------------------------------------------------------
# learning types (all ports of subghz_protocol_keeloq_common_*)
# ---------------------------------------------------------------------------

def normal_learning(serial: int, master_key: int) -> int:
    """Normal Learning: two decrypts of the serial with markers 0x2/0x6."""
    serial &= 0x0FFFFFFF
    k1 = keeloq_decrypt(serial | 0x20000000, master_key)
    k2 = keeloq_decrypt(serial | 0x60000000, master_key)
    return ((k2 & MASK32) << 32) | (k1 & MASK32)


def secure_learning(serial: int, seed: int, master_key: int) -> int:
    """Secure Learning: decrypt(serial) || decrypt(seed)."""
    k1 = keeloq_decrypt(serial & 0x0FFFFFFF, master_key)
    k2 = keeloq_decrypt(seed & MASK32, master_key)
    return ((k1 & MASK32) << 32) | (k2 & MASK32)


def magic_xor_type1_learning(serial: int, xor_key: int) -> int:
    """Magic_xor_type1 Learning."""
    serial &= 0x0FFFFFFF
    return ((((serial & MASK32) << 32) | (serial & MASK32)) ^ xor_key) & MASK64


def magic_serial_type1_learning(serial: int, man: int) -> int:
    serial &= 0x0FFFFFFF
    return ((man & MASK32)
            | ((serial & MASK64) << 40)
            | ((((serial & 0xFF) + ((serial >> 8) & 0xFF)) & 0xFF) << 32))


def magic_serial_type2_learning(btn_serial: int, man: int) -> int:
    p = btn_serial & MASK32
    return ((man & 0xFFFFFFFF0000FFFF)
            | ((p & 0xFF) << 56) | (((p >> 8) & 0xFF) << 48)
            | (((p >> 16) & 0xFF) << 40) | (((p >> 24) & 0xFF) << 32))


def magic_serial_type3_learning(serial: int, man: int) -> int:
    return ((man & 0xFFFFFFFFFF000000) | (serial & 0xFFFFFF)) & MASK64


# legacy aliases
magic_xor_learning = magic_xor_type1_learning


# ---------------------------------------------------------------------------
# frame helpers
# ---------------------------------------------------------------------------

def parse_fix(fix: int) -> tuple[int, int]:
    """Split the FIX part into (button nibble, 28-bit serial)."""
    fix &= MASK32
    return (fix >> 28) & 0xF, fix & 0x0FFFFFFF


def parse_decrypt(dec: int) -> tuple[int, int, int]:
    """Split a decrypted hopping word into (btn, serial10, counter)."""
    dec &= MASK32
    return (dec >> 28) & 0xF, (dec >> 16) & 0x3FF, dec & 0xFFFF


def join_frame(fix: int, hop: int) -> int:
    return ((fix & MASK32) << 32) | (hop & MASK32)


def split_frame(frame: int) -> tuple[int, int]:
    frame &= MASK64
    return (frame >> 32) & MASK32, frame & MASK32
