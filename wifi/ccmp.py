"""AES-128 + CCMP: the actual de-crypter, in pure stdlib Python.

Python's stdlib has no AES, which is why every other tool in this repo shells
out to aircrack-ng. This implements what is needed to turn a captured 802.11
frame back into plaintext once the PSK is known:

* AES-128 forward encryption (the S-box is derived, not a 256-byte table blob);
* CCM (counter + CBC-MAC) as used by WPA2-CCMP: tag generation/verification and
  CTR payload encryption/decryption.

Decryption order matters and is the reverse of encryption: CTR-decrypt the
payload first, *then* verify the tag over the recovered plaintext. A wrong key
survives CTR (it is just a keystream XOR) and is caught by the tag.
"""

from __future__ import annotations

__all__ = ["aes128_block", "cbc_mac", "ccmp_encrypt", "ccmp_decrypt",
           "ccmp_aad", "ccmp_nonce", "split_ccmp_body", "MIC_LEN", "expand_key"]

MIC_LEN = 8
BLOCK = 16

#: 802.11 FC masks for the AAD (Retry/PwrMgmt/MoreData vary per transmission)
_FC_MASK = (0x8F, 0xC7)


def _xtime(value: int) -> int:
    value <<= 1
    return (value ^ 0x1B) & 0xFF if value & 0x100 else value


def _mul(a: int, b: int) -> int:
    """GF(2^8) multiply."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        b >>= 1
        a = _xtime(a)
    return result


def _build_tables() -> tuple[list[int], list[int]]:
    """Derive the S-box and its inverse from the affine transform."""
    inverse = [0] * 256
    for value in range(1, 256):
        for candidate in range(1, 256):
            if _mul(value, candidate) == 1:
                inverse[value] = candidate
                break
    sbox, inv = [0] * 256, [0] * 256
    for value in range(256):
        inv_value = inverse[value]
        shifted = inv_value
        for _ in range(4):
            shifted = ((shifted << 1) | (shifted >> 7)) & 0xFF
            inv_value ^= shifted
        inv_value ^= 0x63
        sbox[value] = inv_value
        inv[sbox[value]] = value
    return sbox, inv


SBOX, INV_SBOX = _build_tables()


def expand_key(key: bytes) -> list[list[int]]:
    """AES-128 key schedule: 11 round keys of 16 bytes."""
    if len(key) != 16:
        raise ValueError("AES-128 needs a 16-byte key")
    words = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    rcon = 1
    for index in range(4, 44):
        temp = list(words[index - 1])
        if index % 4 == 0:
            temp = temp[1:] + temp[:1]                    # RotWord
            temp = [SBOX[b] for b in temp]                # SubWord
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        words.append([words[index - 4][i] ^ temp[i] for i in range(4)])
    return [sum(words[r * 4:r * 4 + 4], []) for r in range(11)]


def aes128_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """Encrypt one 16-byte block."""
    if len(block) != BLOCK:
        raise ValueError("AES block must be 16 bytes")
    # AES byte order: in[4*col + row]; the first four bytes are column 0
    state = [[block[col * 4 + row] for row in range(4)] for col in range(4)]

    def add_round_key(keys: list[int]) -> None:
        for col in range(4):
            for row in range(4):
                state[col][row] ^= keys[col * 4 + row]

    def sub_bytes() -> None:
        for col in range(4):
            for row in range(4):
                state[col][row] = SBOX[state[col][row]]

    def shift_rows() -> None:
        for row in range(1, 4):
            column = [state[col][row] for col in range(4)]
            column = column[row:] + column[:row]
            for col in range(4):
                state[col][row] = column[col]

    def mix_columns() -> None:
        for col in range(4):
            a = state[col]
            total = a[0] ^ a[1] ^ a[2] ^ a[3]
            first = a[0]
            a[0] ^= total ^ _mul(a[0] ^ a[1], 2)
            a[1] ^= total ^ _mul(a[1] ^ a[2], 2)
            a[2] ^= total ^ _mul(a[2] ^ a[3], 2)
            a[3] ^= total ^ _mul(a[3] ^ first, 2)

    add_round_key(round_keys[0])
    for rnd in range(1, 10):
        sub_bytes()
        shift_rows()
        mix_columns()
        add_round_key(round_keys[rnd])
    sub_bytes()
    shift_rows()
    add_round_key(round_keys[10])
    # state is column-major: byte i of the block is state[i]
    return bytes(state[col][row] for col in range(4) for row in range(4))


def cbc_mac(round_keys: list[list[int]], data: bytes) -> bytes:
    """CCM's integrity primitive: CBC-MAC with a zero IV, zero-padded."""
    chain = bytes(BLOCK)
    for offset in range(0, len(data), BLOCK):
        piece = data[offset:offset + BLOCK]
        if len(piece) < BLOCK:
            piece = piece + bytes(BLOCK - len(piece))
        chain = aes128_block(bytes(a ^ b for a, b in zip(chain, piece)),
                             round_keys)
    return chain


def _counter_block(nonce: bytes, counter: int) -> bytes:
    # L = 2, so the counter block is [L-1] || nonce(13) || counter(2)
    return bytes([1]) + nonce + counter.to_bytes(2, "big")


def _keystream(round_keys: list[list[int]], nonce: bytes, length: int,
               start: int = 1) -> bytes:
    out = bytearray()
    counter = start
    while len(out) < length:
        out += aes128_block(_counter_block(nonce, counter), round_keys)
        counter += 1
    return bytes(out[:length])


def _b0(nonce: bytes, msg_len: int, aad: bytes) -> bytes:
    # flags: Adata(0x40) | M'=(8-2)/2 << 3 | L-1=1
    flags = (0x40 if aad else 0x00) | (((MIC_LEN - 2) // 2) << 3) | 0x01
    return bytes([flags]) + nonce + msg_len.to_bytes(2, "big")


def _tag(round_keys: list[list[int]], nonce: bytes, aad: bytes,
         payload: bytes) -> bytes:
    mac_input = _b0(nonce, len(payload), aad)
    if aad:
        mac_input += len(aad).to_bytes(2, "big") + aad
    raw = cbc_mac(round_keys, mac_input + payload)[:MIC_LEN]
    masked = aes128_block(_counter_block(nonce, 0), round_keys)[:MIC_LEN]
    return bytes(a ^ b for a, b in zip(raw, masked))


def ccmp_encrypt(payload: bytes, key: bytes, nonce: bytes,
                 aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt a payload and return (ciphertext, mic)."""
    round_keys = expand_key(key)
    cipher = bytes(a ^ b for a, b in
                   zip(payload, _keystream(round_keys, nonce, len(payload))))
    return cipher, _tag(round_keys, nonce, aad, payload)


def ccmp_decrypt(cipher: bytes, key: bytes, nonce: bytes, aad: bytes,
                 mic: bytes | None = None) -> bytes:
    """Decrypt, then verify the tag. Raises ValueError on a bad MIC."""
    if len(nonce) != 13:
        raise ValueError("CCMP nonce must be 13 bytes")
    if mic is None:
        if len(cipher) < MIC_LEN:
            raise ValueError("frame too short to carry a MIC")
        cipher, mic = cipher[:-MIC_LEN], cipher[-MIC_LEN:]
    round_keys = expand_key(key)
    plain = bytes(a ^ b for a, b in
                  zip(cipher, _keystream(round_keys, nonce, len(cipher))))
    if not hmac_compare(_tag(round_keys, nonce, aad, plain), mic):
        raise ValueError("MIC mismatch — wrong key or corrupt frame")
    return plain


def hmac_compare(left: bytes, right: bytes) -> bool:
    """Constant-time-ish compare."""
    if len(left) != len(right):
        return False
    diff = 0
    for a, b in zip(left, right):
        diff |= a ^ b
    return diff == 0


def ccmp_aad(header: bytes) -> bytes:
    """Build the CCMP AAD from an 802.11 MAC header.

    Two FC bits are masked because they legitimately change between
    retransmissions (Retry, PwrMgmt, MoreData); everything else — addresses,
    sequence control, and any A4/QoS control — is covered verbatim.
    """
    if len(header) < 24:
        raise ValueError("short MAC header")
    fc1 = header[1]
    to_ds, from_ds = fc1 & 0x01, fc1 & 0x02
    subtype = header[0] >> 4
    aad = bytearray([header[0] & _FC_MASK[0], fc1 & _FC_MASK[1]])
    aad += header[4:22]                        # A1, A2, A3, sequence control
    if to_ds and from_ds:
        if len(header) < 30:
            raise ValueError("4-address frame truncated")
        aad += header[22:30]                   # A4
        offset = 30
    else:
        offset = 24
    if subtype & 0x08:                         # QoS data carries a control field
        aad += header[offset:offset + 2]
    return bytes(aad)


def ccmp_nonce(priority: int, transmitter: bytes, pn: bytes) -> bytes:
    """CCMP nonce: priority octet, A2 transmitter, then the 48-bit PN."""
    if len(transmitter) != 6 or len(pn) != 6:
        raise ValueError("transmitter and PN must be 6 bytes each")
    return bytes([priority & 0x0F]) + transmitter + pn


def split_ccmp_body(body: bytes) -> tuple[bytes, bytes, int]:
    """Split a protected frame body into (pn, ciphertext_with_mic, key_id).

    The 8-octet CCMP header is: PN0, PN1, Rsvd, KeyID|ExtIV, PN2..PN5.
    """
    if len(body) < 8 + MIC_LEN:
        raise ValueError("frame too short for CCMP")
    pn = bytes([body[0], body[1], body[4], body[5], body[6], body[7]])
    key_id = (body[3] >> 6) & 0x03
    if not body[3] & 0x20:
        raise ValueError("ExtIV bit clear — not a CCMP frame")
    return pn, body[8:], key_id

