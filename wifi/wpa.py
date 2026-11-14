"""WPA2-PSK key hierarchy and handshake verification, in pure stdlib.

The mathematics of a PSK attack, with no external tool:

    PMK  = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32)
    PTK  = PRF-512(PMK, "Pairwise key expansion",
                   min(AP,STA) || max(AP,STA) || min(ANonce,SNonce) || max(...))
    MIC  = HMAC-<KDV hash>(KCK, EAPOL)[0:16]

A captured 4-way handshake pins SSID, both nonces and both MACs, so a candidate
passphrase is *proven* by recomputing the MIC and comparing. The KCK is the
first 16 bytes of the PTK; nothing else is needed to test a password.

Only passphrases of 8..63 printable ASCII bytes are legal WPA2 PSKs (a 64-char
hex string would be a raw PMK).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field

from omni.wifi.ccmp import hmac_compare

__all__ = ["Handshake", "pmk", "ptk", "verify", "valid_psk", "mic_for",
           "PTK_BITS", "KDV"]

#: PTK length per key descriptor version (bits): 1=TKIP, 2=CCMP, 3=AES-CMAC
PTK_BITS = {1: 512, 2: 512, 3: 512}
#: KDV -> (hash for the MIC, PTK bit length)
KDV = {1: (hashlib.md5, 512), 2: (hashlib.sha1, 512), 3: (hashlib.sha1, 512)}

ITERATIONS = 4096


def valid_psk(passphrase: str) -> bool:
    """WPA2 passphrase rule: 8..63 printable ASCII characters."""
    if not 8 <= len(passphrase) <= 63:
        return False
    return all(32 <= ord(ch) <= 126 for ch in passphrase)


def pmk(passphrase: str, ssid: bytes) -> bytes:
    """Derive the 256-bit PMK (PBKDF2-HMAC-SHA1, 4096 rounds)."""
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"), ssid,
                               ITERATIONS, 32)


def _prf(key: bytes, label: bytes, seed: bytes, bits: int) -> bytes:
    """WPA PRF-n: HMAC-SHA1 over label||0x00||seed||counter, concatenated."""
    need = (bits + 159) // 160
    out = b""
    for counter in range(1, need + 1):
        out += hmac.new(key, label + b"\x00" + seed + bytes([counter]),
                        hashlib.sha1).digest()
    return out[:bits // 8]


def ptk(pmk_bytes: bytes, ap: bytes, sta: bytes, a_nonce: bytes,
        s_nonce: bytes, bits: int = 512) -> bytes:
    """Derive the PTK; argument order in the seed is normalised by sort."""
    seed = (min(ap, sta) + max(ap, sta) + min(a_nonce, s_nonce)
            + max(a_nonce, s_nonce))
    return _prf(pmk_bytes, b"Pairwise key expansion", seed, bits)


def mic_for(eapol: bytes, kck: bytes, kdv: int = 2) -> bytes:
    """Compute the EAPOL MIC over the frame with its MIC field zeroed."""
    digest, _bits = KDV.get(kdv, KDV[2])
    return hmac.new(kck, eapol, digest).digest()[:16]


@dataclass
class Handshake:
    """Everything needed to test a passphrase against a capture."""

    ssid: bytes
    ap: bytes
    sta: bytes
    a_nonce: bytes
    s_nonce: bytes
    eapol: bytes
    mic: bytes
    kdv: int = 2
    replay_counter: int = 0
    bssid: str = ""
    source: str = ""
    extra: dict = field(default_factory=dict)

    def verify(self, passphrase: str) -> bool:
        """True when this passphrase reproduces the captured MIC."""
        if not valid_psk(passphrase):
            return False
        key = ptk(pmk(passphrase, self.ssid), self.ap, self.sta,
                  self.a_nonce, self.s_nonce, KDV.get(self.kdv, KDV[2])[1])
        # the MIC field itself must be zeroed before it is recomputed
        blank = bytearray(self.eapol)
        blank[81:97] = bytes(16)
        return hmac_compare(mic_for(bytes(blank), key[:16], self.kdv), self.mic)

    def describe(self) -> str:
        name = self.ssid.decode("utf-8", "replace") or "<hidden>"
        return (f"{name}  AP={_mac(self.ap)}  STA={_mac(self.sta)}  "
                f"kdv={self.kdv}  rc={self.replay_counter}")


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in raw)
