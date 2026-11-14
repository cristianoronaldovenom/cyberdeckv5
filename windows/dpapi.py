"""Windows DPAPI unwrapping.

Two modes:

* **live** — call ``CryptUnprotectData`` through ``ctypes`` (must run on the
  same Windows account that encrypted the blob). Pure stdlib.
* **offline** — derive the user master key from a password + SID and decrypt
  with AES-256-CBC. Needs ``cryptography`` (or ``pycryptodome``) for the AES
  primitive; both are optional and only imported in that path.
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import struct

__all__ = ["DpapiError", "is_windows", "unprotect", "master_key_from_password",
           "decrypt_with_master_key"]


class DpapiError(RuntimeError):
    """DPAPI blob could not be unwrapped."""


def is_windows() -> bool:
    return os.name == "nt"


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def unprotect(blob: bytes) -> bytes:
    """Decrypt a live DPAPI blob for the current user (Windows only)."""
    if not is_windows():
        raise DpapiError("live DPAPI needs Windows; use the offline path")
    buffer_in = ctypes.create_string_buffer(blob, len(blob))
    data_in = _DataBlob(len(blob), ctypes.cast(buffer_in, ctypes.POINTER(ctypes.c_char)))
    data_out = _DataBlob()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(data_in), None, None, None, None, 0, ctypes.byref(data_out))
    if not ok:
        raise DpapiError(f"CryptUnprotectData failed: {ctypes.GetLastError()}")
    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(data_out.pbData)


# ---------------------------------------------------------------------------
# offline path
# ---------------------------------------------------------------------------

def _aes_cbc_decrypt(key: bytes, iv: bytes, payload: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return dec.update(payload) + dec.finalize()
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES  # type: ignore
        return AES.new(key, AES.MODE_CBC, iv).decrypt(payload)
    except ImportError:
        raise DpapiError(
            "offline DPAPI needs AES — pip install cryptography") from None


def _sid_bytes(sid: str) -> bytes:
    """Pack a ``S-1-5-21-...`` string into its binary form."""
    parts = [int(p) for p in sid.split("-")[1:]]
    revision, count, authority = parts[0], parts[1], parts[2]
    subs = parts[3:]
    raw = struct.pack("<BB", revision, count) + authority.to_bytes(6, "big")
    for sub in subs:
        raw += struct.pack("<I", sub)
    return raw


def master_key_from_password(password: str, sid: str, *, rounds: int = 240_000,
                             entropy: bytes = b"") -> tuple[bytes, bytes, bytes]:
    """Rebuild (key, iv, hmac_key) from a Windows password + SID.

    Mirrors the DPAPI SHA-512 chain: SHA512(SHA512(password_utf16) + salt) is
    stretched ``rounds`` times before being split into key material.
    """
    salt = _sid_bytes(sid) + entropy
    derived = hashlib.sha512((password.encode("utf-16-le"))).digest()
    derived = hashlib.sha512(derived + salt).digest()
    for _ in range(rounds):
        derived = hashlib.sha512(derived).digest()
    blob = hashlib.sha512(derived + salt).digest()
    return blob[:32], blob[32:48], blob[48:80]


def decrypt_with_master_key(master_key: bytes, blob: bytes) -> bytes:
    """Unwrap a DPAPI blob that was protected with ``master_key``.

    ``blob`` is the base64-decoded ``encrypted_key``/``data`` field as stored in
    Chrome's ``Local State`` and ``Login Data`` databases.
    """
    # 5.0 DPAPI blob: len(4) ver(4) guid(16) flags(4) desc_len(4) desc
    offset = 4 + 4 + 16 + 4
    desc_len = struct.unpack_from("<I", blob, offset)[0]
    offset += 4 + desc_len
    offset += 4  # crypto alg id
    key_len = struct.unpack_from("<I", blob, offset)[0]
    offset += 4 + key_len
    iv_len = struct.unpack_from("<I", blob, offset)[0]
    offset += 4
    iv = blob[offset:offset + iv_len]
    offset += iv_len
    payload = blob[offset + 4:]
    return _aes_cbc_decrypt(master_key, iv.rjust(16, b"\0")[:16], payload)


def chrome_master_key(local_state_path: str, password: str | None = None,
                      sid: str | None = None) -> list[dict]:
    """Return the browser master keys, unwrapped when a password is supplied."""
    with open(local_state_path, "r", encoding="utf-8") as fh:
        state = json.load(fh)
    raw = base64.b64decode(state["os_crypt"]["encrypted_key"])
    if raw[:5] == b"DPAPI":
        raw = raw[5:]
    out = []
    for entry in ("encrypted_key", "encrypted_key_v20"):
        pass
    if password and sid:
        key, _, _ = master_key_from_password(password, sid)
        out.append({"method": "offline", "key": decrypt_with_master_key(key, raw)})
    elif is_windows():
        out.append({"method": "dpapi", "key": unprotect(raw)})
    return out
