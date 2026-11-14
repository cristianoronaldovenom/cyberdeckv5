"""Read HTTPS *metadata* out of a capture — no keys, no decryption.

Encrypted traffic still leaks a lot: the SNI in the ClientHello, certificate
common names in the reply, and every DNS question asked just before. That is
enough to say what a client is doing even when ``wifi.extract`` has no PSK, and
it is the read-out a Pineapple user wants while the portal is up.

Also reports the plaintext half (HTTP hosts, credentials) through the extract
module, so one call covers both cases. Works on a pcap file from
``airodump-ng``, ``tcpdump`` or ``wifi.sniff``.
"""

from __future__ import annotations

import struct

from omni.wifi import extract, pcapread

__all__ = ["OID_CN", "cert_names", "report", "Frame", "scan"]

#: DER prefix of the X.509 commonName OID (06 03 55 04 03)
OID_CN = b"\x06\x03\x55\x04\x03"


class Frame:
    """One interesting observation."""

    def __init__(self, kind: str, value: str):
        self.kind = kind
        self.value = value

    def row(self) -> list[str]:
        return [self.kind, self.value]


def cert_names(blob: bytes, limit: int = 8) -> list[str]:
    """Common names inside a DER certificate, best effort.

    Walks each commonName OID, skips the DER tag/length pair and takes the
    following string. A certificate carries one CN per name, so the same walk
    yields both subject and SAN entries.
    """
    out: list[str] = []
    index = blob.find(OID_CN)
    while index != -1 and len(out) < limit:
        cursor = index + len(OID_CN)
        if cursor + 2 <= len(blob):
            tag, length = blob[cursor], blob[cursor + 1]
            start = cursor + 2
            # 0x0c UTF8String, 0x13 PrintableString, 0x16 IA5String
            if tag in (0x0C, 0x13, 0x16) and 3 < length < 200:
                name = blob[start:start + length]
                if b"." in name and all(32 < b < 127 for b in name):
                    text = name.decode("ascii", "replace")
                    if text not in out:
                        out.append(text)
        index = blob.find(OID_CN, cursor)
    return out


def scan(path: str, limit: int = 400) -> list[Frame]:
    """Every SNI / certificate name in the *unprotected* frames of a capture."""
    found: list[Frame] = []
    for frame in pcapread.read_frames(path):
        if len(found) >= limit:
            break
        payload = _payload(frame)
        if payload is None or payload[:1] != b"\x16":
            continue
        name = extract.parse_sni(payload)
        if name:
            found.append(Frame("sni", name))
        for cn in cert_names(payload):
            found.append(Frame("cert-cn", cn))
    return found


def _payload(frame: bytes) -> bytes | None:
    """TCP payload of a data frame that is *not* CCMP-protected."""
    if (frame[0] >> 2) & 0x03 != 0x02:               # data frames only
        return None
    if frame[1] & 0x40:                               # protected: needs a key
        return None
    inner = extract._inner(frame[pcapread._body_offset(frame):])
    if inner is None:
        return None
    proto, _src, _dst, payload = inner
    if proto != 6:
        return None
    tcp = extract._tcp(payload)
    return tcp[2] if tcp else None


def _dns(path: str) -> list[str]:
    """DNS questions from unprotected frames."""
    names: list[str] = []
    for frame in pcapread.read_frames(path):
        if (frame[0] >> 2) & 0x03 != 0x02 or frame[1] & 0x40:
            continue
        inner = extract._inner(frame[pcapread._body_offset(frame):])
        if inner is None or inner[0] != 17:
            continue
        udp = extract._udp(inner[3])
        if udp and 53 in (udp[0], udp[1]):
            names += extract.parse_dns(udp[2])
    return names


def report(path: str) -> dict:
    """SNI, certificate names and DNS for one capture.

    Protected captures yield nothing here — use ``wifi.extract`` with a key for
    those; this module is the keyless read-out.
    """
    frames = scan(path)
    sni = [f.value for f in frames if f.kind == "sni"]
    certs = [f.value for f in frames if f.kind == "cert-cn"]
    dns = sorted(set(_dns(path)))
    hosts = sorted(set(sni + certs + dns))
    return {
        "sni": sni,
        "cert_cn": certs,
        "dns": dns,
        "hosts": hosts,
        "deterministic": bool(hosts),
        "encrypted_frames": _protected_count(path),
    }


def _protected_count(path: str) -> int:
    """How many frames were skipped because they need a key."""
    total = 0
    try:
        for frame in pcapread.read_frames(path):
            if (frame[0] >> 2) & 0x03 == 0x02 and frame[1] & 0x40:
                total += 1
    except pcapread.PcapError:
        return 0
    return total
