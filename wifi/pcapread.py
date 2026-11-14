"""Read 802.11 frames (and, live, L3 frames) out of a pcap.

Everything here is stdlib ``struct`` work — no tshark, no tcpdump, no scapy.
Supports classic libpcap files (what airodump-ng writes) with a radiotap or
bare 802.11 link type; pcapng is not supported and is rejected clearly.

The same parsers run on a *stream* (:class:`Reader`), because ``tcpdump -w -``
hands the sniffer a live capture rather than a file, and on an AP interface
that stream is Ethernet / Linux-cooked rather than 802.11 — both shapes reach
:func:`network_payload`.

The point is to reach a :class:`omni.wifi.wpa.Handshake`, which pins the SSID,
both nonces and both MACs so a candidate passphrase can be proven locally.
"""

from __future__ import annotations

import struct

from omni.wifi.wpa import Handshake

__all__ = ["PcapError", "read_frames", "find_handshakes", "data_frames",
           "ssid_map", "ssid_of", "addresses", "eapol_key", "ipv4", "llc_ipv4",
           "network_payload", "parse_header", "strip_radiotap", "Reader",
           "body_offset", "EAPOL_SNAP", "LINKTYPE_80211", "LINKTYPE_RADIOTAP",
           "LINKTYPE_ETHERNET", "LINKTYPE_LINUX_SLL", "LINKTYPE_NULL",
           "WIFI_LINKTYPES"]

#: LLC/SNAP prefix on an EAPOL frame
EAPOL_SNAP = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
#: MIC offset inside an EAPOL-Key body, and its length
MIC_OFFSET, MIC_LEN = 81, 16

LINKTYPE_80211 = 105
LINKTYPE_RADIOTAP = 127
#: the L3 link types a live ``tcpdump`` on an AP interface writes
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113

#: link types whose frames carry 802.11 (and therefore radiotap)
WIFI_LINKTYPES = (LINKTYPE_80211, LINKTYPE_RADIOTAP)


class PcapError(RuntimeError):
    """The capture is unreadable or unsupported."""


def parse_header(header: bytes) -> tuple[str, int]:
    """(endian, linktype) from a 24-byte classic pcap header.

    Shared by the file readers and the live parser, so a wrong magic is
    rejected the same way whichever side of the wire it arrived on.
    """
    if len(header) < 24:
        raise PcapError("file too short to be a pcap")
    magic = header[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        raise PcapError("pcapng is not supported — convert with "
                        "'editcap -F pcap in.pcapng out.pcap'")
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise PcapError(f"unknown pcap magic {magic.hex()}")
    return endian, struct.unpack(endian + "I", header[20:24])[0]


def strip_radiotap(data: bytes) -> bytes:
    """Drop the radiotap header (its 16-bit length field says how much)."""
    if len(data) < 4:
        return b""
    skip = struct.unpack("<H", data[2:4])[0]
    return data[skip:]


class Reader:
    """Incremental pcap parser: feed bytes as they arrive, get whole frames.

    A live capture is a stream, not a file: ``tcpdump -w -`` writes the
    24-byte header, then one 16-byte record header per packet, and the record
    can be split across two reads. Keeping the remainder in a buffer is what
    lets the sniffer decode without waiting for EOF.
    """

    def __init__(self) -> None:
        self._buf = b""
        self._started = False
        self.endian = "<"
        self.linktype = -1
        self.frames = 0

    @property
    def started(self) -> bool:
        return self._started

    def feed(self, chunk: bytes) -> list[bytes]:
        """Append ``chunk`` and return every frame that is now complete."""
        self._buf += chunk
        out: list[bytes] = []
        if not self._started:
            if len(self._buf) < 24:
                return out
            self.endian, self.linktype = parse_header(self._buf[:24])
            self._buf = self._buf[24:]
            self._started = True
        while len(self._buf) >= 16:
            captured = struct.unpack(self.endian + "I", self._buf[8:12])[0]
            if len(self._buf) < 16 + captured:
                break
            out.append(self._buf[16:16 + captured])
            self._buf = self._buf[16 + captured:]
            self.frames += 1
        return out


def _open_reader(path: str) -> tuple[Reader, object]:
    """(reader primed with the global header, open file object)."""
    fh = open(path, "rb")
    reader = Reader()
    reader.feed(fh.read(24))
    if not reader.started:
        fh.close()
        raise PcapError("file too short to be a pcap")
    return reader, fh


def read_frames(path: str):
    """Yield raw 802.11 frames (radiotap stripped) from a classic pcap."""
    reader, fh = _open_reader(path)
    try:
        if reader.linktype not in WIFI_LINKTYPES:
            raise PcapError(f"link type {reader.linktype} is not 802.11")
        while True:
            chunk = fh.read(65536)
            if not chunk:
                return
            for data in reader.feed(chunk):
                if reader.linktype == LINKTYPE_RADIOTAP:
                    data = strip_radiotap(data)
                if len(data) >= 24:
                    yield data
    finally:
        fh.close()


def _fc(frame: bytes) -> tuple[int, int]:
    return frame[0], frame[1]


def _is_data(frame: bytes) -> bool:
    return (_fc(frame)[0] >> 2) & 0x03 == 0x02


def _is_protected(frame: bytes) -> bool:
    return bool(_fc(frame)[1] & 0x40)


def _body_offset(frame: bytes) -> int:
    """Start of the frame body / LLC for a data frame."""
    fc1 = _fc(frame)[1]
    offset = 24
    if fc1 & 0x03 == 0x03:          # ToDS + FromDS carries a 4th address
        offset += 6
    if _fc(frame)[0] >> 4 & 0x08:   # QoS data carries a control field
        offset += 2
    return offset


#: public name — the live sniffer needs it to find the CCMP body
body_offset = _body_offset


def ssid_of(frame: bytes) -> tuple[bytes, bytes] | None:
    """(bssid, ssid) when the frame is a beacon or a probe response."""
    fc0 = frame[0]
    if (fc0 >> 2) & 0x03 != 0x00:        # management frames only
        return None
    if fc0 >> 4 not in (0x08, 0x05):     # beacon, probe response
        return None
    if len(frame) < 38:
        return None
    bssid = frame[16:22]
    body = frame[36:]            # after the 24-byte header + 12 fixed fields
    # walk the tag tuples; tag 0 is the SSID
    index = 0
    while index + 2 <= len(body):
        tag, length = body[index], body[index + 1]
        if tag == 0:
            return bssid, body[index + 2:index + 2 + length]
        index += 2 + length
    return None


def ssid_map(path: str) -> dict[bytes, bytes]:
    """BSSID -> SSID from beacons and probe responses."""
    found: dict[bytes, bytes] = {}
    for frame in read_frames(path):
        pair = ssid_of(frame)
        if pair is not None:
            found.setdefault(pair[0], pair[1])
    return found


def addresses(frame: bytes) -> tuple[bytes, bytes] | None:
    """(ap, station) for a data frame, from the ToDS/FromDS bits.

    A1 is the receiver, A2 the transmitter: to the AP the BSSID is A1 and the
    station A2, from the AP it is the other way round.
    """
    fc1 = frame[1]
    to_ds, from_ds = fc1 & 0x01, fc1 & 0x02
    if to_ds and not from_ds:
        return frame[4:10], frame[10:16]         # A1=BSSID, A2=SA
    if from_ds and not to_ds:
        return frame[10:16], frame[4:10]         # A2=BSSID, A1=DA
    return None


def eapol_key(frame: bytes) -> bytes | None:
    """Return the EAPOL-Key body when the frame is a protected EAPOL."""
    if not _is_data(frame) or len(frame) < 24:
        return None
    body = frame[_body_offset(frame):]
    if not body.startswith(EAPOL_SNAP):
        return None
    eapol = body[len(EAPOL_SNAP):]
    if len(eapol) < MIC_OFFSET + MIC_LEN or eapol[1] != 0x03:
        return None
    return eapol


#: historical name, kept so older callers keep working
_eapol_key = eapol_key


def ipv4(packet: bytes) -> tuple[int, bytes, bytes, bytes] | None:
    """(proto, src, dst, payload) for an IPv4 packet."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header_len = (packet[0] & 0x0F) * 4
    proto = packet[9]
    if proto not in (6, 17) or len(packet) < header_len + 4:
        return None
    return proto, packet[12:16], packet[16:20], packet[header_len:]


def llc_ipv4(body: bytes) -> tuple[int, bytes, bytes, bytes] | None:
    """Same, for the LLC/SNAP body of an 802.11 data frame."""
    if len(body) < 8 or not body.startswith(b"\xaa\xaa\x03\x00\x00\x00"):
        return None
    if struct.unpack(">H", body[6:8])[0] != 0x0800:
        return None
    return ipv4(body[8:])


#: link-layer header length and ethertype offset per supported L3 link type
_L3_HEADERS = {LINKTYPE_ETHERNET: (14, 12), LINKTYPE_LINUX_SLL: (16, 14)}


def network_payload(linktype: int,
                    data: bytes) -> tuple[int, bytes, bytes, bytes] | None:
    """(proto, src, dst, payload) for any link type OMNI can read.

    This is what a live capture actually delivers: 802.11 (with radiotap) from
    a monitor interface, and Ethernet, Linux cooked or BSD loopback from an AP
    or uplink interface. Protected 802.11 frames yield nothing — they need a
    key (:class:`omni.wifi.sniff.Keys` supplies one).
    """
    if linktype in WIFI_LINKTYPES:
        frame = strip_radiotap(data) if linktype == LINKTYPE_RADIOTAP else data
        if len(frame) < 24 or not _is_data(frame) or _is_protected(frame):
            return None
        return llc_ipv4(frame[_body_offset(frame):])
    if linktype in _L3_HEADERS:
        header_len, ethertype_at = _L3_HEADERS[linktype]
        if len(data) < header_len:
            return None
        if struct.unpack(">H", data[ethertype_at:ethertype_at + 2])[0] != 0x0800:
            return None
        return ipv4(data[header_len:])
    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return None
        family = struct.unpack("<I", data[:4])[0]
        if family not in (2, 24, 28, 30):      # AF_INET in the BSD variants
            return None
        return ipv4(data[4:])
    return None


def find_handshakes(path: str) -> list[Handshake]:
    """Assemble every testable handshake in a capture.

    Message 2 (STA -> AP, with SNonce) and message 1 or 3 (AP -> STA, with
    ANonce) are paired per (AP, STA). The MIC is taken from message 2.
    """
    ssids = ssid_map(path)
    pending: dict[tuple[bytes, bytes], dict] = {}
    done: list[Handshake] = []

    for frame in read_frames(path):
        eapol = eapol_key(frame)
        if eapol is None:
            continue
        key_info = int.from_bytes(eapol[5:7], "big")
        replay = int.from_bytes(eapol[9:13], "big")
        kdv = key_info & 0x07
        nonce = eapol[17:49]
        mic = eapol[MIC_OFFSET:MIC_OFFSET + MIC_LEN]
        # 0x0080 marks ACK (AP->STA); 0x0100 marks a MIC. Message 4 has neither
        # a usable MIC nor ACK, so it is skipped.
        from_ap = bool(key_info & 0x0080)
        if not from_ap and not key_info & 0x0100:
            continue

        if from_ap:
            ap, sta = frame[10:16], frame[4:10]
        else:
            ap, sta = frame[4:10], frame[10:16]

        slot = pending.setdefault((ap, sta), {})
        if from_ap:
            slot["a_nonce"] = nonce
            slot.setdefault("kdv", kdv)
        else:
            slot["s_nonce"] = nonce
            slot.update({"eapol": eapol, "mic": mic, "kdv": kdv,
                         "replay_counter": replay})
        if not all(k in slot for k in ("a_nonce", "s_nonce", "eapol")):
            continue
        if not any(h.ap == ap and h.sta == sta and
                   h.a_nonce == slot["a_nonce"] for h in done):
            done.append(Handshake(
                ssid=ssids.get(ap, b""), ap=ap, sta=sta,
                a_nonce=slot["a_nonce"], s_nonce=slot["s_nonce"],
                eapol=slot["eapol"], mic=slot["mic"], kdv=slot["kdv"],
                replay_counter=slot["replay_counter"],
                bssid=":".join(f"{b:02X}" for b in ap), source=path))
    return done


def data_frames(path: str):
    """Yield (frame, body) for every protected data frame."""
    for frame in read_frames(path):
        if _is_data(frame) and _is_protected(frame):
            yield frame, frame[_body_offset(frame):]
