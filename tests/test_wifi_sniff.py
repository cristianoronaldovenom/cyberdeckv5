"""Live sniffing: pcap streaming, HTTP decoding, HTTPS names, CCMP decrypt.

The pcap reader and the HTTP decoder are pure byte functions, so most of this
needs nothing but constructed packets. The last group builds a real WPA2
handshake and a CCMP-protected request (``test_wifi_extract`` already does
that) and checks that the *live* path derives the key and prints the request —
the thing a rogue AP actually needs.
"""

import base64
import json
import struct

import pytest

from omni.wifi import http, pcapread, sniff

CLIENT = bytes.fromhex("0a000002")
SERVER = bytes.fromhex("0a000001")


# -- fixture builders -------------------------------------------------------

def tcp_packet(src, dst, sport, dport, seq, payload) -> bytes:
    header = (struct.pack(">HH", sport, dport) + struct.pack(">II", seq, 0)
              + b"\x50\x18" + struct.pack(">HHH", 8192, 0, 0))
    return (b"\x45\x00" + struct.pack(">H", 20 + len(header) + len(payload))
            + b"\x00\x01\x40\x00\x40\x06\x00\x00" + src + dst + header + payload)


def udp_packet(src, dst, sport, dport, body) -> bytes:
    length = 8 + len(body)
    return (b"\x45\x00" + struct.pack(">H", 20 + length)
            + b"\x00\x01\x40\x00\x40\x11\x00\x00" + src + dst
            + struct.pack(">HHHH", sport, dport, length, 0) + body)


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return b"\x11" * 6 + b"\x22" * 6 + struct.pack(">H", ethertype) + payload


def dns_query(name: str) -> bytes:
    blob = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        blob += bytes([len(label)]) + label.encode()
    return blob + b"\x00\x00\x01\x00\x01"


def tls_hello(server_name: bytes) -> bytes:
    ext = b"\x00\x00" + struct.pack(">H", len(server_name) + 5)
    ext += struct.pack(">H", len(server_name) + 3) + b"\x00"
    ext += struct.pack(">H", len(server_name)) + server_name
    return b"\x16\x03\x01" + b"\x00\x00" + b"\x00" * 40 + ext


def pcap_bytes(frames, linktype: int = pcapread.LINKTYPE_ETHERNET) -> bytes:
    head = (b"\xd4\xc3\xb2\xa1" + struct.pack("<HHi", 2, 4, 0)
            + struct.pack("<III", 0, 65535, linktype))
    body = b"".join(struct.pack("<IIII", 0, 0, len(f), len(f)) + f
                    for f in frames)
    return head + body


def post(path: str, host: str, body: bytes) -> bytes:
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode() + body


# -- the pcap stream --------------------------------------------------------

def test_reader_assembles_frames_across_read_boundaries():
    frames = [ethernet(tcp_packet(CLIENT, SERVER, 1000, 80, 1, b"GET / HTTP/1.1"))
              for _ in range(3)]
    blob = pcap_bytes(frames)
    reader = pcapread.Reader()
    seen = []
    for index in range(len(blob)):           # one byte at a time, worst case
        seen += reader.feed(blob[index:index + 1])
    assert len(seen) == 3
    assert reader.linktype == pcapread.LINKTYPE_ETHERNET
    assert seen[0] == frames[0]


def test_parse_header_rejects_pcapng():
    with pytest.raises(pcapread.PcapError, match="pcapng"):
        pcapread.parse_header(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)


def test_network_payload_reads_ethernet_and_radiotap():
    packet = tcp_packet(CLIENT, SERVER, 1234, 80, 1, b"hello")
    parsed = pcapread.network_payload(pcapread.LINKTYPE_ETHERNET,
                                      ethernet(packet))
    assert parsed is not None and parsed[0] == 6
    assert parsed[1] == CLIENT and parsed[2] == SERVER
    assert parsed[3].endswith(b"hello")          # TCP segment, header included
    radiotap = b"\x00\x00\x08\x00" + b"\x00" * 4 + b"frame"   # 8-byte header
    assert pcapread.network_payload(pcapread.LINKTYPE_ETHERNET,
                                    radiotap) is None
    assert pcapread.strip_radiotap(radiotap) == b"frame"


# -- the HTTP decoder -------------------------------------------------------

def test_decoder_joins_a_request_split_mid_header():
    decoder = http.Decoder()
    assert decoder.feed(b"GET /a HTTP/1.1\r\nHo") == []
    messages = decoder.feed(b"st: x.test\r\n\r\n")
    assert [m.url for m in messages] == ["http://x.test/a"]
    assert messages[0].method == "GET" and messages[0].path == "/a"


def test_decoder_reads_a_chunked_form_body():
    decoder = http.Decoder()
    request = (b"POST /login HTTP/1.1\r\nHost: x.test\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n"
               b"d\r\nuser=bob&pass\r\n" b"7\r\nword=1\r\n" b"0\r\n\r\n")
    messages = decoder.feed(request)
    assert len(messages) == 1
    assert ("form", "bob", "1") in messages[0].credentials()


def test_decoder_skips_a_binary_stream():
    decoder = http.Decoder()
    assert decoder.feed(b"\x16\x03\x01" + b"\xaa" * 9000) == []
    assert decoder.pending < 9000 and decoder.skipped > 0


def test_message_basic_auth_and_absolute_target():
    token = base64.b64encode(b"admin:s3cret").decode()
    message = http.Decoder().feed(
        (f"GET http://u.test/x HTTP/1.1\r\nHost: u.test\r\n"
         f"Authorization: Basic {token}\r\n\r\n").encode())[0]
    assert message.host == "u.test" and message.url == "http://u.test/x"
    assert ("basic", "admin", "s3cret") in message.credentials()


# -- the sniffer ------------------------------------------------------------

def test_sniffer_reports_a_request_split_over_two_segments():
    body = b"user=bob&password=pw123"
    request = post("/login", "intranet.test", body)
    frames = [
        ethernet(tcp_packet(CLIENT, SERVER, 49152, 80, 1, request[:40])),
        ethernet(tcp_packet(CLIENT, SERVER, 49152, 80, 41, request[40:])),
    ]
    sniffer = sniff.Sniffer()
    events = sniffer.feed(pcap_bytes(frames))
    report = sniffer.report()
    assert "http" in [e.kind for e in events]
    assert report["http"][0]["url"] == "http://intranet.test/login"
    assert report["creds"] == [["form", "bob", "pw123"]]
    assert "intranet.test" in report["hosts"]


def test_sniffer_reports_sni_cert_and_dns():
    frames = [
        ethernet(tcp_packet(CLIENT, SERVER, 50000, 443, 1,
                             tls_hello(b"bank.example.com"))),
        ethernet(udp_packet(CLIENT, SERVER, 40000, 53, dns_query("x.test")),
                 ethertype=0x0800),
    ]
    sniffer = sniff.Sniffer()
    sniffer.feed(pcap_bytes(frames))
    report = sniffer.report()
    assert "bank.example.com" in report["sni"]
    assert "x.test" in report["dns"]
    assert report["hosts"] == ["bank.example.com", "x.test"]


def test_sniffer_survives_junk_frames_and_writes_the_capture(tmp_path):
    out = tmp_path / "sniff"
    frames = [b"\x00" * 8,
              ethernet(tcp_packet(CLIENT, SERVER, 1, 80, 1, b"GET /h HTTP/1.1\r\n\r\n"))]
    sniffer = sniff.Sniffer(pcap_path=str(out / "traffic.pcap"),
                            jsonl=str(out / "sniff.jsonl"))
    out.mkdir()
    blob = pcap_bytes(frames)
    sniffer.feed(blob[:10])
    sniffer.feed(blob[10:])
    sniffer.close()
    assert (out / "traffic.pcap").read_bytes() == blob
    assert (out / "sniff.jsonl").read_text().count("\n") == len(sniffer.events)


def test_event_rows_and_json_are_plain():
    event = sniff.Event("creds", {"source": "form", "user": "bob",
                                   "pass": "pw", "url": "http://x.test/l"})
    assert event.row()[1] == "creds" and "bob:pw" in event.row()[2]
    assert json.dumps(event.as_dict())            # serialisable


# -- the thing the twin needs: a key, then plaintext ------------------------

def test_sniffer_derives_the_key_and_prints_a_ccmp_request(tmp_path):
    from test_wifi_extract import build_pcap

    capture = tmp_path / "ccmp.pcap"
    build_pcap(capture)                           # real handshake + CCMP frame
    sniffer = sniff.Sniffer(psk="hunter22", ssid="HomeNet")
    sniffer.read_file(str(capture))
    report = sniffer.report()
    assert report["decrypted"] >= 1
    assert report["http"] and "intranet.test" in report["http"][0]["url"]
    assert ["form", "bob", "pw123"] in report["creds"]
    assert "handshake" in [event.kind for event in sniffer.events]


def test_sniffer_without_a_key_reports_the_encrypted_frames(tmp_path):
    from test_wifi_extract import build_pcap

    capture = tmp_path / "ccmp.pcap"
    build_pcap(capture)
    sniffer = sniff.Sniffer()
    sniffer.read_file(str(capture))
    assert sniffer.report()["decrypted"] == 0
    assert sniffer.report()["http"] == []


# -- the module -------------------------------------------------------------

def test_sniff_module_decodes_a_capture(tmp_path):
    from omni.wifi.modules.sniff import Sniff

    capture = tmp_path / "plain.pcap"
    request = post("/login", "cafe.test", b"user=ann&password=tea")
    capture.write_bytes(pcap_bytes([
        ethernet(tcp_packet(CLIENT, SERVER, 4444, 80, 1, request))]))
    out = tmp_path / "out"
    report = Sniff(**{"pcap": str(capture), "out": str(out),
                      "live": "false"}).run()
    assert report["http"][0]["host"] == "cafe.test"
    saved = json.loads((out / "sniff.json").read_text())
    assert saved["creds"] == [["form", "ann", "tea"]]


def test_sniff_module_needs_a_source_or_tcpdump(tmp_path, monkeypatch):
    from omni.wifi.modules import sniff as sniff_module

    monkeypatch.setattr(sniff_module.proc, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="tcpdump"):
        sniff_module.Sniff(**{"iface": "wlan0",
                              "out": str(tmp_path / "o")}).run()


def test_registry_exposes_the_live_sniffer():
    from omni.core.module import registry

    assert "wifi.sniff" in {mod.NAME for mod in registry.all("wifi")}
