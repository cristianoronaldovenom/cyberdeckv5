"""Batch decryption/extraction tests: parsers, reassembly, and a real frame.

The parsers are pure byte functions. The end-to-end test builds a genuine
WPA2 handshake and a CCMP-protected HTTP frame in memory, writes them as a
pcap, and checks the pipeline recovers the URL and the credential from it.
"""

import base64
import struct

import pytest

from omni.wifi import ccmp, extract, pcapread, wpa

SSID = b"HomeNet"
PSK = "hunter22"
AP = bytes.fromhex("001122334455")
STA = bytes.fromhex("66778899aabb")


# -- parsers ----------------------------------------------------------------

def test_sniff_recognises_magic():
    assert extract.sniff(b"\x89PNG\r\n\x1a\n" + b"x" * 20) == ".png"
    assert extract.sniff(b"%PDF-1.7 blah") == ".pdf"
    assert extract.sniff(b"plain text") == ""


def test_parse_http_splits_start_headers_body():
    parsed = extract.parse_http(b"GET /a?b=1 HTTP/1.1\r\nHost: x.test\r\n\r\nbody")
    assert parsed["start"].startswith("GET /a")
    assert parsed["headers"]["host"] == "x.test"
    assert parsed["body"] == b"body"


def test_parse_dns_reads_the_question():
    blob = (b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07example\x03com\x00\x00\x01\x00\x01")
    assert extract.parse_dns(blob) == ["example.com"]


def test_parse_sni_reads_the_server_name():
    name = b"secure.example.com"
    ext = b"\x00\x00" + struct.pack(">H", len(name) + 5)
    ext += struct.pack(">H", len(name) + 3) + b"\x00" + struct.pack(">H", len(name))
    ext += name
    hello = b"\x16\x03\x01" + b"\x00\x00" + b"\x00" * 40 + ext
    assert extract.parse_sni(hello) == "secure.example.com"


def test_parse_sni_ignores_non_tls():
    assert extract.parse_sni(b"GET / HTTP/1.1\r\n\r\n") == ""


def test_parse_sni_survives_padding_and_junk():
    """A hello padded with zeros still has exactly one valid extension."""
    name = b"mail.example.com"
    ext = b"\x00\x00" + struct.pack(">H", len(name) + 5)
    ext += struct.pack(">H", len(name) + 3) + b"\x00" + struct.pack(">H", len(name))
    ext += name
    # 300 bytes of filler *after* the extension, then a second extension that
    # trips the length checks (it claims a name of 9 bytes but carries one)
    junk = b"\x00" * 300 + b"\x00\x00\x00\x07\x00\x06\x00\x00\x00\x01zz"
    filter_ext = b"\x00\x0b\x00\x02\x01\x00"                # ec_point_formats
    hello = (b"\x16\x03\x01" + b"\x00\x00" + b"\x00" * 40 + ext
             + filter_ext + junk)
    assert extract.parse_sni(hello) == "mail.example.com"


def test_basic_auth_decodes():
    token = base64.b64encode(b"admin:s3cret").decode()
    blob = f"Authorization: Basic {token}\r\n".encode()
    assert extract.basic_auth(blob) == [("admin", "s3cret")]


def test_form_creds_pairs_user_and_password():
    assert extract.form_creds(b"user=bob&password=pw1&remember=1") == [
        ("bob", "pw1")]


def test_form_creds_needs_a_secret_key():
    assert extract.form_creds(b"page=2&lang=en") == []


def test_url_creds():
    assert extract.url_creds("ftp://me:pw@host/x") == [("me", "pw")]
    assert extract.url_creds("http://host/x") == []


# -- keys and inputs --------------------------------------------------------

def test_read_text_handles_utf16_bom(tmp_path):
    path = tmp_path / "keys.txt"
    path.write_bytes("HomeNet:hunter22\r\n".encode("utf-16"))
    assert extract.load_keys(extract.read_text(str(path))) == {
        "HomeNet": "hunter22", "HOMENET": "hunter22"}


def test_read_text_handles_utf8_bom(tmp_path):
    path = tmp_path / "keys.txt"
    path.write_bytes("\ufeffNet:pw".encode("utf-8"))
    assert extract.load_keys(extract.read_text(str(path)))["Net"] == "pw"


def test_load_keys_handles_bssid_lines():
    keys = extract.load_keys("AA:BB:CC:DD:EE:FF:s3cret\nHomeNet:hunter22\n")
    assert keys["AA:BB:CC:DD:EE:FF"] == "s3cret"
    assert keys["HomeNet"] == "hunter22"


def test_load_keys_skips_junk():
    assert extract.load_keys("# note\n\nbroken") == {}


def test_expand_inputs_dedupes_and_expands(tmp_path):
    one = tmp_path / "a.pcap"
    one.write_bytes(b"x")
    two = tmp_path / "b.pcap"
    two.write_bytes(b"x")
    assert extract.expand_inputs(f"{one} {one}") == [str(one)]
    assert sorted(extract.expand_inputs(str(tmp_path))) == [
        str(one), str(two)]


def test_expand_inputs_glob(tmp_path):
    one = tmp_path / "a.pcap"
    one.write_bytes(b"x")
    assert extract.expand_inputs(str(tmp_path / "*.pcap")) == [str(one)]


# -- reassembly -------------------------------------------------------------

def test_stream_reassembles_in_order_and_dedupes():
    stream = extract.Stream(("k",), ("10.0.0.2", 1234), ("10.0.0.1", 80))
    stream.feed(True, 100, b"GET ")
    stream.feed(True, 104, b"/x HTTP/1.0")
    stream.feed(True, 100, b"GET ")                  # retransmit
    assert stream.request == b"GET /x HTTP/1.0"


def test_stream_stops_at_a_gap():
    stream = extract.Stream(("k",), ("a", 1), ("b", 80))
    stream.feed(True, 1, b"one")
    stream.feed(True, 9, b"later")
    assert stream.request == b"one"


def test_stream_flags_http_by_port_or_start_line():
    assert extract.Stream(("k",), ("a", 1), ("b", 80)).is_http
    other = extract.Stream(("k",), ("a", 1), ("b", 9001))
    other.feed(True, 1, b"POST /y HTTP/1.1")
    assert other.is_http


# -- end to end through a real capture --------------------------------------

A_NONCE = bytes(range(32))
S_NONCE = bytes(range(32, 64))


def mac_header(fc1: int, a1: bytes, a2: bytes, a3: bytes) -> bytes:
    return b"\x08" + bytes([fc1]) + b"\x00\x00" + a1 + a2 + a3 + b"\x00\x00"


def eapol(mic: bytes = b"\x00" * 16, nonce: bytes = b"\x00" * 32,
          ack: bool = False) -> bytes:
    body = bytearray(95)
    body[0], body[1] = 0x01, 0x03
    body[5:7] = (0x0082 if ack else 0x0102).to_bytes(2, "big")   # ACK/MIC + KDV2
    body[17:49] = nonce
    body[81:97] = mic
    return pcapread.EAPOL_SNAP + bytes(body)


def beacon(ssid: bytes = SSID) -> bytes:
    frame = b"\x80\x00\x00\x00" + b"\xff" * 6 + AP + AP + b"\x00\x00"
    frame += b"\x00" * 12                        # fixed parameters
    return frame + b"\x00" + bytes([len(ssid)]) + ssid


def write_pcap(path, frames: list[bytes]) -> None:
    with open(path, "wb") as fh:
        fh.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHi", 2, 4, 0)
                 + struct.pack("<III", 0, 65535, pcapread.LINKTYPE_80211))
        for frame in frames:
            fh.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
            fh.write(frame)


def ipv4_tcp(src: bytes, dst: bytes, sport: int, dport: int, seq: int,
             payload: bytes) -> bytes:
    """LLC/SNAP + IPv4 + TCP + payload, the way a frame body really looks."""
    tcp = (struct.pack(">HH", sport, dport) + struct.pack(">II", seq, 0)
           + b"\x50\x18" + struct.pack(">HHH", 8192, 0, 0))
    packet = (b"\x45\x00" + struct.pack(">H", 20 + len(tcp) + len(payload))
              + b"\x00\x01\x40\x00\x40\x06\x00\x00" + src + dst + tcp + payload)
    return b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + packet


def build_pcap(path) -> bytes:
    """A capture holding a real handshake and one CCMP HTTP request."""
    key = wpa.ptk(wpa.pmk(PSK, SSID), AP, STA, A_NONCE, S_NONCE)
    kck, tk = key[:16], key[32:48]

    raw = bytearray(eapol(nonce=S_NONCE, ack=False))
    start = len(pcapread.EAPOL_SNAP)
    mic = wpa.mic_for(bytes(raw[start:]), kck, 2)
    raw[start + 81:start + 97] = mic

    msg1 = mac_header(0x02, STA, AP, AP) + eapol(nonce=A_NONCE, ack=True)
    msg2 = mac_header(0x01, AP, STA, AP) + bytes(raw)

    # the payload of interest: an HTTP request with a URL and Basic creds
    token = base64.b64encode(b"bob:pw123")
    http = (b"GET /admin/panel?user=bob&password=pw123 HTTP/1.1\r\n"
            b"Host: intranet.test\r\nAuthorization: Basic " + token
            + b"\r\n\r\n" + b"A" * 80)
    inner = ipv4_tcp(b"\x0a\x00\x00\x02", b"\x0a\x00\x00\x01", 49152, 80, 1, http)

    pn = b"\x01\x00\x00\x00\x00\x00"
    header = mac_header(0x41, AP, STA, b"\xde\xad\xbe\xef\x00\x01")
    aad = ccmp.ccmp_aad(header)
    cipher, mic = ccmp.ccmp_encrypt(inner, tk,
                                    ccmp.ccmp_nonce(0, STA, pn), aad)
    ccmp_header = bytes([pn[0], pn[1], 0x00, 0x20, pn[2], pn[3], pn[4], pn[5]])
    data = header + ccmp_header + cipher + mic

    write_pcap(path, [beacon(), msg1, msg2, data])
    return http


def test_end_to_end_recovers_url_and_credentials(tmp_path):
    pcap = tmp_path / "cap.pcap"
    payload = build_pcap(pcap)
    out = tmp_path / "loot"
    report = extract.extract([str(pcap)], {str(SSID, "utf-8"): PSK}, str(out))

    assert report.frames >= 1
    assert "http://intranet.test" in report.urls
    assert any(u.endswith("/admin/panel?user=bob&password=pw123")
               for u in report.urls)
    assert ("basic", "bob", "pw123") in report.creds
    assert ("form", "bob", "pw123") in report.creds
    assert report.captures == [str(pcap)]
    assert (out / "manifest.json").is_file()
    assert (out / "creds.txt").read_text().count("bob") == 2
    assert payload


def test_end_to_end_skips_an_unknown_ap(tmp_path):
    pcap = tmp_path / "cap.pcap"
    build_pcap(pcap)
    report = extract.extract([str(pcap)], {"OtherNet": PSK}, str(tmp_path / "o"))
    assert report.frames == 0
    assert report.skipped and "no key" in report.skipped[0][1]


def test_end_to_end_reports_a_wrong_key(tmp_path):
    pcap = tmp_path / "cap.pcap"
    build_pcap(pcap)
    report = extract.extract([str(pcap)], {"HomeNet": "wrongpass"},
                             str(tmp_path / "o"))
    assert report.frames == 0
    assert "mismatch" in report.skipped[0][1]


def test_end_to_end_caps_written_files(tmp_path):
    pcap = tmp_path / "cap.pcap"
    build_pcap(pcap)
    report = extract.extract([str(pcap)], {"HomeNet": PSK},
                             str(tmp_path / "o"), max_files=1)
    assert len(report.files) == 1


def test_extract_module_needs_captures(tmp_path):
    from omni.wifi.modules import extract as mod

    with pytest.raises(FileNotFoundError, match="no captures"):
        mod.Extract(INPUT=str(tmp_path / "nope/*.pcap")).execute()


def test_extract_module_needs_keys(tmp_path):
    from omni.wifi.modules import extract as mod

    pcap = tmp_path / "cap.pcap"
    build_pcap(pcap)
    with pytest.raises(ValueError, match="no keys"):
        mod.Extract(INPUT=str(pcap), AUTO="false").execute()
