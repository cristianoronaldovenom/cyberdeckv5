"""WPA2 engine tests: AES vectors, key hierarchy, handshake, CCMP, capture IO.

The crypto is anchored to published vectors (FIPS-197 for AES, the WPA PMK
vector), and the end-to-end path builds a real handshake + capture with the
same primitives so the parser, cracker and decrypter are exercised together.
"""

import struct
from binascii import unhexlify

import pytest

from omni.wifi import ccmp, pcapread, pskcrack, wpa

SSID = b"IEEE"
PSK = "password"
AP = unhexlify("00160197bbbb")
STA = unhexlify("001601cccccc")
A_NONCE = bytes(range(32))
S_NONCE = bytes(range(32, 64))


# -- AES --------------------------------------------------------------------

def test_aes128_fips197_vector():
    key = unhexlify("000102030405060708090a0b0c0d0e0f")
    plain = unhexlify("00112233445566778899aabbccddeeff")
    want = unhexlify("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert ccmp.aes128_block(plain, ccmp.expand_key(key)) == want


def test_aes_sbox_matches_fips_values():
    assert ccmp.SBOX[0x00] == 0x63
    assert ccmp.SBOX[0x01] == 0x7C
    assert ccmp.SBOX[0xFF] == 0x16


def test_aes_rejects_bad_key_and_block_sizes():
    with pytest.raises(ValueError):
        ccmp.expand_key(b"short")
    with pytest.raises(ValueError):
        ccmp.aes128_block(b"short", ccmp.expand_key(bytes(16)))


# -- key hierarchy (published vector) ---------------------------------------

def test_pmk_matches_the_published_vector():
    assert wpa.pmk(PSK, SSID).hex() == (
        "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e")


def test_ptk_is_order_independent():
    first = wpa.pmk(PSK, SSID)
    assert wpa.ptk(first, AP, STA, A_NONCE, S_NONCE) == \
        wpa.ptk(first, STA, AP, S_NONCE, A_NONCE)


def test_ptk_has_the_expected_sections():
    key = wpa.ptk(wpa.pmk(PSK, SSID), AP, STA, A_NONCE, S_NONCE)
    assert len(key) == 64            # KCK 16 | KEK 16 | TK 16 | MIC 16


@pytest.mark.parametrize("psk,expected", [
    ("1234567", False), ("12345678", True), ("a" * 63, True), ("a" * 64, False),
])
def test_valid_psk_lengths(psk, expected):
    assert wpa.valid_psk(psk) is expected


# -- synthetic handshake builder -------------------------------------------

def build_eapol(kdv=2, mic=b"\x00" * 16, nonce=b"\x00" * 32,
                replay=1, ack=False, mic_bit=True, from_ap=False) -> bytes:
    key_info = kdv | (0x0080 if ack else 0) | (0x0100 if mic_bit else 0)
    if from_ap:
        key_info |= 0x0008 | 0x0040            # encrypted key data
    body = bytearray(99)
    body[0], body[1] = 0x01, 0x03              # version 1, type EAPOL-Key
    body[2:4] = b"\x00\x5f"
    body[5:7] = struct.pack(">H", key_info)
    body[9:13] = struct.pack(">I", replay)
    body[17:49] = nonce
    body[81:97] = mic
    return bytes(body)


def build_handshake(passphrase=PSK) -> wpa.Handshake:
    key = wpa.ptk(wpa.pmk(passphrase, SSID), AP, STA, A_NONCE, S_NONCE)
    eapol = bytearray(build_eapol(nonce=S_NONCE))
    mic = wpa.mic_for(bytes(eapol), key[:16], 2)
    eapol[81:97] = mic
    return wpa.Handshake(ssid=SSID, ap=AP, sta=STA, a_nonce=A_NONCE,
                         s_nonce=S_NONCE, eapol=bytes(eapol), mic=mic, kdv=2,
                         bssid="00:16:01:97:BB:BB")


def test_handshake_accepts_the_right_passphrase():
    assert build_handshake().verify(PSK)


def test_handshake_rejects_a_wrong_passphrase():
    assert not build_handshake().verify("wrongpass")


def test_handshake_rejects_an_illegal_length():
    assert not build_handshake().verify("short")


def test_handshake_describe_shows_the_ssid():
    assert "IEEE" in build_handshake().describe()


# -- candidate generation ---------------------------------------------------

def test_expand_mask_walks_the_space():
    assert list(pskcrack.expand_mask("ab")) == ["ab"]        # literals
    assert len(list(pskcrack.expand_mask("?d?d"))) == 100
    assert list(pskcrack.expand_mask("?d?d"))[-1] == "99"
    assert list(pskcrack.expand_mask("a??b")) == ["a?b"]     # escaped "?"
    assert list(pskcrack.expand_mask("a?a"))[-1] == "a~"      # symbols covered


def test_expand_mask_rejects_unknown_token():
    with pytest.raises(ValueError, match="unknown mask token"):
        list(pskcrack.expand_mask("?z"))


def test_rules_include_the_obvious_variants():
    variants = list(pskcrack.rules("acme"))
    assert "acme" in variants and "ACME" in variants and "acme2026" in variants


def test_candidates_skip_illegal_and_duplicates():
    got = list(pskcrack.candidates(["1234567", "password", "password"],
                                   use_rules=False))
    assert got == ["password"]


def test_candidates_combine_wordlist_and_mask():
    # ?d?d alone is too short for a legal PSK, so anchor it to a word
    got = list(pskcrack.candidates(["password"], "password?d?d",
                                   use_rules=False))
    assert got[0] == "password"
    assert len(got) == 1 + 100
    assert "password42" in got


def test_crack_finds_the_passphrase_from_a_wordlist():
    result = pskcrack.crack(build_handshake(), ["nope", "password"],
                            use_rules=False)
    assert result.found and result.passphrase == PSK


def test_crack_finds_it_through_a_rule():
    result = pskcrack.crack(build_handshake(), ["Password"], use_rules=True)
    assert result.found and result.passphrase == "password"


def test_crack_reports_exhaustion_without_a_hit():
    result = pskcrack.crack(build_handshake(), ["nope"], use_rules=False)
    assert not result.found and result.complete


def test_crack_respects_a_limit():
    result = pskcrack.crack(build_handshake(), mask="?u?u?u?u?u?u?u?u",
                            limit=50)
    assert not result.found and not result.complete


def test_crack_parallel_finds_the_same_passphrase():
    result = pskcrack.crack_parallel(build_handshake(),
                                     ["wrongpass", "password"],
                                     use_rules=False, workers=2,
                                     chunk_size=1)
    assert result.found and result.passphrase == PSK


def test_crack_parallel_reports_exhaustion():
    result = pskcrack.crack_parallel(build_handshake(), ["wrongpass"],
                                     use_rules=False, workers=2, chunk_size=1)
    assert not result.found and result.complete


# -- CCMP -------------------------------------------------------------------

def mac_header(fc1: int, a1: bytes, a2: bytes, a3: bytes) -> bytes:
    return b"\x08" + bytes([fc1]) + b"\x00\x00" + a1 + a2 + a3 + b"\x10\x00"


def test_ccmp_round_trip():
    tk = bytes(range(16))
    header = mac_header(0x01, AP, STA, AP)
    nonce = ccmp.ccmp_nonce(0, STA, b"\x00\x00\x00\x00\x00\x01")
    aad = ccmp.ccmp_aad(header)
    cipher, mic = ccmp.ccmp_encrypt(b"GET / HTTP/1.1\r\n", tk, nonce, aad)
    assert b"GET" not in cipher
    assert ccmp.ccmp_decrypt(cipher, tk, nonce, aad, mic) == b"GET / HTTP/1.1\r\n"


def test_ccmp_rejects_a_wrong_key():
    tk = bytes(range(16))
    header = mac_header(0x01, AP, STA, AP)
    nonce = ccmp.ccmp_nonce(0, STA, b"\x00" * 6)
    aad = ccmp.ccmp_aad(header)
    cipher, mic = ccmp.ccmp_encrypt(b"payload", tk, nonce, aad)
    with pytest.raises(ValueError, match="MIC mismatch"):
        ccmp.ccmp_decrypt(cipher, bytes(16), nonce, aad, mic)


def test_ccmp_rejects_tampering():
    tk = bytes(range(16))
    header = mac_header(0x01, AP, STA, AP)
    nonce = ccmp.ccmp_nonce(0, STA, b"\x00" * 6)
    aad = ccmp.ccmp_aad(header)
    cipher, mic = ccmp.ccmp_encrypt(b"payload", tk, nonce, aad)
    with pytest.raises(ValueError, match="MIC mismatch"):
        ccmp.ccmp_decrypt(bytes([cipher[0] ^ 0xFF]) + cipher[1:], tk, nonce,
                          aad, mic)


def test_ccmp_nonce_is_13_bytes():
    assert len(ccmp.ccmp_nonce(0, STA, b"\x00" * 6)) == 13
    with pytest.raises(ValueError):
        ccmp.ccmp_decrypt(b"x" * 16, bytes(16), b"short", b"")


def test_ccmp_aad_covers_three_addresses():
    aad = ccmp.ccmp_aad(mac_header(0x01, AP, STA, AP))
    assert AP in aad and STA in aad


def test_split_ccmp_body_extracts_the_pn():
    body = bytes([1, 2, 0, 0x20, 3, 4, 5, 6]) + bytes(16)
    pn, rest, key_id = ccmp.split_ccmp_body(body)
    assert pn == bytes([1, 2, 3, 4, 5, 6]) and key_id == 0
    assert rest == bytes(16)


def test_split_ccmp_body_needs_the_extiv_bit():
    with pytest.raises(ValueError, match="ExtIV"):
        ccmp.split_ccmp_body(bytes(8) + bytes(16))


# -- capture IO -------------------------------------------------------------

def beacon(bssid: bytes, ssid: bytes) -> bytes:
    body = bytes(12) + b"\x00" + bytes([len(ssid)]) + ssid + b"\x01\x04\x82\x84"
    return (b"\x80\x00" + b"\x00\x00" + b"\xff" * 6 + bssid + bssid
            + b"\x00\x00" + body)


def eapol_frame(src: bytes, dst: bytes, bssid: bytes, eapol: bytes) -> bytes:
    # FromDS: A1=destination, A2=transmitter (src), A3=source/bssid
    return (b"\x08\x42" + b"\x00\x00" + dst + src + bssid + b"\x00\x00"
            + pcapread.EAPOL_SNAP + eapol)


def write_pcap(path, frames, linktype=pcapread.LINKTYPE_80211):
    # FC second octet 0x42 = Retry set; exercise the AAD mask in the parser
    import struct as st
    with open(path, "wb") as fh:
        fh.write(st.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for frame in frames:
            fh.write(st.pack("<IIII", 0, 0, len(frame), len(frame)))
            fh.write(frame)


def build_capture(tmp_path, passphrase=PSK):
    hs = build_handshake(passphrase)
    msg1 = build_eapol(nonce=A_NONCE, replay=1, ack=True, mic_bit=False,
                       from_ap=True)
    frames = [beacon(AP, SSID),
              eapol_frame(AP, STA, AP, msg1),
              eapol_frame(STA, AP, AP, hs.eapol)]
    path = tmp_path / "cap.pcap"
    write_pcap(path, frames)
    return str(path)


def test_find_handshakes_reads_a_capture(tmp_path):
    found = pcapread.find_handshakes(build_capture(tmp_path))
    assert len(found) == 1
    assert found[0].ssid == SSID
    assert found[0].ap == AP and found[0].sta == STA


def test_parsed_handshake_verifies(tmp_path):
    found = pcapread.find_handshakes(build_capture(tmp_path))
    assert found[0].verify(PSK)
    assert not found[0].verify("nope1234")


def test_ssid_map_reads_beacons(tmp_path):
    assert pcapread.ssid_map(build_capture(tmp_path))[AP] == SSID


def test_radiotap_frames_are_stripped(tmp_path):
    inner = beacon(AP, SSID)
    radiotap = b"\x00\x00\x08\x00" + b"\x00" * 4      # it_len = 8
    path = tmp_path / "r.pcap"
    write_pcap(path, [radiotap + inner], pcapread.LINKTYPE_RADIOTAP)
    assert pcapread.find_handshakes(str(path)) == []
    assert pcapread.ssid_map(str(path)) == {AP: SSID}


def test_pcapng_is_rejected(tmp_path):
    path = tmp_path / "x.pcapng"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + bytes(20))
    with pytest.raises(pcapread.PcapError, match="pcapng"):
        list(pcapread.read_frames(str(path)))


def test_unknown_magic_is_rejected(tmp_path):
    path = tmp_path / "x"
    path.write_bytes(b"garbage" + bytes(17))
    with pytest.raises(pcapread.PcapError, match="unknown pcap magic"):
        list(pcapread.read_frames(str(path)))


def test_wrong_linktype_is_rejected(tmp_path):
    path = tmp_path / "x"
    write_pcap(path, [beacon(AP, SSID)], linktype=1)
    with pytest.raises(pcapread.PcapError, match="link type"):
        list(pcapread.read_frames(str(path)))


# -- end to end: crack a capture, then decrypt its traffic ------------------

def build_full_capture(tmp_path, passphrase=PSK, payload=b"GET /secret HTTP/1.1\r\n"):
    """Capture with a handshake plus one protected data frame."""
    hs = build_handshake(passphrase)
    tk = wpa.ptk(wpa.pmk(passphrase, SSID), AP, STA, A_NONCE, S_NONCE)[32:48]
    header = mac_header(0x41, AP, STA, AP)           # ToDS + Protected
    pn = b"\x00\x00\x00\x00\x00\x07"
    nonce = ccmp.ccmp_nonce(0, STA, pn)
    cipher, mic = ccmp.ccmp_encrypt(payload, tk, nonce, ccmp.ccmp_aad(header))
    ccmp_header = bytes([pn[0], pn[1], 0, 0x20]) + pn[2:] + b"\x00" * 0
    protected = header + ccmp_header + cipher + mic

    msg1 = build_eapol(nonce=A_NONCE, replay=1, ack=True, mic_bit=False,
                       from_ap=True)
    frames = [beacon(AP, SSID),
              eapol_frame(AP, STA, AP, msg1),
              eapol_frame(STA, AP, AP, hs.eapol),
              protected]
    path = tmp_path / "full.pcap"
    write_pcap(path, frames)
    return str(path)


def test_full_chain_cracks_then_decrypts(tmp_path):
    path = build_full_capture(tmp_path)

    found = pcapread.find_handshakes(path)
    assert len(found) == 1
    result = pskcrack.crack(found[0], ["wrong", PSK], use_rules=False)
    assert result.passphrase == PSK

    hs = found[0]
    tk = wpa.ptk(wpa.pmk(result.passphrase, hs.ssid), hs.ap, hs.sta,
                 hs.a_nonce, hs.s_nonce)[32:48]
    recovered = []
    for frame, body in pcapread.data_frames(path):
        if not body.startswith(pcapread.EAPOL_SNAP):
            pn, cipher, _kid = ccmp.split_ccmp_body(body)
            recovered.append(ccmp.ccmp_decrypt(
                cipher, tk, ccmp.ccmp_nonce(0, frame[10:16], pn),
                ccmp.ccmp_aad(frame)))
    assert recovered == [b"GET /secret HTTP/1.1\r\n"]


def test_protected_frames_are_listed_and_eapol_is_skipped(tmp_path):
    path = build_full_capture(tmp_path)
    bodies = [body for _f, body in pcapread.data_frames(path)]
    assert any(b.startswith(pcapread.EAPOL_SNAP) for b in bodies)
    assert len([b for b in bodies if not b.startswith(pcapread.EAPOL_SNAP)]) == 1




