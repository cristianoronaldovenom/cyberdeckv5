"""Module-level tests for the pure cracker and decrypter.

Reuses the synthetic capture builder from test_wpa.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_wpa import PSK, build_full_capture  # noqa: E402

from omni.wifi.modules import decrypt  # noqa: E402


def test_handshakes_module_lists_the_capture(tmp_path):
    mod = decrypt.Handshakes(PCAP=build_full_capture(tmp_path))
    result = mod.execute()
    assert len(result["handshakes"]) == 1
    assert "IEEE" in result["handshakes"][0]


def test_handshakes_module_reports_an_empty_capture(tmp_path):
    path = build_full_capture(tmp_path)
    mod = decrypt.Handshakes(PCAP=path)
    import omni.wifi.pcapread as pr
    original = pr.find_handshakes
    pr.find_handshakes = lambda _p: []
    try:
        assert mod.execute() == {"handshakes": []}
    finally:
        pr.find_handshakes = original


def test_crack_pure_finds_the_key(tmp_path):
    wordfile = tmp_path / "words.txt"
    wordfile.write_text("wrongpass\npassword\n", encoding="utf-8")
    mod = decrypt.CrackPure(PCAP=build_full_capture(tmp_path),
                            WORDLIST=str(wordfile), RULES="false")
    result = mod.execute()
    assert result["passphrase"] == PSK
    assert result["tried"] >= 2


def test_crack_pure_writes_the_psk(tmp_path):
    wordfile = tmp_path / "words.txt"
    wordfile.write_text("password\n", encoding="utf-8")
    mod = decrypt.CrackPure(PCAP=build_full_capture(tmp_path),
                            WORDLIST=str(wordfile), RULES="false")
    result = mod.execute()
    out = mod.get("OUT") or mod.get("PCAP")
    assert result["passphrase"] == PSK
    from omni.core import config
    import os
    path = os.path.join(config.output_dir("wifi"), "psk_00160197BBBB.txt")
    assert os.path.exists(path)
    assert PSK in open(path, encoding="utf-8").read()
    _ = out


def test_crack_pure_needs_a_source(tmp_path):
    mod = decrypt.CrackPure(PCAP=build_full_capture(tmp_path))
    with pytest.raises(ValueError, match="WORDLIST and/or MASK"):
        mod.execute()


def test_crack_pure_fails_on_a_capture_with_no_handshake(tmp_path):
    mod = decrypt.CrackPure(PCAP=str(tmp_path / "missing.pcap"),
                            WORDLIST="x")
    with pytest.raises(Exception):
        mod.execute()


def test_decrypt_module_recovers_the_payload(tmp_path):
    out = tmp_path / "plain.txt"
    mod = decrypt.Decrypt(PCAP=build_full_capture(tmp_path), PSK=PSK,
                          OUT=str(out), PRINT="false")
    result = mod.execute()
    assert result["decrypted"] == 1
    assert b"GET /secret" in out.read_bytes()


def test_decrypt_module_rejects_a_bad_psk(tmp_path):
    mod = decrypt.Decrypt(PCAP=build_full_capture(tmp_path), PSK="wrongpass")
    with pytest.raises(ValueError, match="does not match"):
        mod.execute()


def test_decrypt_module_filters_by_bssid(tmp_path):
    mod = decrypt.Decrypt(PCAP=build_full_capture(tmp_path), PSK=PSK,
                          BSSID="00:16:01:97:BB:BB", PRINT="false",
                          OUT=str(tmp_path / "o.txt"))
    assert mod.execute()["decrypted"] == 1
