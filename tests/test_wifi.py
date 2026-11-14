"""WiFi parsing and keyspace tests — no radio or root required."""

import pytest

from omni.wifi import crack, iface, scan


IW_OUTPUT = """BSS 00:11:22:33:44:55(on wlan0)
\tfreq: 2412
\tbeacon interval: 100 TUs
\tsignal: -42.00 dBm
\tSSID: Cafe-Guest
\t* channel: 1
\tRSN:
\t\t* Authentication suites: PSK
\t\t* WPS: Version: 1.0

BSS aa:bb:cc:dd:ee:ff(on wlan0)
\tsignal: -71.50 dBm
\tSSID: Office-5G
\t* channel: 36
\tRSN:
\t\t* Authentication suites: SAE

BSS 12:34:56:78:90:ab(on wlan0)
\tfreq: 2437
\tsignal: -60.00 dBm
\tSSID: OpenCafe
\t* channel: 6
"""

AIRODUMP_CSV = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
00:11:22:33:44:55, 2026-08-13 10:00:00, 2026-08-13 10:05:00,  1,  54, WPA2, CCMP, PSK, -45,       120,        0,   0.  0.  0.  0,   4, Home, 
aa:bb:cc:dd:ee:ff, 2026-08-13 10:00:00, 2026-08-13 10:05:00,  6,  54, WEP, , , -70,        40,      812,   0.  0.  0.  0,   5, OldAP, 
12:34:56:78:90:ab, 2026-08-13 10:00:00, 2026-08-13 10:05:00, 11,  54, , , , -80,        10,        0,   0.  0.  0.  0,   4, Free, 

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
de:ad:be:ef:00:01, 2026-08-13 10:01:00, 2026-08-13 10:04:00, -50,       12, 00:11:22:33:44:55,
"""

AIRCRACK_OUT = """
                                Aircrack-ng 1.7

      [00:00:01] 1200/14344392 keys tested (1500.00 k/s)

      KEY FOUND! [ hunter2correct ]

      Master Key     : AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99
"""


def test_parse_iw_scan_extracts_aps():
    aps = scan.parse_iw_scan(IW_OUTPUT)
    assert len(aps) == 3
    cafe = aps[0]
    assert cafe["bssid"] == "00:11:22:33:44:55"
    assert cafe["ssid"] == "Cafe-Guest"
    assert cafe["channel"] == 1
    assert cafe["signal"] == -42.0
    assert cafe["security"] == "WPA2"


def test_parse_iw_scan_flags_wps_and_open():
    aps = scan.parse_iw_scan(IW_OUTPUT)
    assert aps[0]["wps"] is True
    assert aps[2]["security"] == "OPEN"


def test_parse_iw_scan_detects_sae():
    aps = scan.parse_iw_scan(IW_OUTPUT)
    assert aps[1]["security"] == "WPA3"


def test_parse_airodump_csv_reads_ap_section_only():
    aps = scan.parse_airodump_csv(AIRODUMP_CSV)
    assert [a["ssid"] for a in aps] == ["Home", "OldAP", "Free"]
    assert aps[1]["security"] == "WEP"
    assert aps[2]["security"] == "OPEN"
    assert aps[0]["beacons"] == 120


def test_ranked_puts_weakest_security_first():
    aps = scan.parse_airodump_csv(AIRODUMP_CSV)
    order = [a["security"] for a in scan.ranked(aps)]
    rank = ["OPEN", "WEP", "WPA", "WPA2", "WPA3"]
    assert order == sorted(order, key=rank.index)
    assert order[0] == "OPEN"
    assert order[-1] == "WPA2"


def test_aircrack_parse_recovers_key():
    hit = crack.aircrack_parse(AIRCRACK_OUT)
    assert hit["key"] == "hunter2correct"
    assert hit["printable"] is True


def test_aircrack_parse_returns_none_without_hit():
    assert crack.aircrack_parse("nothing here") is None


def test_mask_candidates_counts_keyspace():
    assert crack.mask_candidates("?d?d?d?d") == 10_000
    assert crack.mask_candidates("?l?l?d") == 26 * 26 * 10


@pytest.mark.parametrize("spec,expected", [
    ("1-3,6,11", [1, 2, 3, 6, 11]),
    ("36, 40 ,44", [36, 40, 44]),
    ("5-3", [3, 4, 5]),
    ("junk,6", [6]),
    ("", []),
])
def test_parse_channels(spec, expected):
    assert iface.parse_channels(spec) == expected


def test_monitor_name_is_idempotent():
    assert iface.monitor_name("wlan0") == "wlan0mon"
    assert iface.monitor_name("wlan0mon") == "wlan0mon"
