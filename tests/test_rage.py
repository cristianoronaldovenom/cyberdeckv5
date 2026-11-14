"""Aggressive deauth / reconnect tests: client parsing and kick loops."""

import pytest

from omni.wifi.modules import rage, reconnect


# -- station parsing --------------------------------------------------------

AIRODUMP_CSV = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2026-01-01 10:00:00, 2026-01-01 10:05:00, 6, 54, WPA2, CCMP, PSK, -45, 100, 0, , 8, Office,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2026-01-01 10:01:00, 2026-01-01 10:05:00, -60, 12, AA:BB:CC:DD:EE:FF, Office
77:88:99:AA:BB:CC, 2026-01-01 10:02:00, 2026-01-01 10:05:00, -70, 4, AA:BB:CC:DD:EE:FF,
"""


def test_parse_clients_finds_stations():
    clients = rage.parse_clients(AIRODUMP_CSV)
    assert "11:22:33:44:55:66" in clients
    assert "77:88:99:AA:BB:CC" in clients


def test_parse_clients_ignores_the_ap_row():
    assert "AA:BB:CC:DD:EE:FF" not in rage.parse_clients(AIRODUMP_CSV)


def test_parse_clients_can_filter_by_bssid():
    found = rage.parse_clients(AIRODUMP_CSV, "aa:bb:cc:dd:ee:ff")
    assert len(found) == 2


def test_parse_clients_drops_broadcast():
    text = "FF:FF:FF:FF:FF:FF, a, b, -60, 1, AA:BB:CC:DD:EE:FF, x\n"
    assert rage.parse_clients(text) == []


def test_parse_clients_dedupes():
    text = ("11:22:33:44:55:66, a, b, -60, 1, AA:BB:CC:DD:EE:FF, x\n"
            "11:22:33:44:55:66, a, b, -61, 2, AA:BB:CC:DD:EE:FF, x\n")
    assert rage.parse_clients(text) == ["11:22:33:44:55:66"]


def test_parse_clients_on_empty_input():
    assert rage.parse_clients("") == []


def test_parse_clients_skips_the_csv_header():
    header = ("Station MAC, First time seen, Last time seen, Power, "
              "# packets, BSSID, Probed ESSIDs\n")
    assert rage.parse_clients(header) == []


# -- reason codes -----------------------------------------------------------

def test_default_reasons_start_with_the_classic_kick():
    assert rage.REASONS[0] == 7


def test_reasons_are_parsed_from_options():
    mod = rage.DeauthRage(BSSID="AA:BB:CC:DD:EE:FF", REASONS="1,4")
    assert mod._reasons() == [1, 4]


def test_reasons_fall_back_when_garbage():
    mod = rage.DeauthRage(BSSID="AA:BB:CC:DD:EE:FF", REASONS="x,y")
    assert mod._reasons() == list(rage.REASONS)


# -- kick loop --------------------------------------------------------------

@pytest.fixture
def stubbed(monkeypatch):
    """Stub the monitor switch, discovery and aireplay so the loop runs offline."""
    calls: list[tuple] = []

    def fake_deauth(mon, bssid, client, count, reason=None):
        calls.append((mon, bssid, client, count))
        return type("R", (), {"code": 0, "ok": True, "out": "", "err": "",
                              "text": ""})

    monkeypatch.setattr("omni.wifi.capture.deauth", fake_deauth)
    monkeypatch.setattr(rage.WifiModule, "monitor", lambda self: "wlan0mon")
    monkeypatch.setattr(rage.WifiModule, "restore", lambda self, mon: None)
    monkeypatch.setattr(rage.DeauthRage, "_discover",
                        lambda self, mon, seconds: [])
    return calls


def test_rage_kicks_every_given_client(stubbed):
    mod = rage.DeauthRage(BSSID="aa:bb:cc:dd:ee:ff",
                          CLIENTS="11:22:33:44:55:66,77:88:99:aa:bb:cc",
                          RUNTIME="3", BURST="3", REFRESH="99")
    result = mod.execute()
    assert result["frames"] > 0
    assert result["clients"] == ["11:22:33:44:55:66", "77:88:99:AA:BB:CC"]
    assert {c[2] for c in stubbed} == {"11:22:33:44:55:66",
                                       "77:88:99:AA:BB:CC"}


def test_rage_upserts_bssid_and_burst(stubbed):
    mod = rage.DeauthRage(BSSID="aa:bb:cc:dd:ee:ff",
                          CLIENTS="11:22:33:44:55:66", RUNTIME="3", BURST="7")
    mod.execute()
    assert stubbed[0][1] == "AA:BB:CC:DD:EE:FF"
    assert stubbed[0][3] == 7


def test_rage_falls_back_to_broadcast(stubbed):
    result = rage.DeauthRage(BSSID="aa:bb:cc:dd:ee:ff",
                             RUNTIME="3").execute()
    assert result["clients"] == [rage.BROADCAST]


def test_rage_reports_reason_list(stubbed):
    result = rage.DeauthRage(BSSID="aa:bb:cc:dd:ee:ff",
                             CLIENTS="11:22:33:44:55:66",
                             RUNTIME="3").execute()
    assert result["reasons"] == list(rage.REASONS)


# -- reconnect --------------------------------------------------------------

def test_reconnect_defaults_to_broadcast_target(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr("omni.wifi.capture.deauth",
                        lambda mon, bssid, client, count, reason=None: (
                            calls.append((client, count)),
                            type("R", (), {"code": 0, "ok": True, "out": "",
                                           "err": "", "text": ""}))[1])
    monkeypatch.setattr(reconnect.WifiModule, "monitor", lambda self: "w0")
    monkeypatch.setattr(reconnect.WifiModule, "restore", lambda self, m: None)
    result = reconnect.Reconnect(BSSID="aa:bb:cc:dd:ee:ff",
                                 SECONDS="3", CYCLE="1",
                                 BEACON="false").execute()
    assert result["targets"] == 1
    assert calls and calls[0][0] == "FF:FF:FF:FF:FF:FF"


def test_reconnect_exposes_reason_cycle():
    assert len(reconnect.REASONS) == len(set(reconnect.REASONS)) == 6
