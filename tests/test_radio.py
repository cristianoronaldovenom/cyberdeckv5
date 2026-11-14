"""Radio parser tests: spectrum, sensors, IR, RFID, capability, BT."""

import pytest

from omni.radio import bluetooth, capability, ir, rfid, spectrum


# -- spectrum ---------------------------------------------------------------

RTL_POWER = ("2026-08-13, 10:00:00, 433000000, 433100000, 10000.0, 200, "
             "-42.5, -61.0, -33.2, -70.1\n"
             "2026-08-13, 10:00:01, 433100000, 433200000, 10000.0, 200, "
             "-55.0, -48.3\n")


def test_band_lookup():
    assert spectrum.band("ism433")[0] < spectrum.band("ism433")[1]
    with pytest.raises(ValueError):
        spectrum.band("nope")


def test_parse_rtl_power_maps_bins_to_frequencies():
    rows = spectrum.parse_rtl_power(RTL_POWER)
    assert len(rows) == 6
    assert rows[0] == {"hz": 433_000_000, "db": -42.5}
    assert rows[3]["hz"] == 433_030_000


def test_parse_rtl_power_ignores_junk():
    assert spectrum.parse_rtl_power("garbage\n\n") == []


def test_peaks_ranks_strongest_and_spaces_them():
    rows = [{"hz": 433_000_000, "db": -30.0},
            {"hz": 433_010_000, "db": -31.0},
            {"hz": 433_200_000, "db": -80.0},
            {"hz": 433_300_000, "db": -40.0}]
    tops = spectrum.peaks(rows, count=5, floor=-60)
    assert [p["hz"] for p in tops] == [433_000_000, 433_300_000]
    assert tops[0]["mhz"] == 433.0


def test_peaks_respects_floor():
    rows = [{"hz": 1, "db": -90.0}]
    assert spectrum.peaks(rows, floor=-60) == []


RTL433 = '{"model":"Acurite-Tower","id":1234,"freq":433.9,"rssi":-12.5,"channel":"A"}\n'
RTL433 += "not json\n"


def test_parse_rtl433_json_extracts_fields():
    rows = spectrum.parse_rtl433_json(RTL433)
    assert len(rows) == 1
    assert rows[0]["model"] == "Acurite-Tower"
    assert rows[0]["id"] == "1234"
    assert rows[0]["channel"] == "A"


def test_sensor_lines_render():
    line = spectrum.sensor_lines(spectrum.parse_rtl433_json(RTL433))[0]
    assert "Acurite-Tower" in line and "rssi=-12.5" in line


# -- IR ---------------------------------------------------------------------

def test_parse_mode2_pairs_pulses_and_spaces():
    pairs = ir.parse_mode2("pulse 560\nspace 1690\ntimeout 5000\npulse 560\n")
    assert pairs == [(True, 560), (False, 1690), (True, 560)]


def test_to_answer_file_roundtrip(tmp_path):
    path = tmp_path / "a.ir"
    ir.to_answer_file([(True, 560), (False, 1690)], str(path))
    assert path.read_text().splitlines() == ["pulse 560", "space 1690"]


# -- RFID -------------------------------------------------------------------

PM3_OUT = """[+] Searching 125 kHz
[+] EM 410x ID 3A0F2B1C4D
[+] HID Prox TAG ID: 2006ec3a28
"""


def test_parse_pm3_tags_extracts_uid_and_protocol():
    tags = rfid.parse_pm3_tags(PM3_OUT)
    assert {"uid": "3A0F2B1C4D", "protocol": "EM410"} in tags
    assert any(t["protocol"] == "HID Prox" for t in tags)


def test_parse_pm3_tags_without_tags_is_empty():
    assert rfid.parse_pm3_tags("[+] no tag found") == []


def test_hid_formats_cover_common_families():
    for name in ("em4100", "hidprox", "indala", "awid"):
        assert name in rfid.HID_FORMATS


NFC_OUT = "NFC device: ACS / ACR122U opened\n\tUID (4 bytes): 11 22 33 44\n"


def test_parse_nfc_list_reads_uid():
    tags = rfid.parse_nfc_list(NFC_OUT)
    assert tags[0]["uid"] == "11 22 33 44"
    assert "ACR122U" in tags[0]["description"]


# -- Bluetooth --------------------------------------------------------------

INQUIRY = "Scanning ...\n\t00:1A:7D:DA:71:13\tiPhone\n\tAA:BB:CC:DD:EE:FF\tCarKit\n"


def test_parse_inquiry_extracts_address_and_name():
    rows = bluetooth.parse_inquiry(INQUIRY)
    assert rows == [{"address": "00:1A:7D:DA:71:13", "name": "iPhone"},
                    {"address": "AA:BB:CC:DD:EE:FF", "name": "CarKit"}]


def test_parse_ble_skips_banner():
    rows = bluetooth.parse_ble("LE Scan ...\n11:22:33:44:55:66\tBeacon\n")
    assert rows == [{"address": "11:22:33:44:55:66", "name": "Beacon"}]


# -- capability -------------------------------------------------------------

def test_probe_reports_every_known_device():
    assert set(capability.probe()) == set(capability.HARDWARE)


def test_parse_hexdump_joins_valid_lines():
    text = "aa bb cc\nnot hex\ndd ee\n"
    assert capability.parse_hexdump(text) == "aabbccddee"


def test_band_table_exposes_bands():
    names = [row["name"] for row in capability.band_table()]
    assert "ism433" in names
