"""Flipper file-format tests: round-trips for .ir / .ibtn and the index."""

import os

import pytest

from omni.flip import files, firmware, ibutton, ir


@pytest.fixture
def ir_text():
    return (
        "Filetype: Flipper IR Library\nVersion: 1\n#\n"
        "#\n# name: Samsung_TV\ntype: parsed\nprotocol: Samsung32\n"
        "address: 07 00\ncommand: 06 00\n#\n"
    )


@pytest.fixture
def ibtn_text():
    return ("Filetype: Flipper iButton key\nVersion: 2\n"
            "Name: gate\nProtocol: DS1990\nData: 01 02 03 04 05 06 07 08\n")


def test_ir_parse_and_save(ir_text, tmp_path):
    parsed = ir.parse(ir_text)
    assert parsed.summary()
    names = [s.name for s in parsed.signals]
    assert "Samsung_TV" in names
    out = tmp_path / "out.ir"
    ir.save(parsed.signals, str(out))
    reparsed = ir.load(str(out))
    assert parsed.summary() == reparsed.summary()


def test_ibtn_roundtrip(ibtn_text, tmp_path):
    key = ibutton.parse(ibtn_text)
    assert key.protocol == "DS1990"
    assert key.data == "0102030405060708"
    out = tmp_path / "gate.ibtn"
    ibutton.save(key, str(out), name="gate")
    assert ibutton.load(str(out)).data == key.data


def test_index_dir_skips_other_files(tmp_path, ir_text):
    (tmp_path / "remote.ir").write_text(ir_text)
    (tmp_path / "notes.txt").write_text("not a flipper file")
    rows = files.index_dir(str(tmp_path))
    assert len(rows) == 1 and rows[0]["kind"] == "ir"


def test_firmware_describe():
    caps = firmware.describe("flipper_zero")
    assert caps["subghz"] and caps["sd"]
    assert firmware.raw_preset_check("02 11 90 0C ")
    assert not firmware.raw_preset_check("nope")
