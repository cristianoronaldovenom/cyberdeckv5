"""Backup-side iPhone takeover: manifest index, search, keychain, HID flows.

Everything runs on a synthetic backup layout (``Manifest.db`` plus hashed
blobs), so the archive logic is exercised with no device, no pymobiledevice3
and no real backup.
"""

import os
import sqlite3

import pytest

from omni.ios import backup
from omni.ios.modules.automate import normalise
from omni.ios.modules.loot import Keychain, Loot

#: the tables ``keychain-2.db`` actually carries
KEYCHAIN_DDL = """
CREATE TABLE genp (svce TEXT, acct TEXT, data BLOB, mdat INTEGER);
CREATE TABLE inet (svce TEXT, acct TEXT, data BLOB);
CREATE TABLE cert (data BLOB);
CREATE TABLE keys (data BLOB);
"""

KEYCHAIN_ROWS = [
    ("AirPort", "home-wifi", b"\x00" * 60, 1700000000),
    ("Facebook", "alice@example.com", b"\x01" * 80, 1700000500),
]


def _sqlite(path: str, script: str, rows: list[tuple] = ()) -> str:
    """Create a small sqlite file (a real one, not a stub)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(script)
        if rows:
            conn.executemany("INSERT INTO genp VALUES (?, ?, ?, ?)", rows)
        conn.commit()
    finally:
        conn.close()
    return path


def _blob(root: str, file_id: str, payload: str | None = None) -> str:
    """Where a manifest entry's bytes live in a real backup."""
    path = os.path.join(root, file_id[:2], file_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if payload is not None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(payload)
    return path


@pytest.fixture
def backup_dir(tmp_path):
    root = str(tmp_path / "backup")
    os.makedirs(root)
    manifest = _sqlite(
        os.path.join(root, "Manifest.db"),
        "CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT,"
        " flags INTEGER);",
    )
    entries = [
        ("0a" * 20, "KeychainDomain", "keychain-2.db", 1),
        ("1b" * 20, "HomeDomain", "Library/SMS/sms.db", 1),
        ("2c" * 20, "AppDomain-com.whatsapp", "Documents/ChatStorage.sqlite", 1),
        ("3d" * 20, "CameraRollDomain", "Media/DCIM/IMG_0001.JPG", 1),
    ]
    conn = sqlite3.connect(manifest)
    try:
        conn.executemany("INSERT INTO Files VALUES (?, ?, ?, ?)", entries)
        conn.commit()
    finally:
        conn.close()
    _sqlite(_blob(root, "0a" * 20), KEYCHAIN_DDL, KEYCHAIN_ROWS)
    _sqlite(_blob(root, "1b" * 20), "CREATE TABLE message (text TEXT);")
    _blob(root, "2c" * 20, "not really a database")
    _blob(root, "3d" * 20, "jpeg bytes")
    return root


# -- the index ---------------------------------------------------------------

def test_entries_come_out_of_the_manifest(backup_dir):
    index = backup.ManifestIndex(backup_dir)
    assert index.available and not index.unpacked
    entries = index.entries()
    assert [entry.name for entry in entries] == [
        "keychain-2.db", "sms.db", "ChatStorage.sqlite", "IMG_0001.JPG"]
    assert entries[1].domain_path == "HomeDomain/Library/SMS/sms.db"


def test_categories_are_what_makes_the_archive_usable(backup_dir):
    index = backup.ManifestIndex(backup_dir)
    grouped = index.by_category()
    assert set(grouped) >= {"keychain", "sms", "whatsapp", "photos"}
    assert backup.categorise("HomeDomain", "Library/SMS/sms.db") == ["sms"]
    assert backup.categorise("HomeDomain", "Library/Preferences/x.plist") == []


def test_summary_rows_count_each_category(backup_dir):
    rows = backup.summarise(backup.ManifestIndex(backup_dir).entries())
    labels = [row[0] for row in rows]
    assert "keychain" in labels and "photos" in labels
    assert dict((row[0], row[1]) for row in rows)["sms"] == "1"


def test_search_is_a_substring_match_on_the_domain_path(backup_dir):
    index = backup.ManifestIndex(backup_dir)
    assert len(index.search(["sms.db"])) == 1
    assert len(index.search(["whatsapp"])) == 1
    assert len(index.search(["nothing-like-this"])) == 0
    assert len(index.search([])) == 4


def test_a_blob_is_found_and_read_back(backup_dir):
    index = backup.ManifestIndex(backup_dir)
    entry = index.search(["whatsapp"])[0]
    assert os.path.isfile(index.blob(entry))
    assert index.read(entry) == b"not really a database"


def test_an_unpacked_tree_is_indexed_too(tmp_path):
    tree = tmp_path / "unpacked"
    (tree / "HomeDomain" / "Library" / "SMS").mkdir(parents=True)
    (tree / "HomeDomain" / "Library" / "SMS" / "sms.db").write_text("x")
    (tree / "Info.plist").write_text("not a manifest")
    index = backup.ManifestIndex(str(tree))
    assert index.unpacked and index.manifest == ""
    entries = index.entries()
    assert [entry.name for entry in entries] == ["sms.db"]
    assert entries[0].domain == "HomeDomain"
    assert os.path.isfile(index.blob(entries[0]))



# -- the modules -------------------------------------------------------------

def test_loot_searches_the_archive_without_a_device(backup_dir):
    report = Loot(DIR=backup_dir, GREP="sms").run()
    assert report["files"] == 4 and report["matched"] == 1
    assert report["paths"] == ["HomeDomain/Library/SMS/sms.db"]


def test_loot_extracts_the_matches_it_found(backup_dir, tmp_path):
    out = str(tmp_path / "loot")
    report = Loot(DIR=backup_dir, CATEGORY="whatsapp", EXTRACT="true",
                  OUT=out).run()
    assert report["matched"] == 1 and len(report["copied"]) == 1
    copied = report["copied"][0]
    assert os.path.isfile(copied)
    assert "ChatStorage.sqlite" in os.path.basename(copied)


def test_loot_refuses_a_directory_that_is_not_a_backup(tmp_path):
    with pytest.raises(FileNotFoundError):
        Loot(DIR=str(tmp_path / "nope")).run()


def test_keychain_summarises_the_tables_it_finds(backup_dir):
    report = Keychain(DIR=backup_dir).run()
    assert report["counts"]["genp"] == 2
    assert report["counts"]["inet"] == 0
    assert backup.sqlite_tables(report["database"]).count("genp") == 1


def test_keychain_lists_services_and_accounts(backup_dir):
    report = Keychain(DIR=backup_dir, ACTION="items").run()
    services = [item["service"] for item in report["items"]]
    assert services == ["AirPort", "Facebook"]
    assert report["items"][0]["encrypted"] is True
    assert report["items"][0]["bytes"] == 60


def test_keychain_greps_and_dumps_json(backup_dir, tmp_path):
    out = str(tmp_path / "kc.json")
    report = Keychain(DIR=backup_dir, ACTION="dump", GREP="facebook",
                      OUT=out).run()
    assert [item["account"] for item in report["items"]] == [
        "alice@example.com"]
    with open(report["path"], encoding="utf-8") as fh:
        assert "Facebook" in fh.read()


def test_keychain_without_a_keychain_domain_is_a_clear_failure(tmp_path):
    root = tmp_path / "nochain"
    (root / "HomeDomain").mkdir(parents=True)
    (root / "HomeDomain" / "x.plist").write_text("y")
    with pytest.raises(FileNotFoundError):
        Keychain(DIR=str(root)).run()


# -- HID flows ---------------------------------------------------------------

def test_coordinates_accept_fractions_and_raw_normalised_values():
    assert normalise("0.5,0.5") == (32768, 32768)
    assert normalise("0,1") == (0, 65535)
    assert normalise("32768,60000") == (32768, 60000)
    assert normalise("9,9") == (9, 9)
    with pytest.raises(ValueError):
        normalise("nowhere")


def test_ios_takeover_modules_are_registered():
    from omni.core.module import registry

    names = {module.NAME for module in registry.all("ios")}
    assert {"ios.loot", "ios.keychain", "ios.automate"} <= names
