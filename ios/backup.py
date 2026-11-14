"""What a backup really contains, without a jailbreak.

A backup directory is a pile of hashed filenames next to ``Manifest.db`` — a
sqlite table mapping every hash back to ``<domain>/<relative path>``.
``backup2 list`` walks that table one screen at a time; this module turns it
into a searchable index, which is the only question that matters after a
backup has been taken:

    omni run ios.loot DIR=<backup> GREP=keychain

Everything here works on a plain directory, so an archive somebody else took —
or a tree already unpacked with ``backup2 unback`` — is just as usable, and the
whole thing is stdlib (``sqlite3`` + ``plistlib``), which is what makes it
testable offline.
"""

from __future__ import annotations

import os
import plistlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path

__all__ = ["Entry", "CATEGORIES", "categorise", "ManifestIndex", "sqlite_rows",
           "sqlite_tables", "read_plist", "search", "summarise"]

#: category -> the fragments that identify it in ``domain/relativePath``
CATEGORIES: dict[str, tuple[str, ...]] = {
    "keychain": ("keychain", "keybag"),
    "sms": ("sms.db", "library/sms", "sms/"),
    "whatsapp": ("chatstorage.sqlite", "msgstore.db", "whatsapp"),
    "calls": ("callhistory", "call_history.db"),
    "contacts": ("addressbook", "contacts.sqlite"),
    "notes": ("notestore", "notes.sqlite"),
    "cookies": ("cookies", "binarycookies", "safari"),
    "wifi": ("wifi", "airport", "networkinterfaces"),
    "location": ("routined", "locationd", "cached.sqlite"),
    "health": ("healthdb", "health"),
    "photos": ("media/dcim", "cameraroll", "photodata"),
    "secrets": ("password", "credential", "oauth", "token", "secret"),
}

#: what the Files table is called on every iOS 10+ backup
FILES_TABLE = "Files"


@dataclass(frozen=True)
class Entry:
    """One file of a backup, as the manifest describes it."""

    file_id: str
    domain: str = ""
    relative_path: str = ""
    flags: int = 0

    @property
    def domain_path(self) -> str:
        return f"{self.domain}/{self.relative_path}".strip("/")

    @property
    def name(self) -> str:
        return os.path.basename(self.relative_path.rstrip("/"))

    def categories(self) -> list[str]:
        return categorise(self.domain, self.relative_path)

    def to_row(self) -> list[str]:
        return [self.domain, self.relative_path, ",".join(self.categories())
                or "-"]


def categorise(domain: str, relative_path: str) -> list[str]:
    """Which categories a manifest path falls into (possibly none)."""
    haystack = f"{domain}/{relative_path}".lower()
    return [name for name, needles in CATEGORIES.items()
            if any(needle in haystack for needle in needles)]


def _connect(path: str) -> sqlite3.Connection:
    """Open read-only, via a file URI so the path can hold spaces/drive colons."""
    try:
        uri = Path(path).expanduser().resolve().as_uri() + "?mode=ro"
        return sqlite3.connect(uri, uri=True)
    except (ValueError, sqlite3.Error):
        return sqlite3.connect(path)


def sqlite_rows(path: str, sql: str, params: tuple = ()) -> list[dict]:
    """Rows of a read-only query; ``[]`` when the file is not a database."""
    if not os.path.isfile(path):
        return []
    try:
        conn = _connect(path)
    except sqlite3.Error:
        return []
    try:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(sql, params)]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def sqlite_tables(path: str) -> list[str]:
    """Table names in a sqlite file (empty list if it cannot be read)."""
    return [row["name"] for row in sqlite_rows(
        path, "SELECT name FROM sqlite_master WHERE type='table' "
              "ORDER BY name")]


def read_plist(path: str) -> object:
    """Parse a plist (xml or binary); ``{}`` when it cannot be read."""
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}



class ManifestIndex:
    """A searchable view of one backup directory (encrypted or not)."""

    def __init__(self, root: str):
        self.root = os.path.expanduser(root)
        self.manifest = self._find_manifest()
        self._entries: list[Entry] | None = None
        self.unpacked = not self.manifest

    def _find_manifest(self) -> str:
        for name in ("Manifest.db", "Manifest.plist"):
            candidate = os.path.join(self.root, name)
            if os.path.isfile(candidate):
                return candidate
        return ""

    @property
    def available(self) -> bool:
        return bool(self.manifest) or os.path.isdir(self.root)

    def entries(self) -> list[Entry]:
        """Every file the manifest (or the unpacked tree) knows about."""
        if self._entries is not None:
            return self._entries
        if self.manifest.endswith(".db"):
            rows = sqlite_rows(
                self.manifest,
                "SELECT fileID, domain, relativePath, flags FROM "
                f"{FILES_TABLE}")
            self._entries = [Entry(str(row.get("fileID") or ""),
                                   str(row.get("domain") or ""),
                                   str(row.get("relativePath") or ""),
                                   int(row.get("flags") or 0))
                             for row in rows]
        elif self.manifest:
            self._entries = self._entries_from_plist()
        else:
            self._entries = self._entries_from_tree()
        return self._entries

    def _entries_from_plist(self) -> list[Entry]:
        data = read_plist(self.manifest)
        entries: list[Entry] = []
        if isinstance(data, dict):
            for domain, files in (data.get("Files") or {}).items():
                if not isinstance(files, dict):
                    continue
                for name, meta in files.items():
                    meta = meta if isinstance(meta, dict) else {}
                    entries.append(Entry(str(meta.get("FileID") or ""),
                                         str(domain), str(name),
                                         int(meta.get("Flags") or 0)))
        return entries

    def _entries_from_tree(self) -> list[Entry]:
        """An unpacked backup: ``<root>/<domain>/<relative path>``."""
        entries: list[Entry] = []
        for current, _dirs, names in os.walk(self.root):
            for name in names:
                full = os.path.join(current, name)
                relative = os.path.relpath(full, self.root).replace("\\", "/")
                if "/" not in relative:
                    continue                # Manifest/info at the top level
                domain, _, rest = relative.partition("/")
                entries.append(Entry("", domain, rest))
        return entries

    # -- queries -----------------------------------------------------------
    def search(self, terms: list[str]) -> list[Entry]:
        """Entries whose domain/path contain *all* terms (case-insensitive)."""
        return search(self.entries(), terms)

    def by_category(self, category: str = "") -> dict[str, list[Entry]]:
        """Entries grouped by category, or one category when named."""
        grouped: dict[str, list[Entry]] = {}
        for entry in self.entries():
            for name in entry.categories():
                if category and name != category:
                    continue
                grouped.setdefault(name, []).append(entry)
        return grouped

    def blob(self, entry: Entry) -> str:
        """The on-disk file for a manifest entry ('' when it is not here)."""
        candidates: list[str] = []
        if entry.file_id:
            candidates += [os.path.join(self.root, entry.file_id[:2],
                                        entry.file_id),
                           os.path.join(self.root, entry.file_id)]
        if entry.relative_path:                  # unpacked tree layout
            candidates += [os.path.join(self.root, entry.domain,
                                        entry.relative_path),
                           os.path.join(self.root, entry.domain_path)]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        return ""

    def read(self, entry: Entry) -> bytes:
        path = self.blob(entry)
        if not path:
            return b""
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except OSError:
            return b""


def search(entries: list[Entry], terms: list[str]) -> list[Entry]:
    """Filter entries by terms, keeping manifest order."""
    needles = [t.lower() for t in terms if t]
    if not needles:
        return list(entries)
    return [entry for entry in entries
            if all(needle in entry.domain_path.lower() for needle in needles)]


def summarise(entries: list[Entry]) -> list[list[str]]:
    """Table rows: category / files / one example path."""
    grouped: dict[str, list[Entry]] = {}
    for entry in entries:
        for name in entry.categories() or ["(uncategorised)"]:
            grouped.setdefault(name, []).append(entry)
    rows = []
    for name in sorted(grouped):
        bucket = grouped[name]
        rows.append([name, str(len(bucket)), bucket[0].domain_path[:52]])
    return rows
