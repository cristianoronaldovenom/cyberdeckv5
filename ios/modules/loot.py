"""Backup-side takeover: index the archive, then lift the goods.

``ios.backup`` takes the archive; these two modules answer what is *in* it —
offline, with no device and no jailbreak:

* ``ios.loot`` — category summary plus a search over ``Manifest.db``, with an
  optional copy-out of every match (keychain blobs, ``sms.db``, WhatsApp's
  ``ChatStorage.sqlite``, Safari cookies, Health, the routined location cache);
* ``ios.keychain`` — the keychain database itself: which services and accounts
  are stored, and how big each encrypted blob is (``ios.keybag`` produces the
  keybag that unwraps them).

Both run on a live backup directory or on a tree already unpacked with
``backup2 unback``.
"""

from __future__ import annotations

import json
import os
import shutil
import time

from omni.core import config, console
from omni.core.module import Module, Option
from omni.ios import backup

__all__ = ["Loot", "Keychain"]

#: keychain tables that hold user secrets
KEYCHAIN_TABLES = ("genp", "inet", "cert", "keys")


class Loot(Module):
    NAME = "ios.loot"
    DESCRIPTION = "Index a backup, search it, and copy out what matters"
    FAMILY = "ios"
    OPTIONS = (Option("DIR", "backup directory (or unpacked tree)", "",
                       required=True),
               Option("GREP", "only paths containing this text"),
               Option("CATEGORY", "keychain|sms|whatsapp|cookies|..."),
               Option("LIMIT", "rows to print", "40"),
               Option("EXTRACT", "copy every match into OUT", "false",
                      choices=("true", "false")),
               Option("OUT", "copy-out directory"))

    def index(self) -> backup.ManifestIndex:
        path = os.path.expanduser(self.get("DIR"))
        if not os.path.isdir(path):
            raise FileNotFoundError(f"no such backup directory: {path}")
        index = backup.ManifestIndex(path)
        if not index.available:
            raise RuntimeError(
                f"{path} has no Manifest.db and no domain folders — point "
                "DIR at the backup root, not at a hashed subdirectory")
        return index

    def matches(self, index: backup.ManifestIndex) -> list[backup.Entry]:
        """Entries selected by CATEGORY and GREP."""
        category = self.get("CATEGORY").strip().lower()
        terms = [t for t in self.get("GREP").split() if t]
        entries = index.entries()
        if category:
            entries = index.by_category(category).get(category, [])
        return backup.search(entries, terms)

    def execute(self) -> dict:
        index = self.index()
        entries = index.entries()
        if not entries:
            raise RuntimeError("the manifest lists no files — an encrypted "
                               "Manifest.db needs the backup password")
        console.kv([("backup", index.root),
                    ("manifest", index.manifest or "(unpacked tree)"),
                    ("files", len(entries))])
        console.table(["category", "files", "example"],
                      backup.summarise(entries))

        matches = self.matches(index)
        limit = max(1, self.get_int("LIMIT", 40))
        console.table(["domain", "path", "category"],
                      [entry.to_row() for entry in matches[:limit]])
        if not matches:
            console.warn("nothing matched — try CATEGORY=keychain or a "
                         "broader GREP")
            return {"files": len(entries), "matched": 0}

        result: dict = {"files": len(entries), "matched": len(matches),
                        "categories": sorted({c for e in matches
                                              for c in e.categories()}),
                        "paths": [e.domain_path for e in matches[:limit]]}
        if self.get_bool("EXTRACT"):
            target = os.path.expanduser(
                self.get("OUT") or
                os.path.join(config.output_dir("ios/loot"),
                             f"loot_{time.strftime('%Y%m%d_%H%M%S')}"))
            os.makedirs(target, exist_ok=True)
            copied: list[str] = []
            missing: list[str] = []
            for entry in matches:
                blob = index.blob(entry)
                if not blob:
                    missing.append(entry.domain_path)
                    continue
                name = (f"{entry.domain.replace('/', '_')}_"
                        f"{entry.name or entry.file_id}")
                destination = os.path.join(target, name[:160])
                shutil.copyfile(blob, destination)
                copied.append(destination)
            result.update({"out": target, "copied": copied,
                           "missing": missing})
            console.ok(f"{len(copied)} file(s) -> {target}")
            if missing:
                console.warn(f"{len(missing)} entr(ies) have no local blob "
                             "(encrypted backup, or not downloaded yet)")
        console.ok(f"{len(matches)} match(es) of {len(entries)} file(s)")
        return result



class Keychain(Module):
    NAME = "ios.keychain"
    DESCRIPTION = "Read a backup's keychain DB (services, accounts, blob sizes)"
    FAMILY = "ios"
    OPTIONS = (Option("DIR", "backup directory (or unpacked tree)", "",
                       required=True),
               Option("ACTION", "summary|items|dump", "summary",
                      choices=("summary", "items", "dump")),
               Option("TABLE", "genp|inet|cert|keys", "genp",
                      choices=KEYCHAIN_TABLES),
               Option("GREP", "only rows whose service/account matches"),
               Option("LIMIT", "rows to print", "40"),
               Option("OUT", "JSON path for ACTION=dump"))

    #: databases the keychain lives in, best first
    NAMES = ("keychain-2.db", "keychain.db", "keychain-backup.plist")

    def database(self) -> str:
        """Path to the keychain database inside this backup."""
        index = backup.ManifestIndex(os.path.expanduser(self.get("DIR")))
        for entry in index.entries():
            if entry.name in self.NAMES:
                blob = index.blob(entry)
                if blob:
                    return blob
        for name in self.NAMES:                 # unpacked tree fallback
            candidate = os.path.join(index.root, "KeychainDomain", name)
            if os.path.isfile(candidate):
                return candidate
        raise FileNotFoundError(
            "no keychain database in this backup — KeychainDomain is absent "
            "when the backup was taken without a password (or was pruned)")

    @staticmethod
    def columns(path: str, table: str) -> list[str]:
        return [str(row.get("name")) for row in
                backup.sqlite_rows(path, f"PRAGMA table_info({table})")]

    def items(self, path: str) -> list[dict]:
        """Rows of the requested keychain table, secrets left encrypted."""
        table = self.get("TABLE")
        columns = self.columns(path, table)
        wanted = [name for name in ("svce", "acct", "data", "mdat")
                  if name in columns]
        if not wanted:
            return []
        rows = backup.sqlite_rows(
            path, f"SELECT {', '.join(wanted)} FROM {table}")
        needle = self.get("GREP").strip().lower()
        out: list[dict] = []
        for row in rows:
            blob = row.get("data") or b""
            size = len(blob) if isinstance(blob, (bytes, bytearray)) else 0
            item = {"service": str(row.get("svce") or ""),
                    "account": str(row.get("acct") or ""),
                    "bytes": size, "encrypted": size > 44,
                    "modified": row.get("mdat") or 0}
            if needle and needle not in (f"{item['service']} "
                                          f"{item['account']}").lower():
                continue
            out.append(item)
        return out

    def execute(self) -> dict:
        path = self.database()
        tables = backup.sqlite_tables(path)
        if not tables:
            raise RuntimeError(f"{path} is not a readable sqlite database "
                               "(an encrypted keychain plist?)")
        counts = {name: len(backup.sqlite_rows(
            path, f"SELECT 1 FROM {name}")) if name in tables else 0
            for name in KEYCHAIN_TABLES}
        console.kv([("database", path), ("tables", len(tables))])
        console.table(["table", "rows"],
                      [[name, str(count)] for name, count in counts.items()])

        if self.get("ACTION") == "summary":
            console.ok(f"{sum(counts.values())} keychain item(s); "
                       f"run ACTION=items for services/accounts")
            return {"database": path, "counts": counts}

        items = self.items(path)
        console.table(["service", "account", "blob"],
                      [[item["service"][:34], item["account"][:28],
                        str(item["bytes"])]
                       for item in items[:max(1, self.get_int("LIMIT", 40))]])
        result: dict = {"database": path, "counts": counts, "items": items}
        if self.get("ACTION") == "dump":
            out = os.path.expanduser(
                self.get("OUT") or os.path.join(
                    config.output_dir("ios/keychain"),
                    f"keychain_{time.strftime('%Y%m%d_%H%M%S')}.json"))
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(items, indent=2) + "\n")
            result["path"] = out
            console.info(f"dumped {len(items)} item(s) -> {out}")
        console.ok(f"{len(items)} item(s) in {self.get('TABLE')}")
        return result
