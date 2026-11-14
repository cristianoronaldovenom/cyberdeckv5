"""iOS filesystem access over the CoreDevice file service (Developer Mode).

The developer tunnel exposes a file service with named domains, which is how
you reach app containers without a jailbreak:

* ``appData`` — every installed app's sandbox (chat DBs, tokens, prefs)
* ``root`` — the read-only system volume
* ``temporary`` — /tmp
* ``systemCrashLogs`` — crash reports

``ios.afc`` covers /var/mobile/Media on a stock device; this covers everything
else and needs Developer Mode plus the tunnel.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.ios.modules._base import IosModule

__all__ = ["Ls", "Pull", "Push", "Rm", "Mkdir", "Apps"]

#: valid file-service domains
DOMAINS = ("appData", "root", "temporary", "systemCrashLogs")


class Ls(IosModule):
    NAME = "ios.ls"
    DESCRIPTION = "List a device directory in a domain (appData, root, ...)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("DOMAIN", "domain to browse", "appData",
                      choices=DOMAINS, required=True),
               Option("PATH", "path inside the domain", ".", required=True),
               Option("BUNDLE", "app bundle id (narrows appData)"))

    def execute(self) -> dict:
        args = ["developer", "core-device", "list-directory", self.get("DOMAIN"),
                self.get("PATH")]
        if self.get("BUNDLE"):
            args += ["--identifier", self.get("BUNDLE")]
        out = self.client().check(*args, timeout=180).out
        entries = [line for line in out.splitlines() if line.strip()]
        for entry in entries[:400]:
            console.info(entry)
        console.ok(f"{len(entries)} entr(ies)")
        return {"domain": self.get("DOMAIN"), "path": self.get("PATH"),
                "entries": entries}


class Pull(IosModule):
    NAME = "ios.pull"
    DESCRIPTION = "Read any file from a domain into loot (app sandboxes too)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("DOMAIN", "domain to read from", "appData",
                      choices=DOMAINS, required=True),
               Option("PATH", "path inside the domain", "", required=True),
               Option("BUNDLE", "app bundle id (narrows appData)"),
               Option("OUT", "local destination file"))

    def execute(self) -> dict:
        remote = self.get("PATH")
        out = os.path.expanduser(
            self.get("OUT") or
            os.path.join(config.output_dir("ios/fs"),
                         f"{time.strftime('%H%M%S')}_"
                         f"{os.path.basename(remote) or 'file'}"))
        parent = os.path.dirname(out)
        if parent:
            os.makedirs(parent, exist_ok=True)
        args = ["developer", "core-device", "read-file", self.get("DOMAIN"),
                remote, "--output", out]
        if self.get("BUNDLE"):
            args += ["--identifier", self.get("BUNDLE")]
        self.client().check(*args, timeout=600)
        size = os.path.getsize(out) if os.path.isfile(out) else 0
        if not size:
            console.warn("empty file — check the domain/path and the bundle id")
        else:
            console.ok(f"{size} byte(s) -> {out}")
        return {"path": out, "bytes": size}


class Push(IosModule):
    NAME = "ios.push"
    DESCRIPTION = "Write a local file into a device domain"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("DOMAIN", "domain to write to", "appData",
                      choices=DOMAINS, required=True),
               Option("PATH", "destination path in the domain", "",
                      required=True),
               Option("LOCAL", "local source file", "", required=True))

    def execute(self) -> dict:
        local = os.path.expanduser(self.get("LOCAL"))
        if not os.path.isfile(local):
            raise FileNotFoundError(f"no such local file: {local}")
        self.client().check("developer", "core-device", "write-file",
                            self.get("DOMAIN"), self.get("PATH"), local,
                            timeout=600)
        console.ok(f"{os.path.getsize(local)} byte(s) -> "
                   f"{self.get('DOMAIN')}:{self.get('PATH')}")
        return {"written": self.get("PATH")}


class Rm(IosModule):
    NAME = "ios.rm"
    DESCRIPTION = "Delete a file or directory in a domain"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("DOMAIN", "domain", "temporary", choices=DOMAINS,
                      required=True),
               Option("PATH", "path to remove", "", required=True))

    def execute(self) -> dict:
        self.client().check("developer", "core-device", "remove-file",
                            self.get("DOMAIN"), self.get("PATH"))
        console.warn(f"removed {self.get('PATH')}")
        return {"removed": self.get("PATH")}


class Mkdir(IosModule):
    NAME = "ios.mkdir"
    DESCRIPTION = "Create a directory in a domain"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("DOMAIN", "domain", "temporary", choices=DOMAINS,
                      required=True),
               Option("PATH", "directory to create", "", required=True))

    def execute(self) -> dict:
        self.client().check("developer", "core-device", "create-directory",
                            self.get("DOMAIN"), self.get("PATH"))
        console.ok(f"created {self.get('PATH')}")
        return {"created": self.get("PATH")}


class Apps(IosModule):
    NAME = "ios.app_containers"
    DESCRIPTION = "Map installed apps to their appData containers"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("GREP", "only bundles containing this text"))

    def execute(self) -> dict:
        client = self.client()
        bundles = client.apps()
        needle = self.get("GREP").lower()
        if needle:
            bundles = [b for b in bundles if needle in b.lower()]
        rows = []
        for bundle in bundles[:40]:
            try:
                listing = client.check(
                    "developer", "core-device", "list-directory", "appData",
                    ".", "--identifier", bundle, timeout=60).out
                found = len([ln for ln in listing.splitlines() if ln.strip()])
            except Exception:                   # noqa: BLE001 - unreadable app
                found = 0
            rows.append([bundle, str(found)])
            if found:
                console.info(f"{bundle}: {found} entr(ies)")
        console.table(["bundle", "entries"], rows)
        console.ok("read one with: omni run ios.pull BUNDLE=<id> PATH=<file>")
        return {"apps": [b for b, n in rows if n]}
