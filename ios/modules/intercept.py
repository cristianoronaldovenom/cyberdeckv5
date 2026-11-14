"""iOS interception: set a proxy, then harvest from a backup.

Two moves that turn control into data:

* ``ios.proxy`` — push an HTTP proxy profile so the phone routes traffic
  through your listener (mitmproxy, Burp, a tcpdump box). Combined with
  ``ios.profile_install`` for a trusted CA, this is full TLS interception.
* ``ios.backup_extract`` — ``backup2 extract`` pulls readable files out of a
  backup archive, so an encrypted-by-keychain blob becomes usable text.

Both need only a paired device; neither needs a jailbreak.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.ios.modules._base import IosModule

__all__ = ["Proxy", "ProxyOff", "BackupExtract", "BackupList"]


class Proxy(IosModule):
    NAME = "ios.proxy"
    DESCRIPTION = "Point the device's HTTP proxy at your listener (MITM setup)"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("SERVER", "listener host/IP", "", required=True),
               Option("PORT", "listener port", "8080", required=True))

    def execute(self) -> dict:
        port = self.get_int("PORT", 8080)
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} out of range")
        self.client().check("profile", "install-http-proxy", self.get("SERVER"),
                            str(port), timeout=300)
        console.ok(f"proxy set to {self.get('SERVER')}:{port}")
        console.info("install a CA with ios.profile_install, then watch the "
                     "listener — traffic is routed through it now")
        return {"server": self.get("SERVER"), "port": port}


class ProxyOff(IosModule):
    NAME = "ios.proxy_off"
    DESCRIPTION = "Clear the HTTP proxy the device is using"
    NEEDS = ("pymobiledevice3",)

    def execute(self) -> dict:
        self.client().check("profile", "remove-http-proxy", timeout=300)
        console.ok("proxy removed — device is back on direct routing")
        return {"proxy": None}


class BackupList(IosModule):
    NAME = "ios.backup_list"
    DESCRIPTION = "List what a backup archive contains before extracting"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("DIR", "backup directory", "", required=True),
               Option("GREP", "only paths containing this text"))

    def execute(self) -> dict:
        path = os.path.expanduser(self.get("DIR"))
        if not os.path.isdir(path):
            raise FileNotFoundError(f"no such backup directory: {path}")
        out = self.client().check("backup2", "list", path, timeout=600).out
        rows = [ln for ln in out.splitlines() if ln.strip()]
        needle = self.get("GREP").lower()
        if needle:
            rows = [r for r in rows if needle in r.lower()]
        for row in rows[:400]:
            console.info(row)
        console.ok(f"{len(rows)} entr(ies) listed")
        return {"entries": rows}


class BackupExtract(IosModule):
    NAME = "ios.backup_extract"
    DESCRIPTION = "Unpack a whole backup into a browsable tree (writes in place)"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("DIR", "backup directory", "", required=True),
               Option("PASSWORD", "backup password when encrypted"))

    def execute(self) -> dict:
        path = os.path.expanduser(self.get("DIR"))
        if not os.path.isdir(path):
            raise FileNotFoundError(f"no such backup directory: {path}")
        args = ["backup2", "unback", path]
        if self.get("PASSWORD"):
            args += ["--password", self.get("PASSWORD")]
        console.info("unpacking in place — this rewrites the backup into "
                     "domain folders")
        self.client().check(*args, timeout=3600)
        files = sum(len(names) for _root, _dirs, names in os.walk(path))
        console.ok(f"backup unpacked ({files} file(s) under {path})")
        return {"path": path, "files": files}


class BackupFile(IosModule):
    NAME = "ios.backup_file"
    DESCRIPTION = "Extract one file from a backup by domain and path"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("DIR", "backup directory", "", required=True),
               Option("DOMAIN", "domain, e.g. AppDomain-com.app", "",
                      required=True),
               Option("PATH", "relative path inside the domain", "",
                      required=True),
               Option("PASSWORD", "backup password when encrypted"))

    def execute(self) -> dict:
        path = os.path.expanduser(self.get("DIR"))
        if not os.path.isdir(path):
            raise FileNotFoundError(f"no such backup directory: {path}")
        args = ["backup2", "extract", self.get("DOMAIN"), self.get("PATH"),
                path]
        if self.get("PASSWORD"):
            args += ["--password", self.get("PASSWORD")]
        self.client().check(*args, timeout=900)
        console.ok(f"extracted {self.get('DOMAIN')}:{self.get('PATH')}")
        return {"domain": self.get("DOMAIN"), "path": self.get("PATH")}

