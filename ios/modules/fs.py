"""iOS filesystem access: AFC media domain and full sandbox reads.

Two distinct file domains, both real:

* ``afc`` — /var/mobile/Media (photos, docs, recordings). Works on a stock
  paired device, no Developer Mode.
* ``developer core-device read-file`` — any path on the iOS 17+ sandbox,
  including every app container, if an RSD tunnel is up.

`omni run ios.pull REMOTE=/ handy for grabbing WhatsApp databases on a
jailbroken phone; `omni run ios.pull DOMAIN=media` reads the photo library on
any phone.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.ios.modules._base import IosModule

__all__ = ["Afc", "SandboxPull", "Watch"]


class Afc(IosModule):
    NAME = "ios.afc"
    DESCRIPTION = "Browse/pull/push /var/mobile/Media (photos, docs) — no root"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("ACTION", "ls|pull|push|rm", "ls",
                      choices=("ls", "pull", "push", "rm")),
               Option("REMOTE", "remote path under Media", "/"),
               Option("LOCAL", "local path (pull target / push source)"),
               Option("RECURSIVE", "recurse on ls/pull", "true",
                      choices=("true", "false")))

    def execute(self) -> dict:
        client = self.client()
        action = self.get("ACTION")
        remote = self.get("REMOTE") or "/"
        if action == "ls":
            args = ["afc", "ls", remote]
            if self.get_bool("RECURSIVE", True):
                args += ["--recursive"]
            out = client.check(*args, timeout=180).out
            paths = [ln for ln in out.splitlines() if ln.strip()]
            for path in paths[:400]:
                console.info(path)
            console.ok(f"{len(paths)} entr(ies)")
            return {"paths": paths, "domain": "media"}
        if action == "pull":
            local = os.path.expanduser(self.get("LOCAL") or
                                       os.path.join(
                                           config.output_dir("ios/afc"),
                                           f"media_{time.strftime('%H%M%S')}"))
            parent = os.path.dirname(local)
            if parent:
                os.makedirs(parent, exist_ok=True)
            args = ["afc", "pull", remote, local, "--ignore-errors"]
            client.check(*args, timeout=1800)
            console.ok(f"pulled {remote} -> {local}")
            return {"pulled": local, "domain": "media"}
        if action == "push":
            local = os.path.expanduser(self.get("LOCAL"))
            if not local or not os.path.exists(local):
                raise ValueError("PUSH needs a real LOCAL file")
            client.check("afc", "push", local, remote)
            console.ok(f"pushed {local} -> {remote}")
            return {"pushed": remote}
        client.check("afc", "rm", remote)
        console.warn(f"deleted {remote}")
        return {"deleted": remote, "domain": "media"}


class SandboxPull(IosModule):
    NAME = "ios.sandbox_pull"
    DESCRIPTION = "Read any file from the device (Developer Mode + tunnel)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("REMOTE", "absolute device path", "", required=True),
               Option("OUT", "local destination file"))

    def execute(self) -> dict:
        client = self.client()
        out = os.path.expanduser(
            self.get("OUT") or
            os.path.join(config.output_dir("ios/fs"),
                         os.path.basename(self.get("REMOTE")) or "file"))
        parent = os.path.dirname(out)
        if parent:
            os.makedirs(parent, exist_ok=True)
        client.check("developer", "core-device", "read-file", self.get("REMOTE"),
                     out, timeout=600)
        size = os.path.getsize(out) if os.path.isfile(out) else 0
        console.ok(f"{size} byte(s) -> {out}")
        return {"remote": self.get("REMOTE"), "path": out, "bytes": size}


class Watch(IosModule):
    NAME = "ios.watch"
    DESCRIPTION = "Stream a device directory: new files are logged as they land"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("REMOTE", "directory to watch", "/"),
               Option("SECONDS", "how long to watch", "30"))

    def execute(self) -> dict:
        client = self.client()
        seconds = max(5, self.get_int("SECONDS", 30))
        console.info(f"watching {self.get('REMOTE')} for {seconds}s")
        try:
            client.run("developer", "core-device", "watch", self.get("REMOTE"),
                       timeout=seconds)
        except Exception as exc:                 # noqa: BLE001 - timeout is fine
            console.info(f"stopped after {seconds}s ({exc})")
        return {"remote": self.get("REMOTE"), "seconds": seconds}
