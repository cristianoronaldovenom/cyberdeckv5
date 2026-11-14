"""iOS recon: app inventory, process control, location, syslog."""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.ios.modules._base import IosModule

__all__ = ["Apps", "Launch", "Kill", "Processes", "Location", "Syslog"]


class Apps(IosModule):
    NAME = "ios.apps"
    DESCRIPTION = "List installed application bundle identifiers"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("GREP", "only keep bundle ids containing this substring"),
               Option("SAVE", "also write them to loot", "false",
                      choices=("true", "false")))

    def execute(self) -> dict:
        client = self.client()
        apps = client.apps()
        needle = self.get("GREP").lower()
        if needle:
            apps = [a for a in apps if needle in a.lower()]
        for bundle in apps:
            console.info(bundle)
        if self.get_bool("SAVE"):
            path = os.path.join(config.output_dir("ios"),
                               f"apps_{time.strftime('%Y%m%d_%H%M%S')}.txt")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("\n".join(apps) + "\n")
            console.info(f"list saved: {path}")
        console.ok(f"{len(apps)} bundle(s)")
        return {"apps": apps}


class Launch(IosModule):
    NAME = "ios.launch"
    DESCRIPTION = "Launch an application by bundle identifier"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("BUNDLE", "bundle identifier", "", required=True))

    def execute(self) -> dict:
        self.client().launch(self.get("BUNDLE"))
        console.ok(f"launched {self.get('BUNDLE')}")
        return {"bundle": self.get("BUNDLE")}


class Kill(IosModule):
    NAME = "ios.kill"
    DESCRIPTION = "SIGKILL processes whose executable matches a name"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("NAME", "executable/bundle substring", "", required=True))

    def execute(self) -> dict:
        killed = self.client().kill(self.get("NAME"))
        if not killed:
            console.warn(f"no process matched {self.get('NAME')!r}")
        else:
            console.ok(f"killed pid(s) {killed}")
        return {"killed": killed}


class Processes(IosModule):
    NAME = "ios.processes"
    DESCRIPTION = "List running processes (pid + name)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("GREP", "only keep names containing this substring"))

    def execute(self) -> dict:
        found = self.client().processes()
        needle = self.get("GREP").lower()
        if needle:
            found = [row for row in found if needle in row[1].lower()]
        console.table(["pid", "name"], [[str(p), n] for p, n in found[:200]])
        console.ok(f"{len(found)} process(es)")
        return {"processes": found}


class Location(IosModule):
    NAME = "ios.location"
    DESCRIPTION = "Spoof or clear the device GPS fix (Developer Mode)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("LAT", "latitude", ""),
               Option("LON", "longitude", ""),
               Option("ACTION", "set|clear|scenarios", "set",
                      choices=("set", "clear", "scenarios")))

    def execute(self) -> dict:
        client = self.client()
        action = self.get("ACTION")
        if action == "clear":
            client.clear_location()
            console.ok("location simulation cleared")
            return {"action": "clear"}
        if action == "scenarios":
            res = client.check("developer", "core-device", "location",
                               "available-scenarios")
            console.info(res.out.strip() or "(none)")
            return {"scenarios": res.out.strip()}
        if not (self.get("LAT") and self.get("LON")):
            raise ValueError("SET needs LAT and LON")
        lat, lon = float(self.get("LAT")), float(self.get("LON"))
        client.set_location(lat, lon)
        console.ok(f"location fixed at {lat:.5f},{lon:.5f}")
        return {"lat": lat, "lon": lon}


class Syslog(IosModule):
    NAME = "ios.syslog"
    DESCRIPTION = "Capture device syslog for a few seconds to loot"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("SECONDS", "capture window", "10"),
               Option("PROCESS", "only this process name"),
               Option("OUT", "explicit output path"))

    def execute(self) -> dict:
        client = self.client()
        path = os.path.expanduser(
            self.get("OUT") or
            os.path.join(config.output_dir("ios/syslog"),
                         f"syslog_{time.strftime('%Y%m%d_%H%M%S')}.log"))
        console.info(f"capturing for {self.get_int('SECONDS', 10)}s")
        client.syslog(self.get_int("SECONDS", 10), out=path,
                      process=self.get("PROCESS") or None)
        lines = 0
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = sum(1 for _ in fh)
        console.ok(f"{lines} line(s) -> {path}")
        return {"path": path, "lines": lines}
