"""Permission control, debloating and full-device backup.

Three things PhoneSploit does that the rest of the family did not cover:

* ``pm grant`` / ``pm revoke`` on a *dangerous* permission — how a sideloaded
  implant gets the camera or location it never asked for;
* ``pm disable-user`` on bloat/telemetry packages (and the reverse, to undo);
* ``adb backup`` of an app or the whole device, which needs no root and hands
  you an ``.ab`` archive you can unpack offline.

Everything is argv-list driven; the dangerous-permission map is a plain dict so
planning works without touching the device.
"""

from __future__ import annotations

import os
import time

from omni.android.modules._base import AndroidModule
from omni.core import config, console
from omni.core.module import Option

__all__ = ["Grant", "Revoke", "Perms", "Debloat", "Backup",
           "resolve_permission", "DANGEROUS"]

#: short alias -> full permission name
DANGEROUS = {
    "camera": "android.permission.CAMERA",
    "microphone": "android.permission.RECORD_AUDIO",
    "location": "android.permission.ACCESS_FINE_LOCATION",
    "coarse-location": "android.permission.ACCESS_COARSE_LOCATION",
    "contacts": "android.permission.READ_CONTACTS",
    "sms": "android.permission.READ_SMS",
    "send-sms": "android.permission.SEND_SMS",
    "call-log": "android.permission.READ_CALL_LOG",
    "phone-state": "android.permission.READ_PHONE_STATE",
    "storage": "android.permission.READ_EXTERNAL_STORAGE",
    "storage-write": "android.permission.WRITE_EXTERNAL_STORAGE",
    "calendar": "android.permission.READ_CALENDAR",
    "sensors": "android.permission.BODY_SENSORS",
    "accounts": "android.permission.GET_ACCOUNTS",
    "overlay": "android.permission.SYSTEM_ALERT_WINDOW",
}


def resolve_permission(name: str) -> str:
    """Map a short alias to a full permission, passing full names through."""
    key = name.strip().lower()
    if key in DANGEROUS:
        return DANGEROUS[key]
    if "." in name:
        return name.strip()
    raise ValueError(f"unknown permission {name!r} — use one of "
                     f"{', '.join(sorted(DANGEROUS))} or a full name")


class Grant(AndroidModule):
    NAME = "android.grant"
    DESCRIPTION = "Grant dangerous permissions to a package"
    OPTIONS = (Option("PACKAGE", "target package", "", required=True),
               Option("PERM", "comma-separated aliases or full names", "",
                      required=True))

    def execute(self) -> dict:
        client = self.adb()
        granted, failed = [], []
        for raw in self.get("PERM").split(","):
            if not raw.strip():
                continue
            perm = resolve_permission(raw)
            res = client.grant(self.get("PACKAGE"), perm)
            (granted if res.ok else failed).append(perm)
            if not res.ok:
                console.warn(f"{perm}: {res.text[:120]}")
        console.ok(f"granted {len(granted)}/{len(granted) + len(failed)}")
        return {"package": self.get("PACKAGE"), "granted": granted,
                "failed": failed}


class Revoke(AndroidModule):
    NAME = "android.revoke"
    DESCRIPTION = "Revoke permissions from a package"
    OPTIONS = (Option("PACKAGE", "target package", "", required=True),
               Option("PERM", "comma-separated aliases or full names", "",
                      required=True))

    def execute(self) -> dict:
        client = self.adb()
        revoked, failed = [], []
        for raw in self.get("PERM").split(","):
            if not raw.strip():
                continue
            perm = resolve_permission(raw)
            res = client.revoke(self.get("PACKAGE"), perm)
            (revoked if res.ok else failed).append(perm)
        console.ok(f"revoked {len(revoked)}/{len(revoked) + len(failed)}")
        return {"package": self.get("PACKAGE"), "revoked": revoked,
                "failed": failed}


class Perms(AndroidModule):
    NAME = "android.perms"
    DESCRIPTION = "Show the permission set an installed package declares"
    OPTIONS = (Option("PACKAGE", "package to inspect", "", required=True),
               Option("GREP", "only keep names containing this substring"))

    def execute(self) -> dict:
        client = self.adb()
        perms = client.permissions(self.get("PACKAGE"))
        needle = self.get("GREP").lower()
        if needle:
            perms = [p for p in perms if needle in p.lower()]
        for perm in perms:
            console.info(perm)
        console.ok(f"{len(perms)} permission(s)")
        return {"package": self.get("PACKAGE"), "permissions": perms}


class Debloat(AndroidModule):
    NAME = "android.debloat"
    DESCRIPTION = "Disable (or re-enable) bloat and telemetry packages for user 0"
    OPTIONS = (Option("PACKAGE", "comma-separated packages", "", required=True),
               Option("ACTION", "disable|enable|status", "disable",
                      choices=("disable", "enable", "status")))

    def execute(self) -> dict:
        client = self.adb()
        action = self.get("ACTION")
        rows = []
        changed = 0
        for raw in self.get("PACKAGE").split(","):
            package = raw.strip()
            if not package:
                continue
            if action == "status":
                enabled = client.is_enabled(package)
                rows.append([package, "enabled" if enabled else "disabled"])
                continue
            res = client.set_enabled(package, action == "enable")
            changed += 1 if res.ok else 0
            rows.append([package, "ok" if res.ok else res.text[:60]])
        console.table(["package", action], rows)
        if action != "status":
            console.ok(f"{changed} package(s) {action}d")
        return {"action": action, "changed": changed, "rows": rows}


class Backup(AndroidModule):
    NAME = "android.backup"
    DESCRIPTION = "Full or per-app adb backup into the loot directory"
    OPTIONS = (Option("PACKAGE", "single package (blank = everything)"),
               Option("OUT", "output .ab path"),
               Option("APK", "include the APK itself", "true",
                      choices=("true", "false")),
               Option("SHARED", "include shared storage", "false",
                      choices=("true", "false")),
               Option("TIMEOUT", "seconds to wait for the backup", "600"))

    def execute(self) -> dict:
        client = self.adb()
        stamp = time.strftime("%Y%m%d_%H%M%S")
        target = self.get("PACKAGE").strip() or "device"
        path = os.path.expanduser(
            self.get("OUT") or
            os.path.join(config.output_dir("android/backup"),
                         f"{target}_{stamp}.ab"))
        args = ["backup", "-f", path]
        if self.get("PACKAGE"):
            args += ["-apk" if self.get_bool("APK", True) else "-noapk",
                     self.get("PACKAGE").strip()]
        elif self.get_bool("SHARED"):
            args += ["-shared"]
        console.warn('confirm the prompt on the device ("Back up my data")')
        res = client.raw(*args, timeout=self.get_int("TIMEOUT", 600))
        size = os.path.getsize(path) if os.path.exists(path) else 0
        if not res.ok:
            raise RuntimeError(f"adb backup failed: {res.text[:200]}")
        if size <= 24:
            console.warn("archive is empty — the prompt was probably declined")
        console.ok(f"{size} bytes -> {path}")
        return {"path": path, "bytes": size, "package": target}
