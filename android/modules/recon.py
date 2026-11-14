"""Device recon: info dump, sensors, audit, loot extraction."""

from __future__ import annotations

from omni.android import media, security
from omni.core import config, console
from omni.core.module import Option
from omni.android.modules._base import AndroidModule


class Info(AndroidModule):
    NAME = "android.info"
    DESCRIPTION = "Dump device fingerprint, battery and screen state"

    def execute(self) -> dict:
        data = security.fingerprint(self.adb())
        console.kv(list(data.items()))
        return data


class Sensors(AndroidModule):
    NAME = "android.sensors"
    DESCRIPTION = "List sensor hardware"

    def execute(self) -> list[str]:
        rows = security.sensors(self.adb())
        for name in rows:
            console.info(name)
        return rows


class Audit(AndroidModule):
    NAME = "android.audit"
    DESCRIPTION = "Risky permissions + root/instrumentation indicators"
    OPTIONS = (Option("MODE", "findings|packages|paths|all", "all",
                      choices=("findings", "packages", "paths", "all")),)

    def execute(self) -> dict:
        client, mode = self.adb(), self.get("MODE")
        out: dict = {}
        if mode in ("findings", "all"):
            out["findings"] = security.malware_scan(client)
            for row in out["findings"]:
                console.warn(f"{row['kind']:10} {row['package']}  {row['note']}")
        if mode in ("packages", "all"):
            out["packages"] = security.audit_packages(client)
            console.table(["package", "installer", "risky perms"],
                          [[r["package"], r["installer"] or "(sideload)",
                            ", ".join(r["risky"]) or "-"]
                           for r in out["packages"]])
        if mode in ("paths", "all"):
            out["paths"] = security.world_readable(client)
            for line in out["paths"]:
                console.info(line)
        return out


class Dump(AndroidModule):
    NAME = "android.dump"
    DESCRIPTION = "Save call log, SMS, contacts and clipboard to loot"
    OPTIONS = (Option("WHAT", "calls|sms|contacts|clipboard", "calls",
                      choices=("calls", "sms", "contacts", "clipboard")),)

    def execute(self) -> str:
        client, what = self.adb(), self.get("WHAT")
        data = {"calls": media.call_log, "sms": media.sms,
                "contacts": media.contacts,
                "clipboard": media.clipboard_dump}[what](client)
        path = f"{config.output_dir('android/dumps')}/{what}.txt"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(data + "\n")
        console.ok(f"{len(data.splitlines())} lines -> {path}")
        return path


class Media(AndroidModule):
    NAME = "android.media"
    DESCRIPTION = "Pull DCIM/Pictures/Movies/Download/Music to loot"

    def execute(self) -> str:
        target = media.copy_media(self.adb())
        console.ok(f"saved under {target}")
        return target


class Whatsapp(AndroidModule):
    NAME = "android.whatsapp"
    DESCRIPTION = "Copy the WhatsApp message databases (root recommended)"

    def execute(self) -> str | None:
        target = media.whatsapp_pull(self.adb())
        if target:
            console.ok(f"databases under {target}")
        return target
