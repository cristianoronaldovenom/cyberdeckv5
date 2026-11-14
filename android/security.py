"""Reconnaissance from the device: fingerprint, sensors, malware-ish smells.

Ported from PhoneSploit-Pro's ``dump`` menu (AzeemIdrisi, GPL-3.0), extended
with a package-audit pass that flags sideloaded/over-privileged apps.
"""

from __future__ import annotations

import re

from omni.android.adb import Adb
from omni.core import console

__all__ = ["fingerprint", "sensors", "malware_scan", "audit_packages",
           "permissions_of", "world_readable", "SUITE_MARKERS"]

#: Locations that should never be world-readable on a hardened device.
SENSITIVE_PATHS = (
    ("/data/data", "app private data"),
    ("/sdcard/Android/data", "external app data"),
    ("/sdcard/Download", "downloads"),
    ("/data/local/tmp", "temp payload staging"),
)

#: Signs of a rooted / instrumented device.
ROOT_MARKERS = ("su", "magisk", "busybox", "frida-server", "xposed",
                "supersu", "kingroot")

#: Package name fragments typical of stalkerware / RATs / injectors.
SUITE_MARKERS = {
    "com.termux": "terminal",
    "org.frida": "instrumentation",
    "de.robv.android.xposed": "hooking",
    "com.topjohnwu.magisk": "root manager",
    "com.koushikdutta.superuser": "root manager",
    "eu.chainfire.supersu": "root manager",
    "com.whatsapp": "messenger",
    "org.telegram.messenger": "messenger",
    "com.anydesk.anydeskandroid": "remote desktop",
    "com.teamviewer.quicksupport.market": "remote desktop",
    "com.vysor.samsung": "remote control",
}


def fingerprint(adb: Adb) -> dict:
    """Everything identifying the device and its OS build."""
    return {
        "serial": adb.serial or "",
        "model": adb.model(),
        "manufacturer": adb.prop("ro.product.manufacturer"),
        "brand": adb.prop("ro.product.brand"),
        "android": adb.android_version(),
        "sdk": adb.sdk(),
        "build_id": adb.prop("ro.build.id"),
        "fingerprint": adb.prop("ro.build.fingerprint"),
        "abi": adb.prop("ro.product.cpu.abi"),
        "patch_level": adb.prop("ro.build.version.security_patch"),
        "bootloader": adb.prop("ro.bootloader"),
        "rooted": adb.is_rooted(),
        "ip": adb.ip_address(),
        "battery": adb.battery().get("level", "?"),
        "screen": adb.screen_state(),
    }


def sensors(adb: Adb) -> list[str]:
    """List sensor hardware reported by the device."""
    out = adb.shell_result("dumpsys", "sensorservice").out
    return sorted({m.strip() for m in re.findall(r"0x[0-9a-f]+\)\s+(\w[\w .]+)", out)})


def malware_scan(adb: Adb) -> list[dict]:
    """Heuristic pass: root kits, Frida servers, suspicious listeners."""
    findings: list[dict] = []
    packages = adb.packages(third_party_only=True)
    for pkg in packages:
        for marker, label in SUITE_MARKERS.items():
            if marker in pkg:
                findings.append({"package": pkg, "kind": label,
                                 "note": "notable package"})
    for marker in ROOT_MARKERS:
        hits = adb.shell_result("which", marker).out.strip()
        if hits:
            findings.append({"package": hits, "kind": "binary",
                             "note": f"{marker} present in PATH"})
    for line in adb.shell_result("netstat", "-tlnp").out.splitlines():
        if "0.0.0.0:" in line or ":::" in line:
            findings.append({"package": line.split()[-1], "kind": "listener",
                             "note": "world-reachable socket"})
    return findings


def audit_packages(adb: Adb) -> list[dict]:
    """Flag sideloaded apps and those holding high-risk permissions."""
    risky = ("BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW",
             "READ_SMS", "READ_CALL_LOG", "RECORD_AUDIO", "CAMERA",
             "READ_CONTACTS", "ACCESS_FINE_LOCATION", "PACKAGE_USAGE_STATS")
    rows = []
    for pkg in adb.packages(third_party_only=True):
        info = {"package": pkg, "installer": _installer(adb, pkg), "risky": []}
        for perm in risky:
            if perm in permissions_of(adb, pkg):
                info["risky"].append(perm)
        if info["risky"] or info["installer"] in ("", "null"):
            rows.append(info)
    return rows


def _installer(adb: Adb, package: str) -> str:
    out = adb.shell_result("pm", "dump", package).out
    m = re.search(r"installerPackageName=(\S+)", out)
    return m.group(1) if m else ""


def permissions_of(adb: Adb, package: str) -> set[str]:
    out = adb.shell_result("dumpsys", "package", package).out
    wanted = set(re.findall(r"android\.permission\.([A-Z_]+)", out))
    return {w.split(".")[-1] for w in wanted}


def world_readable(adb: Adb) -> list[str]:
    """Probe sensitive paths for group/other read bits (needs shell access)."""
    hits = []
    for path, label in SENSITIVE_PATHS:
        res = adb.shell_result("ls", "-ld", path)
        if not res.ok:
            continue
        bits = res.out.split()[0] if res.out.split() else ""
        if len(bits) >= 10 and ("r" in bits[7] or bits[7] in "r-"):
            hits.append(f"{path}  ({label})  {bits}")
    return hits


def report(adb: Adb) -> None:
    """Print the whole recon set as a readable block."""
    from omni.core import console as con

    con.section("device")
    con.kv(list(fingerprint(adb).items()))
    con.section("sensors")
    for name in sensors(adb):
        con.info(name)
    con.section("findings")
    for row in malware_scan(adb):
        con.warn(f"{row['kind']:12} {row['package']}  {row['note']}")
