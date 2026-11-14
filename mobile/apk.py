"""APK analysis helpers built on jadx / apkleaks / aapt (when present)."""

from __future__ import annotations

import os
import re
import zipfile

from omni.core import proc

__all__ = ["inspect_apk", "permissions", "manifest_summary", "secrets",
           "decompile", "package_name"]


def inspect_apk(path: str) -> dict:
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
    return {"path": path, "size": os.path.getsize(path), "entries": len(names),
            "has_dex": any(n.endswith(".dex") for n in names),
            "native_libs": sorted({n.split("/")[2] for n in names
                                   if n.startswith("lib/") and n.count("/") > 2})}


def permissions(path: str) -> list[str]:
    """Pull ``android.permission`` strings out of the binary manifest context
    (cheap heuristic) and any plaintext XML inside the APK."""
    found: set[str] = set()
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if name.endswith(".xml"):
                blob = zf.read(name)
                found.update(m.decode("utf-8", "ignore") for m in
                             re.findall(rb"android\.permission\.[A-Z_.]+", blob))
    return sorted(found)


def manifest_summary(path: str) -> dict:
    return {"apk": os.path.basename(path),
            "native_abis": inspect_apk(path).get("native_libs", []),
            "permissions": permissions(path)}


def secrets(path: str, out_dir: str | None = None) -> list[str]:
    """Run ``apkleaks`` if installed, else grep dex strings for endpoints."""
    if proc.has("apkleaks"):
        out = proc.run(["apkleaks", "-f", path,
                        *(["-o", out_dir] if out_dir else [])]).text
        return [ln.strip() for ln in out.splitlines() if ln.strip()]
    if proc.has("strings"):
        out = proc.run(["strings", path]).text
        return sorted(set(re.findall(r"https?://[\w./%-]+", out)))
    raise RuntimeError("need apkleaks or strings in PATH")


def decompile(path: str, out_dir: str) -> str:
    if not proc.has("jadx"):
        raise RuntimeError("jadx not found — apt install jadx")
    os.makedirs(out_dir, exist_ok=True)
    proc.run(["jadx", "-d", out_dir, path], timeout=3600).ok
    return out_dir


def package_name(path: str) -> str:
    if proc.has("aapt"):
        out = proc.run(["aapt", "dump", "badging", path]).text
        m = re.search(r"package: name='([^']+)'", out)
        if m:
            return m.group(1)
    with zipfile.ZipFile(path) as zf:
        blob = zf.read("AndroidManifest.xml")
    m = re.search(rb"P(?:\x00)k(?:\x00)g(?:\x00)..." , blob)  # noqa: vague
    return m.group(0).decode("latin1") if m else ""
