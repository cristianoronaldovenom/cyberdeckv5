"""Flipper firmware bundle helper — unpack/inspect a Private-Unleashed zip."""

from __future__ import annotations

import os
import re
import zipfile

__all__ = ["inspect_bundle", "extract_bundle", "describe"]


def inspect_bundle(path: str) -> dict:
    """Metadata of an ``.uf2``/``.zip`` firmware bundle without running it."""
    info: dict = {"path": os.path.basename(path), "size": os.path.getsize(path)}
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            info["entries"] = len(names)
            info["parts"] = names[:15]
            fw = [n for n in names if n.endswith((".bin", ".uf2", ".dfu"))]
            if fw:
                info["firmware"] = fw[0]
        return info
    with open(path, "rb") as fh:
        head = fh.read(512)
    info["format"] = "uf2" if head[:4] == b"UF2\n" else "unknown"
    return info


def extract_bundle(path: str, dest: str) -> str:
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(path) as zf:
        zf.extractall(dest)
    return dest


def describe(model: str = "flipper_zero") -> dict:
    """Static capability matrix for the supported boards."""
    caps = {
        "flipper_zero": {"subghz": True, "nrf": True, "ble": True,
                         "rgb_backlight": True, "sd": True},
    }
    return caps.get(model, {"unknown": True})


def raw_preset_check(custom_preset: str) -> bool:
    """Cheap sanity check for a Furi preset dump (cc1101 register stream)."""
    s = custom_preset.strip()
    return bool(s) and all(
        len(tok) == 2 and 0 <= int(tok, 16) <= 255
        for tok in s.split(" "))
