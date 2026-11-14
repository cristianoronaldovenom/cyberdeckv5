"""Generic Flipper-file CRUD: read, convert, list, install onto an SD card."""

from __future__ import annotations

import os
import shutil

from omni.core import config, console
from omni.rf import subfile
from omni.flip import ibutton, ir

__all__ = ["read_any", "convert_to_sub", "index_dir", "push_to_sd",
           "LOOT_SUBDIR"]


def loot_dir(kind: str) -> str:
    return config.output_dir(os.path.join("flip", kind))


def read_any(path: str):
    """Read any Flipper text file by extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".sub":
        return subfile.load(path)
    if ext == ".ir":
        return ir.load(path)
    if ext == ".ibtn":
        return ibutton.load(path)
    raise ValueError(f"unknown Flipper extension: {ext}")


def convert_to_sub(path: str, out_name: str | None = None) -> str:
    """Normalize any captured file into a proper ``.sub`` in the loot dir."""
    obj = read_any(path)
    if not isinstance(obj, subfile.SubFile):
        raise TypeError(f"{path} is not sub-convertible")
    target = os.path.join(loot_dir("sub"),
                          out_name or os.path.basename(path))
    if not target.endswith(".sub"):
        target += ".sub"
    obj.save(target)
    return target


def index_dir(directory: str, recursive: bool = True) -> list[dict]:
    """Summarise every Flipper file below ``directory``."""
    globs = (".sub", ".ir", ".ibtn")
    rows: list[dict] = []
    walker = os.walk(directory) if recursive else ((directory, [], []),)
    for root, _dirs, names in walker:
        for name in sorted(names):
            if not name.lower().endswith(globs):
                continue
            path = os.path.join(root, name)
            try:
                obj = read_any(path)
                rows.append({"path": path, "kind": os.path.splitext(name)[1][1:],
                             "summary": getattr(obj, "summary", lambda: "")()})
            except Exception as exc:  # noqa: BLE001
                rows.append({"path": path, "kind": "?", "summary": str(exc)})
    return rows


def push_to_sd(path: str, mount: str | None = None, kind: str | None = None) -> str:
    """Copy a capture onto a mounted Flipper SD card (``$OMNI_FLIPPER``)."""
    mount = mount or config.get_value("flipper.mount")
    if not mount or not os.path.isdir(mount):
        raise RuntimeError("flipper SD not mounted — set flipper.mount in config")
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    folder = kind or {"sub": "SubGHZ", "ir": "Infrared",
                      "ibtn": "Lagoon"}.get(ext, "SubGHZ")
    dest_dir = os.path.join(mount, folder)
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, os.path.basename(path))
    shutil.copy2(path, dest)
    console.ok(f"installed to {dest}")
    return dest
