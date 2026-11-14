"""Flipper iButton ``.ibtn`` reader/writer (Cyphal / Metakom / key files)."""

from __future__ import annotations

import os
import re

__all__ = ["IbuttonFile", "load", "save", "parse"]

_HEAD = ("Filetype: Flipper iButton key", "Version: 2")


class IbuttonFile:
    def __init__(self, protocol: str = "DS1990", data: str = "",
                 path: str = ""):
        self.protocol = protocol
        self.data = data.replace(" ", "")
        self.path = path

    def serial(self) -> str:
        """Reversed-byte display form, like the Flipper shows it."""
        raw = self.data
        if len(raw) % 2:
            return raw
        rev = "".join(raw[i:i + 2] for i in range(0, len(raw), 2))
        return ":".join(rev[i:i + 2] for i in range(0, len(rev), 2))

    def summary(self) -> str:
        return f"{self.protocol} {self.serial()}"


def parse(text: str) -> IbuttonFile:
    proto, data, name = "DS1990", "", ""
    for line in text.splitlines():
        if line.startswith("Filetype:"):
            continue
        key, _, val = line.partition(":")
        val = val.strip()
        if key.strip() == "Protocol":
            proto = val
        elif key.strip() == "Data":
            data = val.replace(" ", "")
        elif key.strip() == "Name":
            name = val
    if name and not data:
        m = re.search(r"([0-9A-Fa-f]{14,16})", name)
        if m:
            data = m.group(1)
    return IbuttonFile(protocol=proto, data=data)


def load(path: str) -> IbuttonFile:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        key = parse(fh.read())
    key.path = path
    return key


def save(key: IbuttonFile, path: str, name: str | None = None) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    pretty = " ".join(key.data[i:i + 2] for i in range(0, len(key.data), 2))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(_HEAD) + "\n")
        fh.write(f"Name: {name or os.path.splitext(os.path.basename(path))[0]}\n")
        fh.write(f"Protocol: {key.protocol}\n")
        fh.write(f"Data: {pretty}\n")
    return path
