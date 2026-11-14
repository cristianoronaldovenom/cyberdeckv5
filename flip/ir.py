"""Flipper Infrared ``.ir`` reader/writer.

Format (Flipper F0 release)::

    Filetype: Flipper IR Library
    Version: 1
    #
    name: Samsung_TV
    type: parsed
    protocol: Samsung32
    address: 07 00
    command: 06 00
"""

from __future__ import annotations

import os
import re

__all__ = ["IrFile", "Signal", "load", "save"]


class Signal:
    """One parsed IR command (or a raw burst)."""

    def __init__(self, name: str, kind: str, protocol: str = "",
                 address: str = "", command: str = "",
                 raw: str = ""):
        self.name = name
        self.kind = kind            # "parsed" | "raw"
        self.protocol = protocol
        self.address = address
        self.command = command
        self.raw = raw

    def as_pairs(self) -> list[tuple[str, str]]:
        base = [("name", self.name), ("type", self.kind)]
        if self.kind == "parsed":
            base += [("protocol", self.protocol),
                     ("address", self.address), ("command", self.command)]
        else:
            base += [("frequency", "38000"), ("duty_cycle", "0.330000"),
                     ("data", self.raw)]
        return base


class IrFile:
    """One Flipper ``.ir`` library."""

    def __init__(self, path: str = "", signals: list[Signal] | None = None):
        self.path = path
        self.signals = signals or []

    def summary(self) -> str:
        protos = sorted({s.protocol for s in self.signals if s.protocol})
        return f"{len(self.signals)} signal(s): {', '.join(protos) or 'raw'}"


def parse(text: str) -> IrFile:
    signals: list[Signal] = []
    current: dict[str, str] = {}
    comment: dict[str, str] = {}

    def flush() -> None:
        nonlocal current, comment
        if not current:
            return
        name = (comment.get("name") or current.get("name", "")).strip("# ").strip()
        sig = Signal(name=name or "signal",
                     kind=current.get("type", "parsed"))
        if sig.kind == "parsed":
            sig.protocol = current.get("protocol", "")
            sig.address = current.get("address", "")
            sig.command = current.get("command", "")
        else:
            sig.raw = re.sub(r"\s+", " ", current.get("data", "")).strip()
        signals.append(sig)
        current, comment = {}, {}

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            if line.startswith("# name:"):
                flush()
                comment["name"] = line.split(":", 1)[1]
            continue
        if line.startswith(("Filetype:", "Version:")):
            continue
        key, _, val = line.partition(":")
        if not val and not current:
            comment.setdefault("name", key)
            continue
        current[key.strip()] = val.strip()
        if key.strip() == "data" or (current.get("type") == "parsed"
                                     and key.strip() == "command"):
            flush()
    flush()
    return IrFile(signals=signals)


def load(path: str) -> IrFile:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse(fh.read())


def save(signals: list[Signal], path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("Filetype: Flipper IR Library\nVersion: 1\n#\n")
        for sig in signals:
            fh.write(f"#\n# name: {sig.name}\n")
            for key, val in sig.as_pairs():
                fh.write(f"{key}: {val}\n")
    return path
