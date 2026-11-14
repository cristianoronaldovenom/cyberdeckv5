"""Infrared: capture raw timing with mode2, replay with ir-ctl."""

from __future__ import annotations

import os
import re

from omni.core import config, proc

__all__ = ["device", "parse_mode2", "to_answer_file", "capture", "send_default",
           "CARRIER"]


CARRIER = 38_000


def device() -> str:
    return str(config.get_value("radio.ir_device", "/dev/lirc0"))


def parse_mode2(text: str) -> list[tuple[bool, int]]:
    """``space 1234`` / ``pulse 560`` lines -> ``[(False, 1234), (True, 560)]``."""
    pairs: list[tuple[bool, int]] = []
    for line in text.splitlines():
        m = re.match(r"^\s*(pulse|space|timeout)\s+(\d+)", line)
        if not m:
            continue
        kind, dur = m.group(1), int(m.group(2))
        if kind == "timeout":
            continue
        pairs.append((kind == "pulse", dur))
    return pairs


def to_answer_file(pairs: list[tuple[bool, int]], path: str) -> str:
    """Write an ir-ctl compatible answer file; also yields Keeloq-ish timing."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for level, dur in pairs:
            fh.write(f"{'pulse' if level else 'space'} {dur}\n")
    return path


def capture(seconds: int = 10, outdir: str | None = None) -> dict:
    """Record raw IR timings with ``mode2`` (needs lirc + a receiver)."""
    proc.require("mode2", "apt install lirc")
    outdir = outdir or config.output_dir("radio/ir")
    raw = proc.run(["mode2", "-d", device()], timeout=max(5, int(seconds)))
    pairs = parse_mode2(raw.out)
    if not pairs:
        return {"pairs": 0, "file": None, "raw": raw.text[:500]}
    path = to_answer_file(pairs, os.path.join(outdir, "capture.ir"))
    return {"pairs": len(pairs), "file": path}


def send_default(path: str, carrier: int = CARRIER) -> proc.Result:
    """Replay a captured answer file through ``ir-ctl``."""
    proc.require("ir-ctl", "apt install v4l-utils")
    return proc.run(["ir-ctl", "-d", device(), f"--carrier={int(carrier)}",
                     f"--send=@{path}"], timeout=60)
