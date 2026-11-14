"""Small shared helpers: formatting, byte math, timestamps, file IO."""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone

__all__ = [
    "stamp", "ago", "human_bytes", "slug", "truncate",
    "write_text", "read_text", "ensure_dir", "xcrc", "iso_now", "parse_int",
]


def parse_int(text: str, default: int = 0) -> int:
    """Parse ``0x1F`` / ``31`` / ``0b101`` into an int; ``default`` on junk."""
    raw = (text or "").strip().replace("_", "")
    if not raw:
        return default
    try:
        return int(raw, 0)
    except ValueError:
        try:
            return int(raw, 16 if any(c in "abcdefABCDEF" for c in raw) else 10)
        except ValueError:
            return default


def stamp(fmt: str = "%Y%m%d_%H%M%S") -> str:
    return datetime.now().strftime(fmt)


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(epoch: float | int | None) -> str:
    """Relative time string ("3h ago") for unix timestamps."""
    if not epoch:
        return "?"
    delta = int(time.time() - float(epoch))
    if delta < 60:
        return f"{max(delta, 0)}s ago"
    for size, suffix in ((3600, "m"), (86_400, "h"), (604_800, "d")):
        if delta < size * 60:
            return f"{delta // (size // 60)} {suffix} ago"
    return datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d")


def human_bytes(num: float | int | None) -> str:
    if num is None:
        return "?"
    num = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024 or unit == "TiB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TiB"


def slug(text: str, limit: int = 40) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip()).strip("_")
    return clean[:limit] or "unnamed"


def truncate(text: str, width: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[: max(0, width - 1)] + "\u2026"


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def write_text(path: str, text: str) -> str:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def read_text(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return default


def xcrc(data: bytes, poly: int = 0x07) -> int:
    """Plain CRC-8 used by 1-Wire/iButton payloads."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc
