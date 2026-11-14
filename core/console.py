"""Console output helpers — colour, banners, tables, progress, prompts.

Colour auto-disables when stdout is not a TTY or NO_COLOR is set, so piping
`omni ... | tee` stays clean.
"""

from __future__ import annotations

import os
import shutil
import sys
import time

__all__ = [
    "C", "banner", "info", "ok", "warn", "err", "debug", "section", "table",
    "kv", "ask", "confirm", "choose", "progress", "rule", "clear", "colour",
]


def colour() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


class C:
    """ANSI escapes, emptied when colour is off."""

    R = G = Y = B = M = Cy = W = D = X = ""

    @classmethod
    def enable(cls, on: bool) -> None:
        if on:
            cls.R, cls.G, cls.Y, cls.B, cls.M = ("\033[31m", "\033[32m",
                                                "\033[33m", "\033[34m",
                                                "\033[35m")
            cls.Cy, cls.W, cls.D, cls.X = "\033[36m", "\033[1;97m", "\033[90m", "\033[0m"
        else:
            cls.R = cls.G = cls.Y = cls.B = cls.M = ""
            cls.Cy = cls.W = cls.D = cls.X = ""


C.enable(colour())


def clear() -> None:
    """Clear the terminal (skipped when OMNI_NO_CLEAR is set)."""
    if os.environ.get("OMNI_NO_CLEAR"):
        return
    if sys.stdout.isatty():
        os.system("clear" if os.name != "nt" else "cls")


def rule(char: str = "-", width: int | None = None) -> None:
    print(char * (width or shutil.get_terminal_size((78, 24)).columns))


BANNER = r"""
   ____  __  __ _   _ ___
  / __ \|  \/  | \ | |_ _|
 | |  | | \  / |  \| || |
 | |__| | |\/| | |\  || |
  \____/|_|  |_|_| \_|___|
"""


def banner(version: str, codename: str, subtitle: str = "") -> None:
    print(C.Cy + BANNER + C.X)
    print(f"{C.W}  OMNI v{version}{C.X} {C.D}:: {codename}{C.X}")
    if subtitle:
        print(f"{C.D}  {subtitle}{C.X}")
    print(f"{C.D}  thirteen fused trades :: rf / wifi / radio / car / brute /"
          f" android / ios / pentest / mobile / windows / news / flip / core{C.X}")
    rule("=")


def info(msg: str) -> None:
    print(f"{C.Cy}[i]{C.X} {msg}")


def ok(msg: str) -> None:
    print(f"{C.G}[+]{C.X} {msg}")


def warn(msg: str) -> None:
    print(f"{C.Y}[!]{C.X} {msg}")


def err(msg: str) -> None:
    print(f"{C.R}[-]{C.X} {msg}")


def debug(msg: str) -> None:
    if os.environ.get("OMNI_DEBUG"):
        print(f"{C.D}[d] {msg}{C.X}")


def section(title: str) -> None:
    print()
    print(f"{C.W}== {title} {'=' * max(0, 74 - len(title))}{C.X}")


def table(headers: list[str], rows: list[list[str]],
          max_width: int | None = None) -> None:
    """Aligned column output, clipped to the terminal width."""
    if not rows:
        info("(no rows)")
        return
    cols = len(headers)
    body = [[str(c) for c in r][:cols] for r in rows]
    widths = [len(h) for h in headers]
    for r in body:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    cap = max_width or max(20, shutil.get_terminal_size((100, 24)).columns)
    while sum(widths) + 2 * (cols - 1) > cap and max(widths) > 8:
        widths[widths.index(max(widths))] -= 1

    def line(cells: list[str]) -> str:
        out = []
        for i, cell in enumerate(cells):
            text = cell if len(cell) <= widths[i] else cell[: widths[i] - 1] + "\u2026"
            out.append(text.ljust(widths[i]))
        return "  ".join(out).rstrip()

    print(C.W + line(headers) + C.X)
    print(C.D + line(["-" * w for w in widths]) + C.X)
    for r in body:
        print(line(r))


def kv(pairs: list[tuple[str, object]], indent: str = "  ") -> None:
    """Key/value block used by info/status dumps."""
    pad = max((len(str(k)) for k, _ in pairs), default=0)
    for key, val in pairs:
        print(f"{indent}{C.D}{str(key).ljust(pad)}{C.X}  {val}")


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default not in (None, "") else ""
    try:
        val = input(f"{C.Cy}?{C.X} {prompt}{suffix}: ").strip()
    except EOFError:
        return default or ""
    return val or (default or "")


def confirm(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    try:
        val = input(f"{C.Cy}?{C.X} {prompt} [{suffix}]: ").strip().lower()
    except EOFError:
        return default
    if not val:
        return default
    return val in ("y", "yes", "j", "ja")


def choose(prompt: str, options: list[str], default: int = 1) -> int | None:
    """Numeric picker; returns a 0-based index or None when cancelled."""
    for i, opt in enumerate(options, 1):
        marker = "*" if i == default else " "
        print(f"  {C.D}{marker}{C.X} {C.W}{i:2d}{C.X}  {opt}")
    raw = ask(prompt, str(default))
    if raw.lower() in ("q", "quit", "exit", "back", ""):
        return None
    try:
        idx = int(raw) - 1
    except ValueError:
        return None
    return idx if 0 <= idx < len(options) else None


class progress:
    """Tiny spinner/bar context manager for long-running local work."""

    def __init__(self, label: str, total: int | None = None, width: int = 28):
        self.label, self.total, self.width = label, total, width

    def __enter__(self) -> "progress":
        self.start = time.time()
        return self

    def update(self, done: int) -> None:
        if self.total:
            frac = min(1.0, done / self.total)
            filled = int(frac * self.width)
            bar = "#" * filled + "." * (self.width - filled)
            sys.stdout.write(f"\r{C.Cy}[{bar}]{C.X} {self.label} "
                             f"{done}/{self.total}")
        else:
            frames = "|/-\\"
            sys.stdout.write(f"\r{C.Cy}[{frames[done % 4]}]{C.X} {self.label}")
        sys.stdout.flush()

    def __exit__(self, *exc) -> None:
        elapsed = time.time() - self.start
        sys.stdout.write("\r" + " " * 78 + "\r")
        sys.stdout.flush()
        if not exc[0]:
            print(f"{C.G}[+]{C.X} {self.label} {C.D}({elapsed:.1f}s){C.X}")
