"""Normalise the tree to LF line endings and make shell scripts executable.

Windows checkouts are the usual way a working Linux tool stops working: a CRLF
``install.sh`` fails with ``/bin/bash^M: bad interpreter`` before it runs a
single line. This rewrites every text file with LF endings and restores the
executable bit a POSIX shell needs.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

TEXT_SUFFIXES = {".py", ".sh", ".md", ".txt", ".toml", ".cfg", ".ini", ".json",
                 ".yaml", ".yml", ".sub", ".marquee", ".mobileconfig"}
#: extension-less scripts that are still text
TEXT_NAMES = {"omni", "omni-doctor", "LICENSE", "Makefile", ".gitignore",
              ".gitattributes", ".editorconfig"}
EXECUTABLE = {"install.sh", "omni", "omni-doctor"}
SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache", "build", "dist",
             "node_modules", ".venv"}


def iter_text_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES \
                and path.name not in TEXT_NAMES:
            continue
        yield path


def to_lf(path: Path) -> bool:
    raw = path.read_bytes()
    fixed = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if fixed.startswith(b"\xef\xbb\xbf"):       # UTF-8 BOM breaks ast/py_compile
        fixed = fixed[3:]
    if fixed == raw:
        return False
    path.write_bytes(fixed)
    return True


def make_executable(path: Path) -> bool:
    if os.name == "nt":
        return False
    mode = path.stat().st_mode
    if mode & stat.S_IXUSR:
        return False
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return True


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    converted = [str(p.relative_to(root)) for p in iter_text_files(root)
                 if to_lf(p)]
    execs = [str(p.relative_to(root)) for p in iter_text_files(root)
             if p.name in EXECUTABLE and make_executable(p)]
    print(f"normalised {len(converted)} file(s) to LF")
    if execs:
        print(f"chmod +x: {', '.join(execs)}")
    if converted:
        for name in converted[:40]:
            print(f"  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
