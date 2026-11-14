"""Linux contract: LF line endings, exec bits, no Windows-only assumptions.

These keep the tree runnable on the actual target platform. A CRLF `install.sh`
fails before it executes, and POSIX `which` ignores a launcher without the
execute bit.
"""

import os
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
#: committed text files that must be LF and (for scripts) executable
SCRIPTS = ("install.sh", "bin/omni")
TEXT_GLOBS = ("omni/**/*.py", "tests/*.py", "*.md", "*.toml")


def _text_files():
    for pattern in TEXT_GLOBS:
        for path in ROOT.glob(pattern):
            if path.is_file():
                yield path
    for name in SCRIPTS:
        path = ROOT / name
        if path.is_file():
            yield path


def test_no_crlf_in_committed_text():
    offenders = [str(p.relative_to(ROOT)) for p in _text_files()
                 if b"\r\n" in p.read_bytes()]
    assert offenders == [], f"CRLF found (run scripts/normalise_eol.py): {offenders}"


@pytest.mark.skipif(os.name == "nt", reason="exec bits are POSIX-only")
def test_scripts_are_executable():
    for name in SCRIPTS:
        path = ROOT / name
        mode = path.stat().st_mode
        assert mode & stat.S_IXUSR, f"{name} is not executable"


def test_scripts_have_a_sh_shebang():
    for name in SCRIPTS:
        first = (ROOT / name).read_bytes().split(b"\n", 1)[0]
        assert first in (b"#!/bin/sh", b"#!/usr/bin/env bash"), (name, first)


def test_install_sh_guards_python_and_venv():
    body = (ROOT / "install.sh").read_text()
    assert "python3-venv" in body
    assert "3.11" in body
    assert "--deps-only" in body


def test_install_sh_keeps_declared_ios_packages():
    body = (ROOT / "install.sh").read_text()
    for package in ("libimobiledevice-utils", "usbmuxd"):
        assert package in body


def test_normaliser_targets_the_repo_root():
    body = (ROOT / "scripts" / "normalise_eol.py").read_text()
    assert "parent.parent" in body
