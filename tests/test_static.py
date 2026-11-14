"""Static checks that do not need hardware: syntax, BOM, undefined names.

`scripts/undefined_names.py` exists because a NameError (`iface_mod` in
rage.py) only surfaced when a test happened to hit that branch. This runs the
same analysis over the whole tree.
"""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PY_FILES = sorted(p for p in ROOT.joinpath("omni").rglob("*.py"))


def test_every_module_file_compiles():
    for path in PY_FILES:
        source = path.read_text(encoding="utf-8", errors="replace")
        try:
            compile(source, str(path), "exec")
        except SyntaxError as exc:                    # pragma: no cover
            pytest.fail(f"{path.relative_to(ROOT)}: {exc}")


def test_no_utf8_bom_in_python_files():
    offenders = [str(p.relative_to(ROOT)) for p in PY_FILES
                 if p.read_bytes().startswith(b"\xef\xbb\xbf")]
    assert offenders == [], f"BOM found (run scripts/normalise_eol.py): {offenders}"


def test_no_undefined_global_names():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "undefined_names.py")],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(ROOT))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 problem(s)" in result.stdout
