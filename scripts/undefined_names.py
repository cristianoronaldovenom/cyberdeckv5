"""Find undefined names inside every module's execute() without running it.

The `iface_mod` NameError in rage.py only showed up because a test happened to
exercise the discovery path. This compiles each module and resolves every
LOAD_GLOBAL / LOAD_NAME against builtins + module globals + the function's own
locals, reporting names that resolve to nothing.
"""

from __future__ import annotations

import builtins
import dis
import py_compile
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def module_globals(path: Path) -> set[str]:
    """Names bound at module level (imports, defs, assignments)."""
    source = path.read_text(encoding="utf-8", errors="replace")
    tree = compile(source, str(path), "exec")
    names: set[str] = set()
    for node in tree.co_consts:
        if isinstance(node, types.CodeType):
            names |= {n for n in node.co_names}
    # co_names of the module code covers imports/defs/assignments cheaply
    names |= set(tree.co_names)
    return names


def undefined_in_code(code: types.CodeType) -> list[tuple[str, str]]:
    """(function, name) pairs that look undefined."""
    found: list[tuple[str, str]] = []

    def walk(co: types.CodeType) -> None:
        locals_here = (set(co.co_varnames) | set(co.co_cellvars)
                       | set(co.co_freevars) | set(co.co_names))
        for instr in dis.get_instructions(co):
            if instr.opname not in ("LOAD_GLOBAL", "LOAD_NAME"):
                continue
            name = instr.argval
            if isinstance(name, str) and name not in locals_here:
                found.append((co.co_name, name))
        for const in co.co_consts:
            if isinstance(const, types.CodeType):
                walk(const)

    walk(code)
    return found


def main() -> int:
    bad = 0
    checked = 0
    for path in sorted(ROOT.joinpath("omni").rglob("*.py")):
        source = path.read_text(encoding="utf-8", errors="replace")
        try:
            code = compile(source, str(path), "exec")
        except SyntaxError as exc:
            print(f"SYNTAX {path.relative_to(ROOT)}: {exc}")
            bad += 1
            continue
        checked += 1
        available = (module_globals(path) | set(dir(builtins))
                     | {"__file__", "__name__", "__doc__"})
        for function, name in undefined_in_code(code):
            if name in available:
                continue
            print(f"UNDEFINED {path.relative_to(ROOT)}::{function} -> {name}")
            bad += 1
    print(f"checked {checked} file(s), {bad} problem(s)")
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
