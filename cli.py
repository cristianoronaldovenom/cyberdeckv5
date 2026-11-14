"""OMNI command dispatcher and interactive shell.

``omni run <module> [OPT=value ...]`` for one-shot use, bare ``omni`` for the
msf-style shell (``use`` / ``set`` / ``options`` / ``run`` / ``back`` /
``search`` / ``info`` / ``exit``). ``--json`` turns every ``run`` into machine
readable output on stdout.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys

import omni
from omni.core import console
from omni.core.module import FAMILIES, Module, registry

__all__ = ["main", "Shell"]


def _modules_json() -> list[dict]:
    out = []
    for fam in registry.families():
        for mod in registry.all(fam):
            out.append({"name": mod.NAME, "family": fam,
                        "description": mod.DESCRIPTION,
                        "needs": list(mod.NEEDS)})
    return out


def _print_error(exc: Exception, verbose: bool) -> None:
    if verbose:
        console.err(f"{type(exc).__name__}: {exc}")
        import traceback
        traceback.print_exc()
    else:
        console.err(str(exc))


class Shell:
    """The interactive use/set/run loop over one loaded module."""

    def __init__(self, mod: Module):
        self.mod = mod

    def cmdloop(self) -> None:
        while True:
            try:
                raw = input(f"{console.C.Cy}{self.mod.NAME}{console.C.X} > ")
            except (EOFError, KeyboardInterrupt):
                print()
                return
            cmd, *args = raw.split()
            try:
                if cmd in ("back", "exit", "quit"):
                    return
                if cmd == "options":
                    self.mod.help()
                elif cmd == "info":
                    self.mod.help()
                elif cmd == "set":
                    if not args:
                        console.warn("usage: set OPTION value")
                        continue
                    val = raw.split(None, 2)[2] if len(raw.split(None, 2)) > 2 else ""
                    self.mod.set(args[0], val)
                    console.ok(f"{args[0]} => {self.mod.opts[args[0].upper()].shown()}")
                elif cmd == "run":
                    self.mod.run()
                elif cmd == "search":
                    registry.print_search(" ".join(args))
                else:
                    console.warn("commands: set | run | options | info | "
                                 "search | back")
            except Exception as exc:  # noqa: BLE001 — shell must survive
                _print_error(exc, verbose=bool(__import__("os").environ.get("OMNI_DEBUG")))


def _build_parser() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--json", action="store_true",
                        default=argparse.SUPPRESS, help="emit JSON summaries")
    parent.add_argument("--no-color", action="store_true",
                        default=argparse.SUPPRESS,
                        help="disable ANSI colour (sets NO_COLOR)")
    parent.add_argument("--verbose", "-v", action="store_true",
                        default=argparse.SUPPRESS,
                        help="tracebacks and debug output")
    parent.add_argument("--elevate", action="store_true",
                        default=argparse.SUPPRESS,
                        help="relaunch as administrator (Windows UAC)")
    p = argparse.ArgumentParser(prog="omni",
                                description="OMNI — thirteen fused security trades",
                                parents=[parent])
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("list", parents=[parent], help="list every module")
    sub.add_parser("dash", parents=[parent],
                   help="tabbed dashboard (interactive TUI)")
    gui_parser = sub.add_parser("gui", parents=[parent],
                                help="clickable dashboard window (Tkinter)")
    gui_parser.add_argument("--check", action="store_true",
                            help="build and close the window (smoke test)")
    sub.add_parser("menu", parents=[parent],
                   help="the plain goal menu (double-click behaviour)")
    sub.add_parser("goals", parents=[parent],
                   help="list the one-click goals")
    gp = sub.add_parser("goal", parents=[parent],
                        help="run one goal end to end (Wi-Fi attack, ...)")
    gp.add_argument("name", help="goal key (see `omni goals`)")
    gp.add_argument("--no-install", action="store_true",
                    help="do not try to install missing tools first")
    sub.add_parser("devices", parents=[parent],
                   help="what this box has (adapters, phones, radios, tools)")
    at = sub.add_parser("auto", parents=[parent],
                        help="one-click audit: safe checks, no questions")
    at.add_argument("--profile", choices=("safe", "full"), default="safe")
    at.add_argument("--open", action="store_true",
                    help="open the report folder when finished")
    stp = sub.add_parser("setup", parents=[parent],
                         help="install missing external tools")
    stp.add_argument("tools", nargs="*", help="specific tools (blank = everything)")
    d = sub.add_parser("doctor", parents=[parent],
                       help="check tool/hardware readiness")
    d.add_argument("--family", default="", help="only check one trade")
    q = sub.add_parser("search", parents=[parent], help="search the registry")
    q.add_argument("args", nargs="*")
    r = sub.add_parser("run", parents=[parent], help="run one module")
    r.add_argument("module")
    r.add_argument("opts", nargs="*", help="OPT=value overrides")
    s = sub.add_parser("use", parents=[parent], help="interactive shell")
    s.add_argument("module")
    p.add_argument("module_pos", nargs="?", help="module name (bare invocation)")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    ns = parser.parse_args(argv if argv is not None else sys.argv[1:])
    import os
    if getattr(ns, "no_color", False):
        os.environ["NO_COLOR"] = "1"
        console.C.enable(False)
    if getattr(ns, "verbose", False):
        os.environ["OMNI_DEBUG"] = "1"
    if getattr(ns, "elevate", False):
        from omni.core import elevate
        if elevate.ensure(sys.argv):
            return 0
    try:
        return _dispatch(ns, parser)
    except KeyboardInterrupt:
        print()
        return 130


def _dispatch(ns, parser) -> int:
    as_json = bool(getattr(ns, "json", False))
    verbose = bool(getattr(ns, "verbose", False))
    if ns.cmd == "dash":
        from omni.core.tui import run_dashboard
        return run_dashboard()
    if ns.cmd == "gui":
        from omni.core import gui
        return gui.run(check=bool(getattr(ns, "check", False)))
    if ns.cmd == "menu":
        from omni.core import menu
        return menu.run()
    if ns.cmd == "goals":
        from omni.core import goals
        for goal in goals.GOALS:
            ready, note = goals.readiness(goal)
            print(f"  {goal.key:<18} {goal.title:<18} "
                  f"{'READY' if ready else 'NEEDS SETUP':<12} {goal.subtitle}")
            if not ready:
                print(f"  {'':<18} {note}")
        return 0
    if ns.cmd == "goal":
        from omni.core import goals
        try:
            report = goals.run_goal(ns.name, install=not ns.no_install)
        except KeyError as exc:
            console.err(str(exc))
            return 1
        console.ok(f"{report['title']}: {report['outcome']}")
        return 0
    if ns.cmd == "devices":
        return _run_module("core.devices", [], as_json, verbose)
    if ns.cmd == "auto":
        return _run_module("core.auto",
                           [f"PROFILE={ns.profile}",
                            f"OPEN={'true' if ns.open else 'false'}"],
                           as_json, verbose)
    if ns.cmd == "setup":
        return _run_module("core.setup",
                           [f"TOOLS={' '.join(getattr(ns, 'tools', []))}"],
                           as_json, verbose)
    if ns.cmd == "list" or (not ns.cmd and not ns.module_pos):
        if as_json:
            print(json.dumps(_modules_json(), indent=2))
            return 0
        if not ns.cmd:
            # a bare `omni` opens the goal menu; the curses dashboard is used
            # only where curses exists and a real terminal is attached
            import sys
            if sys.stdin.isatty() and sys.stdout.isatty():
                try:
                    import curses  # noqa: F401
                except ImportError:
                    from omni.core import menu
                    return menu.run()
                from omni.core.tui import run_dashboard
                return run_dashboard()
        console.banner(omni.__version__, omni.CODENAME)
        for fam, label in FAMILIES.items():
            mods = registry.all(fam)
            if not mods:
                continue
            console.section(f"{fam} — {label}")
            for m in mods:
                print(f"  {console.C.G}{m.NAME:<22}{console.C.X} {m.DESCRIPTION}")
        console.rule()
        return 0

    if ns.cmd == "doctor":
        return _run_module("core.doctor", [f"FAMILY={ns.family}"],
                          as_json, verbose)

    if ns.cmd == "search":
        hits = registry.search(" ".join(ns.args) if getattr(ns, "args", None) else "")
        for m in hits:
            print(f"  {console.C.G}{m.NAME:<22}{console.C.X} {m.DESCRIPTION}")
        return 0

    name = ns.module if ns.cmd in ("run", "use") else ns.module_pos
    if not name:
        parser.error("a module name is required")
    if ns.cmd == "use":
        try:
            mod = registry.build(name)
        except (KeyError, ValueError) as exc:
            console.err(str(exc))
            return 1
        Shell(mod).cmdloop()
        return 0
    return _run_module(name, ns.opts, as_json, verbose)


def _jsonable(obj):
    if isinstance(obj, (list, dict, str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _run_module(name: str, pairs: list[str], as_json: bool,
                verbose: bool) -> int:
    """Build, populate and run a module; shared by ``doctor`` and ``run``."""
    try:
        mod = registry.build(name)
    except (KeyError, ValueError) as exc:
        _print_error(exc, verbose)
        return 1
    for pair in pairs:
        key, _, val = pair.partition("=")
        try:
            mod.set(key, val)
        except (KeyError, ValueError) as exc:
            _print_error(exc, verbose)
            return 1
    try:
        result = mod.run()
        if as_json:
            print(json.dumps({"module": mod.NAME, "ok": True,
                              "result": _jsonable(result)}, default=str))
        return 0
    except Exception as exc:  # noqa: BLE001
        from omni.core.proc import ToolMissing
        _print_error(exc, verbose)
        if isinstance(exc, ToolMissing):
            # a missing external binary is a normal, explained outcome
            console.info("skip it, or make it work later with: omni setup")
            if as_json:
                print(json.dumps({"module": mod.NAME, "ok": False,
                                  "error": str(exc)}))
            return 0
        if isinstance(exc, ValueError) and "missing required option" in str(exc):
            usage = mod.usage()
            if usage:
                print(usage)
        if as_json:
            print(json.dumps({"module": mod.NAME, "ok": False,
                              "error": str(exc)}))
        return 0 if isinstance(exc, ValueError) else 1




if __name__ == "__main__":
    raise SystemExit(main())
