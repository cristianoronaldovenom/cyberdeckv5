"""The plain menu: goals first, then the modules underneath.

This is what a double-click opens, and it is deliberately shallow:

1. **what do you want to do** — a dozen goals ("steal an iPhone's saved
   passwords", "fake Wi-Fi people join by themselves", "take this Windows box
   over"). No module names to learn;
2. **which target** — the task discovers them (attached phones, APs in range,
   LAN hosts) and lists them numbered, so you pick instead of typing MACs;
3. it shows the short chain it will run, then runs it step by step and leaves
   the loot where the modules always put it.

"browse by trade" at the bottom is the old module list for when a goal is not
enough. Everything the task menu runs is a normal module, so anything visible
here is also `omni run …` from a shell.
"""

from __future__ import annotations

import os
import threading
import time

from omni.core import console, devices, proc, tasks
from omni.core.module import FAMILIES, Module, registry

__all__ = ["run", "choose_task", "choose_target", "run_task", "fill_options",
           "choose_trade", "choose_module"]

BACK = ("", "q", "b")


def _read(prompt: str, default: str = "") -> str:
    try:
        return input(prompt).strip() or default
    except (EOFError, KeyboardInterrupt):
        return "q"


def choose_task(read=_read) -> str:
    """Numbered goal list; ``q`` returns ``""``."""
    console.section("what do you want to do")
    print(f"{console.C.W}  [a]{console.C.X} ONE-CLICK — run the safe audit now, "
          f"no questions")
    print(f"  {console.C.D}[i]{console.C.X} install missing tools  "
          f"{console.C.D}[0]{console.C.X} show this box  "
          f"{console.C.D}[m]{console.C.X} all modules  "
          f"{console.C.D}[q]{console.C.X} quit")
    print()
    index = 0
    lookup: dict[int, str] = {}
    for trade, group in tasks.by_trade().items():
        print(f"  {console.C.D}{trade.upper()}{console.C.X}")
        for task in group:
            index += 1
            lookup[index] = task.key
            print(f"   {console.C.G}{index}{console.C.X}  {task.label}")
            print(f"      {console.C.D}{task.blurb}{console.C.X}")
    answer = read(f"{console.C.G}>{console.C.X} number: ")
    if answer in ("q", "quit", "exit"):
        return ""
    if answer == "0":
        return "devices"
    if answer.lower() == "m":
        return "modules"
    if answer.lower() == "a":
        return "auto"
    if answer.lower() == "i":
        return "install"
    try:
        return lookup[int(answer)]
    except (ValueError, KeyError):
        console.warn("no such number")
        return ""


def choose_target(task: tasks.Task, read=_read) -> str:
    """Numbered target list for a task, or a typed value when none is found."""
    if not task.discover:
        return ""
    console.info(f"looking for {task.discover} targets …")
    found = tasks.discover(task.discover)
    if found:
        console.section("which one")
        for index, target in enumerate(found, 1):
            print(f"   {console.C.G}{index}{console.C.X}  {target.label}")
        print(f"  {console.C.D}q{console.C.X}  back")
        answer = read(f"{console.C.G}>{console.C.X} number: ")
        if answer in BACK:
            return "back"
        try:
            return found[int(answer) - 1].value
        except (ValueError, IndexError):
            console.warn("no such number")
            return "back"
    console.warn("nothing found automatically")
    if task.manual:
        return read(f"{console.C.G}?{console.C.X} {task.manual}: ")
    return ""


def _summary(result) -> str:
    """One short line describing what a step returned, for the log."""
    if isinstance(result, dict):
        bits = []
        for key in ("sent", "events", "files", "creds", "items", "processes",
                    "killed", "installed", "count"):
            if key in result:
                value = result[key]
                bits.append(f"{key}={'%d' % len(value) if isinstance(value, list) else value}")
        return ", ".join(bits) or f"{len(result)} key(s)"
    if isinstance(result, list):
        return f"{len(result)} item(s)"
    return str(result)[:80] if result is not None else "-"


class _Heartbeat:
    """Print ``[·] module … Ns`` every two seconds while a step runs."""

    def __init__(self, module: str):
        self.module = module
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None

    def __enter__(self) -> "_Heartbeat":
        def beat() -> None:
            started = time.time()
            while not self.stop.wait(2.0):
                print(f"  {console.C.D}[·]{console.C.X} {self.module} still "
                      f"running … {int(time.time() - started)}s", flush=True)

        self.thread = threading.Thread(target=beat, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=2.5)


WSL_RADIOS = ("wifi.pineapple", "wifi.eviltwin", "wifi.handshake",
              "wifi.jam", "wifi.deauth")


def radio_warning(module: str) -> str:
    """A one-line warning when a WSL-backed radio step has no adapter yet."""
    from omni.core import platform as host, proc

    if not host.is_windows() or module not in WSL_RADIOS:
        return ""
    if not proc.has("wsl"):
        return ""
    out = proc.run(["wsl", "-e", "sh", "-lc",
                    "ls /sys/class/net | grep '^wl' | head -n 1"], timeout=20).out
    if out.strip():
        return ""
    return ("WSL cannot see a wireless adapter — attach it first: "
            "`usbipd list`, then `usbipd attach --wsl --busid <id>`")


def run_task(task: tasks.Task, read=_read, auto: bool = False) -> dict:
    """Discover, confirm and run a task's chain; returns the step results.

    ``auto=True`` skips both the target picker and the go prompt, using the
    first discovered target, so a goal can be one keypress.
    """
    if auto and task.discover:
        found = tasks.discover(task.discover)
        target = found[0].value if found else ""
        console.info("using " + (found[0].label if found else "no target"))
    else:
        target = choose_target(task, read)
    if target == "back":
        return {"skipped": True}
    console.section("what will run")
    for name, opts in task.steps:
        actual = tasks.substitute(name)
        extra = "  ".join(f"{key}={value}" for key, value in opts)
        note = f" {console.C.D}(instead of {name}: no tool){console.C.X}" \
            if actual != name else ""
        print(f"   {console.C.G}•{console.C.X} {actual} {console.C.D}{extra}"
              f"{console.C.X}{note}")
    if target:
        print(f"   {console.C.D}target: {target}{console.C.X}")
    warning = radio_warning(tasks.substitute(task.steps[0][0]))
    if warning:
        console.warn(warning)
    if not auto and read(f"{console.C.G}?{console.C.X} go? [Y/n]: "
                         ).lower().startswith("n"):
        return {"skipped": True}

    results = []
    os.environ["OMNI_LIVE"] = "1"           # stream child output while we run
    try:
        for index, (name, opts) in enumerate(task.steps, 1):
            name = tasks.substitute(name)
            values = dict(opts)
            if target and task.target_opt:
                values[task.target_opt] = target
            print(f"{console.C.D}[{index}/{len(task.steps)}]{console.C.X} "
                  f"{console.C.G}{name}{console.C.X}", flush=True)
            started = time.time()
            try:
                mod = registry.build(name, **values)
            except (KeyError, ValueError) as exc:
                console.err(f"{name}: {exc}")
                results.append({"module": name, "ok": False, "error": str(exc)})
                continue
            try:
                with _Heartbeat(name):
                    outcome = mod.run()
                console.ok(f"{name} finished in {time.time() - started:.1f}s — "
                           f"{_summary(outcome)}")
                results.append({"module": name, "ok": True})
            except Exception as exc:              # noqa: BLE001 - report, go on
                console.err(f"{name} failed after {time.time() - started:.1f}s: "
                            f"{exc}")
                results.append({"module": name, "ok": False, "error": str(exc)})
    finally:
        os.environ.pop("OMNI_LIVE", None)
    failed = [row for row in results if not row["ok"]]
    if failed:
        console.warn(f"{len(failed)} of {len(results)} step(s) failed — the "
                     "rest still ran")
    else:
        console.ok(f"task finished: {len(results)} step(s) ok")
    read(f"{console.C.D}enter for the menu{console.C.X} ")
    return {"task": task.key, "steps": results}



def _read(prompt: str, default: str = "") -> str:
    try:
        return input(prompt).strip() or default
    except (EOFError, KeyboardInterrupt):
        return "q"


def _trade_menu() -> list[tuple[str, str, int]]:
    """(family, label, module count) for the browse-by-trade screen."""
    from omni.core.module import FAMILIES

    rows = []
    for family, label in FAMILIES.items():
        count = len(registry.all(family))
        if count:
            rows.append((family, label, count))
    return rows


def choose_trade(read=_read) -> str:
    """Numbered trade list; ``q`` returns ``""``."""
    rows = _trade_menu()
    console.section("browse by trade")
    for index, (_family, label, count) in enumerate(rows, 1):
        print(f"  {console.C.G}{index}{console.C.X}  {label} "
              f"{console.C.D}({count} modules){console.C.X}")
    print(f"  {console.C.D}q{console.C.X}  back to the goals")
    answer = read(f"{console.C.G}>{console.C.X} number: ")
    if answer in BACK:
        return ""
    try:
        return rows[int(answer) - 1][0]
    except (ValueError, IndexError):
        console.warn("no such number")
        return ""


def choose_module(family: str, read=_read) -> str:
    """Numbered module list for one trade; ``q`` returns ``""``."""
    mods: list[type[Module]] = registry.all(family)
    if not mods:
        console.warn("nothing here")
        return ""
    console.section(f"{FAMILIES.get(family, family)} — pick a module")
    for index, cls in enumerate(mods, 1):
        missing = [tool for tool in getattr(cls, "NEEDS", ()) if not _has(tool)]
        mark = f"{console.C.Y}!" if missing else f"{console.C.G}+"
        note = f"  {console.C.D}needs: {', '.join(missing)}{console.C.X}" \
            if missing else ""
        print(f"  {mark}{console.C.X} {index:>2}  {cls.NAME:<24}"
              f"{cls.DESCRIPTION}{note}")
    print(f"  {console.C.D}q{console.C.X}  back")
    answer = read(f"{console.C.G}>{console.C.X} number: ")
    if answer in BACK:
        return ""
    try:
        return mods[int(answer) - 1].NAME
    except (ValueError, IndexError):
        console.warn("no such number")
        return ""


def fill_options(mod: Module, read=_read) -> list[str]:
    """Ask for the module's options, required first, blank keeps the default."""
    wanted = sorted(mod.opts.values(), key=lambda opt: not opt.required)
    if not wanted:
        console.info("this module takes no options")
        return []
    console.section("what it needs")
    console.table(["option", "what to type", "required", "default"],
                  [[opt.name, opt.description, "yes" if opt.required else "",
                    opt.default or "-"] for opt in wanted])
    pairs: list[str] = []
    for opt in wanted:
        if not opt.required and not opt.default and not opt.value:
            continue
        label = f"{console.C.G}?{console.C.X} {opt.name}"
        hint = f" {console.C.D}({opt.description}){console.C.X}"
        default = f" {console.C.D}[{opt.default}]{console.C.X}" \
            if opt.default else ""
        value = read(f"{label}{hint}{default}: ")
        if value and value != "q":
            pairs.append(f"{opt.name}={value}")
        elif opt.required:
            console.warn(f"{opt.name} is required")
    return pairs


def run(read=_read) -> int:
    """The whole menu loop; returns a process exit code."""
    while True:
        registry.load()
        console.banner(__import__("omni").__version__, "field shell")
        console.info("pick a goal — it finds the targets and runs the chain")
        choice = choose_task(read)
        if not choice:
            return 0
        if choice == "devices":
            devices.render(devices.inventory())
            read(f"{console.C.D}enter to go back{console.C.X} ")
            continue
        if choice == "auto":
            from omni.core import auto
            auto.run()
            read(f"{console.C.D}enter for the menu{console.C.X} ")
            continue
        if choice == "install":
            from omni.core import setup
            offer_install(setup.recommended(), read)
            read(f"{console.C.D}enter for the menu{console.C.X} ")
            continue
        if choice == "modules":
            browse(read)
            continue
        try:
            task = tasks.get(choice)
        except ValueError as exc:
            console.err(str(exc))
            continue
        missing = tasks.step_needs(task)
        if missing:
            console.warn(f"missing tool(s): {', '.join(missing)}")
            offer_install(missing, read)
        run_task(task, read)


def offer_install(tools: list[str], read=_read) -> None:
    """Explain what is missing, offer to install it, then re-check once."""
    from omni.core import setup

    for line in setup.explain(tools):
        console.info(line)
    if setup.wsl_missing():
        console.warn("these are Linux tools and Windows has no WSL yet — "
                     "`wsl --install -d Ubuntu` gives them a home (one reboot)")
        if read(f"{console.C.G}?{console.C.X} open the WSL install? [y/N]: "
                ).lower().startswith("y"):
            proc.run(setup.wsl_plan(), timeout=1800)
            console.info("reboot, then run the goal again")
        return
    plan = setup.plan_for(tools)
    if not plan:
        console.info("no automatic install for these on this platform — "
                     "install them yourself, then run the goal again")
        return
    for tool, argv in plan:
        print(f"   {console.C.D}{tool}: {' '.join(argv)}{console.C.X}")
    if any(argv and argv[0] == "wsl" for _tool, argv in plan):
        console.info("these install inside WSL — the radio still has to be "
                     "passed through (`usbipd list`, then "
                     "`usbipd attach --wsl --busid <id>`) before hostapd sees it")
    if not read(f"{console.C.G}?{console.C.X} install now? [Y/n]: "
                ).lower().startswith("n"):
        os.environ["OMNI_LIVE"] = "1"          # stream the package manager
        try:
            with _Heartbeat("install"):
                setup.install([tool for tool, _argv in plan])
        finally:
            os.environ.pop("OMNI_LIVE", None)
    left = [tool for tool in tools if not _has(tool)]
    if left:
        console.warn("still missing: " + ", ".join(left)
                     + " — a fresh shell may be needed for PATH")
    else:
        console.ok("ready")


def browse(read=_read) -> None:
    """The old module list, one trade at a time."""
    while True:
        family = choose_trade(read)
        if not family:
            return
        while True:
            name = choose_module(family, read)
            if not name:
                break
            try:
                mod = registry.build(name)
            except (KeyError, ValueError) as exc:
                console.err(str(exc))
                continue
            pairs = fill_options(mod, read)
            for pair in pairs:
                key, _, value = pair.partition("=")
                mod.set(key, value)
            if mod.missing():
                console.warn("still missing: " + ", ".join(mod.missing()))
                continue
            console.info(f"running {mod.NAME} …")
            os.environ["OMNI_LIVE"] = "1"
            try:
                with _Heartbeat(mod.NAME):
                    outcome = mod.run()
                console.ok(f"{mod.NAME} finished — {_summary(outcome)}")
            except Exception as exc:              # noqa: BLE001 - keep going
                console.err(f"{mod.NAME}: {exc}")
            finally:
                os.environ.pop("OMNI_LIVE", None)
            read(f"{console.C.D}enter for the list{console.C.X} ")


def _has(tool: str) -> bool:
    from omni.core import proc
    return proc.has(tool)
