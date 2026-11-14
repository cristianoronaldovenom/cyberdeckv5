"""Plain-English goals: the five buttons people actually want.

Each goal knows how to find its target, which modules do the work, which tools
make it possible, and what to do when those tools are absent. A goal never
raises: it returns a report with one of three honest outcomes â€”

    done     â€” the chain ran and produced something
    partial  â€” the target or a tool was missing; a fallback still ran
    skipped  â€” nothing found; the report says exactly what to do next

``run_goal`` is what the GUI buttons and ``omni goal`` call. ``readiness`` is
what paints the READY / NEEDS SETUP badge, so the user knows before clicking.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from omni.core import console, proc, setup
from omni.core.module import registry

__all__ = ["Goal", "GOALS", "get", "readiness", "run_goal"]


@dataclass(frozen=True)
class Goal:
    key: str
    title: str
    subtitle: str
    steps: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]
    fallback: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = ()
    optional: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = ()
    discover: str = ""              # iphone | android | wifi | hosts
    target_opt: str = ""
    tools: tuple[str, ...] = ()     # any one of these is enough
    install: tuple[str, ...] = ()   # what auto-install should try
    note: str = ""                  # shown when tools are missing
    timeout: int = 45               # seconds per step; a hang cannot freeze UI
    soft: bool = False              # useful even when the optional tools are absent


def _steps(*pairs: tuple[str, dict]) -> tuple:
    return tuple((name, tuple(sorted(opts.items()))) for name, opts in pairs)


GOALS: tuple[Goal, ...] = (
    Goal("wifi-attack", "Wi-Fi attack",
         "Scan networks, show saved keys, capture a handshake when possible",
         _steps(("wifi.scan", {}), ("wifi.passwords", {})),
         optional=_steps(("wifi.handshake", {"SECONDS": "30"}),
                         ("wifi.crack", {})),
         discover="wifi", target_opt="BSSID",
         tools=("airodump-ng", "aireplay-ng"),
         note="handshake skipped: no monitor adapter (WSL on Windows); "
              "the scan and saved keys are shown", timeout=40, soft=True),
    Goal("iphone-takeover", "iPhone takeover",
         "Connect to the attached iPhone, check control and read its identity",
         _steps(("ios.probe", {}), ("ios.info", {}), ("ios.status", {})),
         fallback=_steps(("ios.devices", {})),
         discover="iphone", target_opt="UDID",
         tools=("pymobiledevice3", "ideviceinfo"),
         install=("pymobiledevice3",),
         note="install pymobiledevice3, then unlock the phone and tap Trust"),
    Goal("windows-takeover", "Windows takeover",
         "Saved Wi-Fi keys, browser logins, users and startup entries",
         _steps(("windows.wifi", {}), ("windows.logins", {}),
                ("windows.recon", {"WHAT": "admins"}),
                ("windows.recon", {"WHAT": "autoruns"})),
         fallback=_steps(("windows.recon", {"WHAT": "users"})),
         tools=("powershell", "reg"),
         note="runs natively on Windows; other hosts get a clear note"),
    Goal("android-attack", "Android attack",
         "Device info, saved accounts, messages and installed packages",
         _steps(("android.info", {}), ("android.creds", {}),
                ("android.apps", {})),
         fallback=_steps(("android.devices", {})),
         discover="android", target_opt="SERIAL",
         tools=("adb",),
         install=("adb",),
         note="enable USB debugging and accept the RSA prompt on the phone"),
    Goal("wifi-jam", "Wi-Fi jam",
         "Kick every client off the network (deauth flood)",
         _steps(("wifi.jam", {"MODE": "deauth", "CHANNELS": "1-13",
                              "SECONDS": "20"})),
         fallback=_steps(("wifi.scan", {})),
         discover="wifi", target_opt="BSSID",
         tools=("mdk4", "aireplay-ng"),
         note="needs mdk4 or aireplay-ng and a monitor-mode adapter",
         timeout=25),
    Goal("car-key", "Car key",
         "Listen for a fob, predict its rolling counters and replay them",
         _steps(("car.unlock", {"SECONDS": "8", "WINDOW": "16"})),
         fallback=_steps(("car.brands", {})),
         tools=(), note="without a CC1101 this runs in labelled demo mode",
         timeout=35),
    Goal("network-scan", "Network scan",
         "Every host on this LAN and the ports it exposes",
         _steps(("pentest.hostscan", {"SWEEP": "true"})),
         tools=(), note="uses a built-in connect scan; nmap is optional"),
    Goal("saved-passwords", "Saved passwords",
         "Wi-Fi keys saved on this computer, in clear text",
         _steps(("wifi.passwords", {})),
         tools=(), note="reads the current user's Wi-Fi profiles"),
    Goal("one-click", "One-click audit",
         "All safe local checks, with a report you can open",
         _steps(("core.auto", {"PROFILE": "safe", "OPEN": "true"})),
         tools=()),
    Goal("this-box", "This box",
         "Adapters, phones, radios, tools and loot on this machine",
         _steps(("core.devices", {})),
         tools=()),
)

#: the five headline buttons, in the order asked for
PRIMARY = ("wifi-attack", "iphone-takeover", "windows-takeover",
           "android-attack", "wifi-jam")
SECONDARY = ("car-key", "network-scan", "saved-passwords", "one-click",
             "this-box")


def get(key: str) -> Goal:
    for goal in GOALS:
        if goal.key == key:
            return goal
    raise KeyError(f"no such goal: {key}")


def _tool_state(goal: Goal) -> tuple[bool, str]:
    if not goal.tools:
        return True, "ready"
    present = [tool for tool in goal.tools if proc.has(tool)]
    if present:
        return True, "ready"
    if goal.soft:
        return True, "scan only"
    return False, "needs " + " or ".join(goal.tools)


def readiness(goal: Goal) -> tuple[bool, str]:
    """(ready, short note) for a card badge; cheap and never raises.

    Target discovery is deliberately *not* done here: it would turn window
    startup into a multi-second scan. The click does that, and reports "no
    target" with the next action instead.
    """
    return _tool_state(goal)


def _discover(goal: Goal, log) -> str:
    if not goal.discover:
        return ""
    try:
        from omni.core import tasks
        found = tasks.discover(goal.discover)
    except Exception as exc:  # noqa: BLE001
        log(f"target lookup failed: {exc}")
        return ""
    if not found:
        log(f"no {goal.discover} target found â€” {goal.note or 'connect one first'}")
        return ""
    log(f"target: {found[0].label}")
    return found[0].value


def _empty(value) -> bool:
    """True when a module ran but produced nothing worth reporting."""
    if value is None:
        return True
    if isinstance(value, (list, tuple, set, dict, str)):
        if len(value) == 0:
            return True
    if isinstance(value, dict):
        return value.get("count") == 0
    return False


def _call(name: str, values: dict, timeout: int):
    """Run one module off-thread with a hard cap; returns (value, error)."""
    box: dict = {}

    def work() -> None:
        try:
            mod = registry.build(name, **values)
            box["mod"] = mod
            if mod.missing():
                box["missing"] = mod.missing()
                return
            box["value"] = mod.run()
        except BaseException as exc:  # noqa: BLE001 - handed to the caller
            box["error"] = exc

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    worker.join(max(1, timeout))
    if worker.is_alive():
        return None, TimeoutError(
            f"{name} took longer than {timeout}s — moved on")
    if "missing" in box:
        return None, ValueError("needs " + ", ".join(box["missing"]))
    return box.get("value"), box.get("error")


def _run_steps(steps, target: str, target_opt: str, log, progress,
               timeout: int = 45) -> list[dict]:
    results = []
    total = len(steps)
    for index, (name, options) in enumerate(steps, 1):
        if progress:
            progress(index, total, name)
        values = dict(options)
        cls = registry.get(name)
        if (target and target_opt and cls is not None
                and any(opt.name == target_opt for opt in cls.OPTIONS)):
            values[target_opt] = target
        log(f"[{index}/{total}] {name}")
        value, error = _call(name, values, timeout)
        if error is None:
            empty = _empty(value)
            results.append({"module": name, "ok": not empty, "empty": empty,
                            "value": value})
            log("  done" if not empty else "  done — but nothing was found")
            continue
        from omni.core.proc import ToolMissing
        skipped = isinstance(error, (ToolMissing, ValueError))
        kind = "missing tool" if isinstance(error, ToolMissing) else \
            type(error).__name__
        log(f"  {kind}: {str(error)[:180]}")
        results.append({"module": name, "ok": False, "skipped": skipped,
                        "reason": str(error)[:300]})
    return results


def auto_install(goal: Goal, log) -> None:
    """Try to install the goal's tools; quiet and forgiving."""
    if not goal.install:
        return
    missing = setup.missing(list(goal.install))
    if not missing:
        return
    log("installing: " + ", ".join(missing) + " (first run only)")
    try:
        setup.install(missing)
    except Exception as exc:  # noqa: BLE001
        log(f"  install skipped: {exc}")


def run_goal(key: str, log=console.info, progress=None,
             install: bool = False) -> dict:
    """Run one goal end to end; always returns a report, never raises.

    Every step is capped by ``goal.timeout``, so a hung adapter cannot leave a
    button spinning. Optional steps (a real handshake) only run when their
    tools are present; otherwise the always-available path still produces the
    network list and saved keys.
    """
    goal = get(key)
    log(f"{goal.title}: {goal.subtitle}")
    if install:
        auto_install(goal, log)
    target = _discover(goal, log)
    results = _run_steps(goal.steps, target, goal.target_opt, log, progress,
                         goal.timeout)
    ran = [row for row in results if row["ok"]]

    if goal.optional:
        ready = bool([tool for tool in goal.tools if proc.has(tool)])
        if ready:
            log("extra: " + ", ".join(name for name, _o in goal.optional))
            extra = _run_steps(goal.optional, target, goal.target_opt, log,
                               progress, goal.timeout)
            results.extend(extra)
            ran.extend(row for row in extra if row["ok"])
        elif goal.note:
            log(goal.note)

    used_fallback = False
    if not ran and goal.fallback:
        log("trying the fallback path")
        fallback = _run_steps(goal.fallback, target, goal.target_opt,
                              log, progress, min(goal.timeout, 30))
        results.extend(fallback)
        used_fallback = any(row["ok"] for row in fallback)
    tried = [row for row in results if not row.get("skipped")]
    if ran and not used_fallback:
        outcome = "done"
    elif ran or tried:
        outcome = "partial"
    else:
        outcome = "skipped"
    if not results:
        outcome = "skipped"
    note = ""
    if outcome != "done":
        note = goal.note or "connect a target or install the missing tool"
        log(note)
    return {"goal": goal.key, "title": goal.title, "outcome": outcome,
            "target": target, "steps": results, "note": note}

