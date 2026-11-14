"""One-click audit: run the safe local checks with zero questions.

The menu's first entry and ``omni auto`` land here. Every step is an ordinary
module, every step is optional, and no step can stop the run: a missing tool or
device is recorded as a skipped line in the report and the next step starts.
The output is a folder with ``report.json`` + ``report.md`` so there is always
something to look at afterwards.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback

from omni.core import config, console, platform as host, proc
from omni.core.module import registry

__all__ = ["Plan", "build_plan", "run", "summary"]

#: (label, module, options) — order is the reading order of the report
_COMMON = (
    ("this box", "core.devices", {}),
    ("radio hardware", "radio.hardware", {}),
    ("nearby Wi-Fi", "wifi.scan", {}),
    ("Wi-Fi passwords on this PC", "wifi.passwords", {}),
    ("hosts on this network", "pentest.hostscan", {"SWEEP": "true"}),
)
_WINDOWS = (
    ("wireless interfaces", "wifi.adapters", {}),
    ("Windows host triage", "windows.recon", {"WHAT": "users"}),
    ("administrators", "windows.recon", {"WHAT": "admins"}),
    ("antivirus", "windows.recon", {"WHAT": "av"}),
    ("browser logins", "windows.logins", {}),
    ("browser cookies", "windows.cookies", {}),
    ("browser history", "windows.history", {"LIMIT": "100"}),
    ("autoruns", "windows.recon", {"WHAT": "autoruns"}),
    ("saved Wi-Fi profiles", "windows.wifi", {}),
)
_LINUX = (
    ("wireless interfaces", "wifi.adapters", {}),
    ("android devices", "android.devices", {}),
)
_MAC = (
    ("wireless interfaces", "wifi.adapters", {}),
    ("iPhone / iPad", "ios.devices", {}),
)


class Plan(list):
    """A list of steps with a human title."""

    def __init__(self, title: str, steps):
        super().__init__(steps)
        self.title = title


def build_plan(profile: str = "safe") -> Plan:
    steps = list(_COMMON)
    if host.is_windows():
        steps += list(_WINDOWS)
    elif host.is_macos():
        steps += list(_MAC)
    else:
        steps += list(_LINUX)
    if profile == "full":
        steps += [("tool readiness", "core.doctor", {}),
                  ("hash masks", "brute.masks", {}),
                  ("network walk", "pentest.reach", {"RUN": "false"})]
    return Plan("one-click audit", steps)


def _jsonable(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in list(value.items())[:200]}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in list(value)[:500]]
    return str(value)


def summary(value) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}={len(v) if isinstance(v, (list, dict)) else v}"
                         for k, v in list(value.items())[:4]) or "ok"
    if isinstance(value, list):
        return f"{len(value)} row(s)"
    return str(value)[:80]


def run(profile: str = "safe", outdir: str = "", save: bool = True,
        open_when_done: bool = True, progress=None) -> dict:
    """Run the plan; never raises, always returns a report dict."""
    plan = build_plan(profile)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    outdir = os.path.expanduser(outdir or os.path.join(
        config.output_dir("auto"), stamp))
    if save:
        os.makedirs(outdir, exist_ok=True)
    console.info(f"one-click audit — {len(plan)} checks, profile {profile}")
    if not proc.has("nmap"):
        console.info("no nmap: the host scan uses its built-in connect scan")

    results = []
    for index, (label, name, options) in enumerate(plan, 1):
        if progress:
            progress(index, len(plan), label)
        print(f"  [{index:>2}/{len(plan)}] {label} …", flush=True)
        started = time.time()
        cls = registry.get(name)
        if cls is None:
            results.append({"label": label, "module": name, "ok": False,
                            "skipped": True, "error": "module unavailable"})
            print("        skipped: module unavailable")
            continue
        try:
            mod = cls(**options)
            if mod.missing():
                results.append({"label": label, "module": name, "ok": False,
                                "skipped": True,
                                "error": "needs " + ", ".join(mod.missing())})
                print("        skipped: needs options")
                continue
            value = mod.run()
            results.append({"label": label, "module": name, "ok": True,
                            "seconds": round(time.time() - started, 2),
                            "summary": summary(value)})
            print(f"        ok: {summary(value)}")
        except Exception as exc:  # noqa: BLE001 - a step may not stop the run
            from omni.core.proc import ToolMissing
            kind = "missing tool" if isinstance(exc, ToolMissing) else \
                type(exc).__name__
            results.append({"label": label, "module": name, "ok": False,
                            "skipped": isinstance(exc, ToolMissing),
                            "error": str(exc)[:500]})
            print(f"        skipped: {kind}: {str(exc)[:120]}"
                  if isinstance(exc, ToolMissing)
                  else f"        failed: {kind}: {str(exc)[:120]}")
            if os.environ.get("OMNI_DEBUG"):
                traceback.print_exc()

    ok = sum(1 for row in results if row["ok"])
    report = {"platform": sys.platform, "profile": profile,
              "started": stamp, "done": ok, "total": len(results),
              "results": results, "dir": outdir}
    if save:
        json_path = os.path.join(outdir, "report.json")
        md_path = os.path.join(outdir, "report.md")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        write_markdown(md_path, report)
        report["json"] = json_path
        report["markdown"] = md_path
        console.ok(f"{ok}/{len(results)} checks produced data")
        console.info(f"report: {md_path}")
    if open_when_done and sys.stdout.isatty():
        reveal(outdir)
    return report


def write_markdown(path: str, report: dict) -> str:
    lines = [f"# OMNI one-click audit — {report['started']}", "",
             f"Platform: {report['platform']} · profile {report['profile']} · "
             f"{report['done']}/{report['total']} checks returned data", ""]
    for row in report["results"]:
        mark = "PASS" if row["ok"] else ("SKIP" if row.get("skipped") else "FAIL")
        lines.append(f"## [{mark}] {row['label']}")
        lines.append(f"`{row['module']}`")
        if row.get("summary"):
            lines.append(f"Result: {row['summary']}")
        if row.get("error"):
            lines.append(f"{row['error']}")
        lines.append("")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    return path


def reveal(path: str) -> None:
    """Open the report folder in the desktop file manager, best effort."""
    try:
        if host.is_windows():
            proc.run(["explorer", os.path.normpath(path)], timeout=10)
        elif host.is_macos():
            proc.run(["open", path], timeout=10)
        elif proc.has("xdg-open"):
            proc.run(["xdg-open", path], timeout=10)
    except Exception:  # noqa: BLE001 - cosmetic
        pass
