"""Persistence: registry Run keys, scheduled tasks, startup shortcuts."""

from __future__ import annotations

import os
import subprocess

from omni.core import console, proc

__all__ = ["run_key", "remove_run_key", "scheduled_task", "remove_task",
           "startup_shortcut", "list_persistence"]

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def run_key(name: str, command: str, machine: bool = False) -> str:
    """Add an HKCU/HKLM Run entry (survives reboot, no admin needed for HKCU)."""
    import winreg  # noqa: PLC0415

    hive = winreg.HKEY_LOCAL_MACHINE if machine else winreg.HKEY_CURRENT_USER
    with winreg.CreateKey(hive, RUN_KEY) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
    console.ok(f"Run key '{name}' -> {command}")
    return command


def remove_run_key(name: str, machine: bool = False) -> bool:
    import winreg  # noqa: PLC0415

    hive = winreg.HKEY_LOCAL_MACHINE if machine else winreg.HKEY_CURRENT_USER
    try:
        with winreg.OpenKey(hive, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
        return True
    except OSError:
        return False


def scheduled_task(name: str, command: str, at_logon: bool = True) -> proc.Result:
    """Register a scheduled task (logon trigger or on-demand)."""
    trigger = "ONLOGON" if at_logon else "ONCE"
    args = ["schtasks", "/Create", "/F", "/TN", name, "/TR", command, "/SC", trigger]
    if not at_logon:
        args += ["/ST", "00:00"]
    return proc.run(args, timeout=60)


def remove_task(name: str) -> proc.Result:
    return proc.run(["schtasks", "/Delete", "/F", "/TN", name], timeout=60)


def startup_shortcut(target: str, name: str | None = None) -> str:
    """Drop a .lnk into the per-user Startup folder via PowerShell."""
    folder = os.path.expandvars(
        r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
    link = os.path.join(folder, (name or os.path.basename(target)) + ".lnk")
    script = (f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{link}');"
              f"$s.TargetPath='{target}';$s.Save()")
    subprocess.run(["powershell", "-NoProfile", "-Command", script],
                   capture_output=True, timeout=90)
    return link


def list_persistence() -> dict:
    from omni.windows import recon
    return {"run_keys": recon.autoruns(),
            "tasks": proc.run(["schtasks", "/Query", "/FO", "CSV", "/NH"],
                              timeout=90).out.splitlines()[:200]}
