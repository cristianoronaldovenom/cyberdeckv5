"""Host recon: users, groups, services, scheduled tasks, AV, SMB shares."""

from __future__ import annotations

from omni.core import proc

__all__ = ["systeminfo", "users", "administrators", "services", "tasks",
           "antivirus", "shares", "installed_software", "defender_status",
           "autoruns"]


def _run(*argv: str, timeout: int = 120) -> str:
    return proc.run(list(argv), timeout=timeout).text


def systeminfo() -> str:
    return _run("systeminfo")


def users() -> list[str]:
    out = _run("net", "user")
    return [ln.strip() for ln in out.splitlines()[4:] if ln.strip()
            and not ln.startswith("The command")]


def administrators() -> list[str]:
    out = _run("net", "localgroup", "administrators")
    return [ln.strip() for ln in out.splitlines()[6:] if ln.strip()
            and not ln.startswith("The command")]


def services() -> list[str]:
    return [ln.strip() for ln in _run("sc", "query", "type=", "service").splitlines()
            if "SERVICE_NAME" in ln]


def tasks() -> list[str]:
    return [ln.strip() for ln in _run("schtasks", "/query", "/fo", "list").splitlines()
            if ln.startswith("TaskName")]


def antivirus() -> list[str]:
    out = _run("wmic", "/namespace:\\\\root\\SecurityCenter2", "path",
               "AntiVirusProduct", "get", "displayName")
    return [ln.strip() for ln in out.splitlines()[1:] if ln.strip()]


def defender_status() -> str:
    return _run("powershell", "-NoProfile", "-Command",
                "Get-MpComputerStatus | Format-List")


def shares() -> list[str]:
    return [ln.strip() for ln in _run("net", "share").splitlines()[4:] if ln.strip()]


def installed_software() -> list[str]:
    out = _run("powershell", "-NoProfile", "-Command",
               "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion"
               "\\Uninstall\\* | Select-Object DisplayName, DisplayVersion | "
               "Format-Table -AutoSize", timeout=180)
    return [ln.rstrip() for ln in out.splitlines() if ln.strip()]


def autoruns() -> list[str]:
    """Run/RunOnce registry values across HKCU, HKLM and the WOW64 view."""
    keys = (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    )
    rows: list[str] = []
    for key in keys:
        for line in _run("reg", "query", key, timeout=60).splitlines():
            line = line.strip()
            if "REG_" in line:
                rows.append(f"{key}  ::  {line}")
    return rows
