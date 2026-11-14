"""Preflight: work out what is blocking iPhone control, and fix it.

Remote control has four gates, and a bare ``core-device`` command fails on
whichever one is missing with a message that never says which:

1. the host must be **paired** with the device;
2. **Developer Mode** must be on (user-toggled, but flippable from the host);
3. the **DeveloperDiskImage** must be mounted;
4. an **RSD tunnel** must exist — on iOS 17.4+ ``pymobiledevice3`` opens one
   itself with no root, so this gate is usually already satisfied.

:func:`diagnose` reports each gate, :func:`bring_up` applies fixes in
dependency order, and both are testable without a device.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from omni.core import console

__all__ = ["Gate", "Report", "diagnose", "bring_up", "DEVICE_KEYS"]

#: keys copied out of ``lockdown info`` for display
DEVICE_KEYS = ("DeviceName", "ProductType", "ProductVersion", "BuildVersion",
               "UniqueDeviceID")


@dataclass
class Gate:
    """One prerequisite for control."""

    name: str
    state: str = "unknown"          # ok | blocked | unknown
    detail: str = ""
    fix: str = ""                   # command to run, or "" when manual

    @property
    def ok(self) -> bool:
        return self.state == "ok"

    @property
    def blocked(self) -> bool:
        return self.state == "blocked"


@dataclass
class Report:
    """Diagnosis result: gates plus device identity."""

    gates: list[Gate] = field(default_factory=list)
    device: dict = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        """True when nothing is blocked (unknown counts as passable)."""
        return not any(g.blocked for g in self.gates)

    @property
    def blockers(self) -> list[Gate]:
        return [g for g in self.gates if g.blocked]

    def rows(self) -> list[list[str]]:
        return [[g.name, g.state, g.detail or g.fix] for g in self.gates]


def _dev_mode(client) -> tuple[str, str]:
    """(state, detail) for Developer Mode, via amfi over lockdown."""
    res = client.run("amfi", "developer-mode-status", timeout=60)
    if not res.ok:
        tail = (res.text.strip().splitlines() or [""])[-1]
        return "unknown", tail[:90]
    blob = res.text.lower()
    if "not enabled" in blob or "false" in blob or "disabled" in blob:
        return "blocked", "developer mode is off"
    return "ok", "developer mode is on"


def _ddi(client) -> tuple[str, str]:
    """(state, detail) for the mounted developer image."""
    res = client.run("mounter", "query-developer-mode-status", timeout=60)
    if res.ok:
        blob = res.text.lower()
        if "false" in blob or "not" in blob:
            return "blocked", "developer image not mounted"
        return "ok", "developer image mounted"
    res = client.run("mounter", "list", timeout=60)
    if res.ok and "developer" in res.text.lower():
        return "ok", "developer image present"
    return "unknown", "mount state unclear"


def diagnose(client) -> Report:
    """Check every control prerequisite without changing anything."""
    report = Report()
    try:
        report.device = {k: str(v) for k, v in client.info().items()
                         if k in DEVICE_KEYS}
    except Exception as exc:                    # noqa: BLE001 - report only
        report.device = {"error": str(exc)[:90]}

    if report.device.get("error"):
        report.gates.append(Gate("device visible", "blocked",
                                 report.device["error"],
                                 "unlock the phone, tap Trust, replug"))
        return report
    report.gates.append(Gate("device visible", "ok",
                             report.device.get("DeviceName", "")
                             or report.device.get("ProductType", "paired")))

    paired = client.is_paired()
    report.gates.append(Gate(
        "paired", "ok" if paired else "blocked",
        "host is trusted" if paired else "not paired with this host",
        "" if paired else "omni run ios.pair"))

    state, detail = _dev_mode(client)
    report.gates.append(Gate("developer mode", state, detail,
                             "omni run ios.up FIX=true"))

    state, detail = _ddi(client)
    report.gates.append(Gate("developer image", state, detail,
                             "omni run ios.up FIX=true"))

    if client.rsd or client.tunnel:
        report.gates.append(Gate("rsd tunnel", "ok", "explicitly configured"))
    else:
        report.gates.append(Gate(
            "rsd tunnel", "ok", "auto (no-root userspace tunnel, iOS 17.4+)"))
    return report


def bring_up(client, fix: bool = True) -> Report:
    """Diagnose, then apply fixes in order; returns the final report."""
    report = diagnose(client)
    if report.ready or not fix:
        return report

    for gate in report.blockers:
        if gate.name == "developer mode":
            console.info("enabling developer mode on the device")
            client.run("amfi", "reveal-developer-mode", timeout=60)
            res = client.run("amfi", "enable-developer-mode", timeout=180)
            if not res.ok:
                console.warn("host could not flip it — toggle Settings > "
                             "Privacy & Security > Developer Mode, then reboot")
            else:
                console.warn("developer mode toggled — the device may want a "
                             "reboot; re-run if control still fails")
        elif gate.name == "developer image":
            console.info("mounting the developer image")
            res = client.run("mounter", "auto-mount", timeout=900)
            if not res.ok:
                console.warn(f"auto-mount failed: {res.text.strip()[:120]}")
    return diagnose(client)
