"""Connect to a device with as little authorization as it will tolerate.

The point of this module is to stop guessing. It walks a fixed ladder — is the
device there, does lockdownd answer, does it trust us, can we reach a service —
and names the exact rung it stopped on:

===========  ===============================================================
no-device    nothing on USB and nothing on the LAN
untrusted    lockdownd answers but raises ``NotTrusted``: the phone is
             reachable and controllable the moment trust exists
dialog       pairing is waiting on the on-screen Trust alert
ok           trusted: identity, AFC and the rest answer
===========  ===============================================================

No step here ever asks for the device *passcode* or an iTunes password —
pairing is certificate based, so the only thing trust costs is one tap, and
after the first time nothing at all.

:func:`classify` turns pymobiledevice3's exceptions into those states,
:func:`ladder` runs the checks, and :func:`connect` optionally pushes through
the untrusted rungs by pairing and polling for the tap.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from omni.core import console

__all__ = ["STATES", "PROBES", "Attempt", "Report", "classify", "reach",
           "ladder", "connect", "verdict"]

#: ladder outcome names, most usable first
STATES = ("ok", "dialog", "untrusted", "no-device", "error")

#: capability probes, cheapest first, each (label, argv, needs trust)
PROBES = (
    ("lockdown query", ("lockdown", "get", "com.apple.mobile.lockdown",
                        "HostID"), True),
    ("lockdown info", ("lockdown", "info"), True),
    ("afc ls /var/mobile/Media", ("afc", "ls", "/"), True),
    ("wifi sync state", ("lockdown", "wifi-connections"), True),
)

#: the reachability rung, which is not itself a service
VISIBLE_STEP = "device visible"

#: substrings that mean "reachable but not trusted", lower-case
_UNTRUSTED = ("nottrusted", "not trusted", "pairing required", "not paired")
_DIALOG = ("pairingdialogresponsepending", "pairing dialog",
           "waiting for the user")
_MISSING = ("no device", "unable to find", "device not found",
            "nodeviceconnected", "no devices")
_LOCKED = ("invalidhostid", "userdenied", "denied pairing")


def classify(text: str) -> str:
    """Map pymobiledevice3 output onto a ladder state."""
    blob = (text or "").lower()
    for needle in _MISSING:
        if needle in blob:
            return "no-device"
    for needle in _UNTRUSTED:
        if needle in blob:
            return "untrusted"
    for needle in _DIALOG:
        if needle in blob:
            return "dialog"
    return "error"


@dataclass
class Attempt:
    """One rung of the ladder."""

    step: str
    state: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.state == "ok"

    def row(self) -> list[str]:
        return [self.step, self.state, self.detail[:120]]


@dataclass
class Report:
    """Everything the ladder learned, in order."""

    attempts: list[Attempt] = field(default_factory=list)

    def add(self, step: str, state: str, detail: str = "") -> Attempt:
        attempt = Attempt(step, state, detail)
        self.attempts.append(attempt)
        return attempt

    @property
    def visible(self) -> bool:
        """The device was at least seen on some transport."""
        return any(a.step == VISIBLE_STEP and a.ok for a in self.attempts)

    @property
    def top(self) -> Attempt | None:
        """The best *service* rung, ignoring bare reachability."""
        service = [a for a in self.attempts if a.step != VISIBLE_STEP]
        for state in STATES:
            for attempt in service:
                if attempt.state == state:
                    return attempt
        return None

    @property
    def state(self) -> str:
        best = self.top
        if best is not None:
            return best.state
        return "untrusted" if self.visible else "no-device"

    @property
    def connected(self) -> bool:
        """A service answered — mere visibility does not count."""
        return self.state == "ok"

    def rows(self) -> list[list[str]]:
        return [a.row() for a in self.attempts]


def reach(client) -> list[tuple[str, str]]:
    """Every (transport, udid) the host can see, USB first."""
    found: list[tuple[str, str]] = []
    try:
        for device in client.devices():
            found.append(("USB", device.udid))
    except Exception:                            # noqa: BLE001 - keep going
        pass
    try:
        out = client.raw("usbmux", "list", "--network", "--simple").out
    except Exception:                            # noqa: BLE001
        out = ""
    for line in out.splitlines():
        udid = line.strip()
        if udid and all(udid != seen for _, seen in found):
            found.append(("Network", udid))
    return found


def ladder(client) -> Report:
    """Walk the reachability ladder without changing anything."""
    report = Report()
    transports = reach(client)
    if not transports:
        report.add(VISIBLE_STEP, "no-device", "nothing on USB or the LAN")
        return report
    for transport, udid in transports:
        report.add(VISIBLE_STEP, "ok", f"{transport} {udid}")

    for label, argv, _needs_trust in PROBES:
        res = client.run(*argv, timeout=60)
        if res.ok:
            report.add(label, "ok", (res.out or "").strip()[:80])
            continue
        state = classify(res.text)
        report.add(label, state, (res.text or "").strip()[:120])
        if state == "untrusted":
            break            # every other probe needs trust as well
    return report


def verdict(report: Report) -> str:
    """One-line human verdict from the ladder state."""
    return {
        "ok": "connected — trusted host, no prompt needed",
        "dialog": "waiting on the Trust alert on the phone (one tap)",
        "untrusted": "reachable but untrusted — one tap, or a stolen record",
        "no-device": "no route — nothing visible on USB or the LAN",
        "error": "reachable but the device refused us",
    }.get(report.state, report.state)


def connect(client, promptless: bool = False, wait: int = 25,
            pause: float = 1.0, clock=time.monotonic) -> Report:
    """Reach the device, and when asked, push through the untrusted rung.

    ``promptless`` pairs immediately and then polls, so a script does not have
    to know whether the user tapped yet. Pairing needs no passcode, and a
    supervised device needs no tap at all.
    """
    report = ladder(client)
    if report.connected or report.state not in ("untrusted", "dialog"):
        return report
    if not promptless:
        console.warn(verdict(report))
        console.info("run with PROMPTLESS=true to pair and wait for the tap")
        return report

    console.info("asking lockdownd to pair (no passcode involved)")
    res = client.run("lockdown", "pair", timeout=120)
    report.add("pair request", "dialog" if res.ok else classify(res.text),
               (res.text or "").strip()[:120] or "dialog shown")

    deadline = clock() + max(1, wait)
    while clock() < deadline:
        probe = client.run("lockdown", "info", timeout=60)
        if probe.ok:
            report.add("pair-verify", "ok", "device answered")
            return report
        time.sleep(pause)
    report.add("pair-verify", classify(res.text),
               "no answer before the wait elapsed")
    return report
