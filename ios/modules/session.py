"""Bring-up and the interactive remote console.

* ``ios.status`` — is this phone controllable right now, and if not, why.
* ``ios.up`` — same check, then fixes it (enable Developer Mode, mount the
  developer image) so a plain ``omni run ios.tap`` starts working.
* ``ios.remote`` — a persistent prompt; type at the phone instead of paying a
  process per keystroke.
"""

from __future__ import annotations

from omni.core import console
from omni.core.module import Option
from omni.ios import preflight
from omni.ios.modules._base import IosModule
from omni.ios.remote import HELP, dispatch

__all__ = ["Status", "Up", "Remote"]


class Status(IosModule):
    NAME = "ios.status"
    DESCRIPTION = "Report whether this iPhone can be remote controlled, and why"
    OPTIONS = (Option("UDID", "target UDID"),)

    def execute(self) -> dict:
        report = preflight.diagnose(self.client())
        for key, value in report.device.items():
            console.kv([(key, value)])
        console.table(["gate", "state", "detail"], report.rows())
        if report.ready:
            console.ok("controllable — try: omni run ios.remote")
        else:
            console.warn(f"{len(report.blockers)} blocker(s); fix with: "
                         "omni run ios.up")
        return {"ready": report.ready,
                "blockers": [g.name for g in report.blockers],
                "device": report.device}


class Up(IosModule):
    NAME = "ios.up"
    DESCRIPTION = "Make the iPhone controllable (enable Developer Mode, mount image)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("FIX", "apply the fixes, not just report", "true",
                      choices=("true", "false")))

    def execute(self) -> dict:
        client = self.client()
        console.info("checking control prerequisites")
        report = preflight.bring_up(client, fix=self.get_bool("FIX", True))
        console.table(["gate", "state", "detail"], report.rows())
        if report.ready:
            console.ok("ready — try: omni run ios.remote  (or ios.tap/ios.type)")
        else:
            console.warn("still blocked by: "
                         + ", ".join(g.name for g in report.blockers))
        return {"ready": report.ready,
                "blockers": [g.name for g in report.blockers]}


class Remote(IosModule):
    NAME = "ios.remote"
    DESCRIPTION = "Interactive remote control console (tap/type/key/shot/...)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("SCRIPT", "commands separated by ';' for non-interactive use"),
               Option("CHECK", "run a preflight pass first", "true",
                      choices=("true", "false")))

    def execute(self) -> dict:
        client = self.client()
        if self.get_bool("CHECK", True):
            report = preflight.diagnose(client)
            if not report.ready:
                console.warn("blocked: "
                             + ", ".join(g.name for g in report.blockers)
                             + " — run ios.up to fix")
            else:
                console.ok(f"connected to {report.device.get('DeviceName', 'device')}")

        script = self.get("SCRIPT")
        if script:
            return self._run_script(client, script)
        return self._run_interactive(client)

    @staticmethod
    def _run_script(client, script: str) -> dict:
        done = 0
        for line in script.split(";"):
            line = line.strip()
            if not line:
                continue
            try:
                out, quit_now = dispatch(client, line)
            except Exception as exc:            # noqa: BLE001 - keep going
                console.err(f"{line}: {exc}")
                continue
            if out:
                console.info(out)
            done += 1
            if quit_now:
                break
        return {"commands": done, "interactive": False}

    @staticmethod
    def _run_interactive(client) -> dict:
        console.info("type 'help' for commands, 'quit' to leave")
        done = 0
        while True:
            try:
                line = input("iphone> ")
            except (EOFError, KeyboardInterrupt):
                console.info("")
                break
            try:
                out, quit_now = dispatch(client, line)
            except Exception as exc:            # noqa: BLE001 - keep the loop
                console.err(str(exc))
                continue
            if out:
                console.info(out)
            done += 1
            if quit_now:
                break
        return {"commands": done, "interactive": True}
