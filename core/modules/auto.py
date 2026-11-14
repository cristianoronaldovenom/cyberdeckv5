"""One-click audit module (``omni auto`` / the menu's first entry)."""

from __future__ import annotations

from omni.core import auto
from omni.core.module import Module, Option

__all__ = ["Auto"]


class Auto(Module):
    NAME = "core.auto"
    DESCRIPTION = "One-click audit: run every safe local check, write a report"
    FAMILY = "core"
    OPTIONS = (Option("PROFILE", "safe|full (full adds readiness + network walk)",
                      "safe", choices=("safe", "full")),
               Option("OUT", "report directory (blank = timestamped loot dir)"),
               Option("SAVE", "write report.json + report.md", "true",
                      choices=("true", "false")),
               Option("OPEN", "open the report folder when done", "true",
                      choices=("true", "false")))

    def execute(self) -> dict:
        return auto.run(profile=self.get("PROFILE") or "safe",
                        outdir=self.get("OUT"),
                        save=self.get_bool("SAVE", True),
                        open_when_done=self.get_bool("OPEN", True))
