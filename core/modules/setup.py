"""Install the external tools a trade needs, with the host package manager.

``omni setup`` explains each tool, shows the exact command and runs the ones
that have a package (winget / brew / apt, or pip for Python-side tools). It is
never required for the toolkit to start. The default ``recommended`` set is a
short list that unlocks most modules in one pass; ``all`` is the long tail.
"""

from __future__ import annotations

from omni.core import console, setup
from omni.core.module import Module, Option

__all__ = ["Setup"]


class Setup(Module):
    NAME = "core.setup"
    DESCRIPTION = "Install missing external tools (winget / brew / apt / pip)"
    FAMILY = "core"
    OPTIONS = (Option("PRESET", "recommended|all|custom", "recommended",
                      choices=("recommended", "all", "custom")),
               Option("TOOLS", "custom comma list (overrides PRESET)"),
               Option("DRY", "show the commands without running them", "false",
                      choices=("true", "false")))

    def execute(self) -> dict:
        requested = [part.strip() for part in
                     self.get("TOOLS").replace(",", " ").split() if part.strip()]
        if requested:
            tools = setup.missing(requested)
        elif self.get("PRESET") == "all":
            tools = setup.missing(sorted(setup.PLAN))
        else:
            tools = setup.recommended()
        if not tools:
            console.ok("nothing to install — the useful tools are present")
            return {"missing": [], "installed": []}
        console.info(f"{len(tools)} tool(s) missing on this host:")
        for line in setup.explain(tools):
            console.info(line)
        plan = setup.plan_for(tools)
        if not plan:
            console.warn("no automatic package for these here — install them "
                         "manually, then run `omni doctor`")
            return {"missing": tools, "installed": []}
        for tool, argv in plan:
            print(f"   {console.C.D}{tool}: {' '.join(argv)}{console.C.X}")
        if self.get_bool("DRY", False):
            return {"missing": tools, "installed": [], "dry": True}
        result = setup.install([tool for tool, argv in plan if argv])
        left = setup.missing(tools)
        if left:
            console.warn("still missing: " + ", ".join(left))
        else:
            console.ok("the requested tools are available now")
        return {"missing": left, **result}
