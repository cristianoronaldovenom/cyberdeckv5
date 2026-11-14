"""Persistence install/remove."""

from __future__ import annotations

from omni.core import console
from omni.core.module import Option
from omni.windows import persist
from omni.windows.modules._base import WindowsModule


class Persist(WindowsModule):
    NAME = "windows.persist"
    DESCRIPTION = "Install or remove autostart (Run key / task / startup folder)"
    OPTIONS = (Option("ACTION", "add|remove|list", "list",
                      choices=("add", "remove", "list")),
               Option("METHOD", "runkey|task|startup", "runkey",
                      choices=("runkey", "task", "startup")),
               Option("NAME", "entry name", "omni"),
               Option("COMMAND", "command or target path", ""),
               Option("MACHINE", "use HKLM (needs admin)", "false",
                      choices=("true", "false")))

    def execute(self) -> object:
        action, method = self.get("ACTION"), self.get("METHOD")
        name, command = self.get("NAME"), self.get("COMMAND")
        if action == "list":
            data = persist.list_persistence()
            for key, rows in data.items():
                console.section(key)
                for row in rows:
                    console.info(str(row))
            return data
        if not command:
            raise ValueError("COMMAND is required for add/remove")
        if action == "add":
            if method == "runkey":
                persist.run_key(name, command, self.get_bool("MACHINE"))
            elif method == "task":
                persist.scheduled_task(name, command).check()
            else:
                console.ok(persist.startup_shortcut(command, name))
            console.ok(f"{method} persistence installed as '{name}'")
            return name
        if method == "runkey":
            ok = persist.remove_run_key(name, self.get_bool("MACHINE"))
        elif method == "task":
            ok = persist.remove_task(name).ok
        else:
            import os
            folder = os.path.expandvars(
                r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
            path = os.path.join(folder, name + ".lnk")
            ok = os.path.isfile(path) and (os.remove(path) or True)
        console.ok("removed" if ok else "nothing to remove")
        return ok
