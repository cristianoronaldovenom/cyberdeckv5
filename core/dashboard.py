"""Dashboard model: a Home tab of one-click actions plus every trade.

The view is deliberately dumb — tab state, filtering, selection, action
resolution and command building live here and are testable without a terminal.

Home is a real tab whose rows are *actions*, so "click a button" is literally
selecting the row and pressing Enter: one-click audit, full audit, this box,
tool readiness, install missing tools, open the last report. Every other tab
is one trade, annotated with the tools that are missing so a dead end is
visible before it is run.
"""

from __future__ import annotations

import os
import shlex

from omni.core import proc

__all__ = ["TABS", "FAMILY_TABS", "HOME_ACTIONS", "ACTION_TARGETS", "Row",
           "Model", "parse_overrides", "latest_report"]

#: (family, short title, hint) — order is the tab order. Home first.
FAMILY_TABS = (
    ("wifi", "WiFi", "monitor adapter, root"),
    ("rf", "RF", "CC1101 on SPI"),
    ("radio", "Radio", "SDR / RFID / BT / IR"),
    ("car", "Car", "OEM keystore"),
    ("brute", "Brute", "masks, wordlists, hashes"),
    ("android", "Droid", "adb over USB"),
    ("ios", "iOS", "Developer Mode + tunnel"),
    ("pentest", "Net", "scan, recon, LAN"),
    ("mobile", "Apps", "Frida / jadx"),
    ("windows", "Win", "Windows host"),
    ("news", "News", "Hacker News"),
    ("flip", "Flip", "Flipper files"),
    ("core", "Core", "doctor, setup, plan"),
)

#: rows shown on the Home tab: (action name, label, description)
HOME_ACTIONS = (
    ("action.auto", "ONE-CLICK AUDIT", "safe checks, no questions, opens report"),
    ("action.full", "FULL AUDIT", "one-click plus readiness and network walk"),
    ("action.devices", "THIS BOX", "adapters, phones, radios, tools, loot"),
    ("action.doctor", "TOOL READINESS", "what is installed, per trade"),
    ("action.install", "INSTALL MISSING TOOLS", "winget / brew / apt / pip"),
    ("action.report", "OPEN LAST REPORT", "the newest one-click audit"),
    ("action.setup", "SETTINGS", "show or change config values"),
)

#: action row -> (module name, fixed options)
ACTION_TARGETS = {
    "action.auto": ("core.auto", {"PROFILE": "safe", "OPEN": "true"}),
    "action.full": ("core.auto", {"PROFILE": "full", "OPEN": "true"}),
    "action.devices": ("core.devices", {}),
    "action.doctor": ("core.doctor", {}),
    "action.install": ("core.setup", {}),
    "action.setup": ("core.config", {}),
}

TABS = (("home", "Home", "one-click actions"),) + FAMILY_TABS


class Row:
    """One selectable module or action in a tab."""

    __slots__ = ("name", "description", "missing")

    def __init__(self, name: str, description: str, missing: list[str]):
        self.name = name
        self.description = description
        self.missing = missing

    @property
    def ready(self) -> bool:
        return not self.missing

    @property
    def mark(self) -> str:
        return "+" if self.ready else "!"

    @property
    def action(self) -> bool:
        return self.name.startswith("action.")


def parse_overrides(pairs: list[str]) -> dict[str, str]:
    """Turn ``["SSID=x", "COUNT=3"]`` into a dict, rejecting junk."""
    out: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"override {pair!r} is not OPT=value")
        key, _, value = pair.partition("=")
        key = key.strip().upper()
        if not key:
            raise ValueError(f"override {pair!r} has no option name")
        out[key] = value
    return out


def latest_report() -> str:
    """Newest one-click audit directory, or "" when none exists."""
    from omni.core import config
    base = os.path.expanduser(str(config.get_value("output_dir",
                                                   "~/omni-loot")))
    root = os.path.join(base, "auto")
    try:
        dirs = [os.path.join(root, name) for name in os.listdir(root)]
    except OSError:
        return ""
    dirs = [p for p in dirs if os.path.isdir(p)]
    return max(dirs, key=os.path.getmtime) if dirs else ""


class Model:
    """Tab/selection state for one dashboard session."""

    def __init__(self, modules: dict[str, list[tuple[str, str]]],
                 have_tool=proc.has):
        self.modules = modules
        self.have_tool = have_tool
        self.tab = 0
        self.cursor: dict[str, int] = {fam: 0 for fam, _t, _h in TABS}
        self.search = ""
        self.values: list[str] = []      # raw OPT=value typed by the user
        self.output: list[str] = []
        self.status = "ready — `a` one-click, arrows move, Enter runs"
        self._needs: dict[str, tuple[str, ...]] = {}

    # -- tabs ---------------------------------------------------------
    def next_tab(self) -> str:
        self.tab = (self.tab + 1) % len(TABS)
        return self.family

    def prev_tab(self) -> str:
        self.tab = (self.tab - 1) % len(TABS)
        return self.family

    @property
    def family(self) -> str:
        return TABS[self.tab][0]

    @property
    def title(self) -> str:
        return TABS[self.tab][1]

    @property
    def hint(self) -> str:
        return TABS[self.tab][2]

    # -- rows ---------------------------------------------------------
    def rows_for(self, family: str) -> list[Row]:
        """Rows of one tab, filtered by the search string."""
        if family == "home":
            return [Row(name, description, [])
                    for name, _label, description in HOME_ACTIONS]
        needle = self.search.lower()
        rows = []
        for name, description in self.modules.get(family, []):
            if needle and needle not in name.lower() \
                    and needle not in description.lower():
                continue
            needs = self._needs.get(name, ())
            missing = [tool for tool in needs if not self.have_tool(tool)]
            rows.append(Row(name, description, missing))
        return rows

    def rows(self) -> list[Row]:
        """Rows in the active tab, filtered by the search string."""
        return self.rows_for(self.family)

    def set_needs(self, needs: dict[str, tuple[str, ...]]) -> None:
        self._needs = needs

    @property
    def selected(self) -> Row | None:
        rows = self.rows()
        if not rows:
            return None
        index = min(self.cursor.get(self.family, 0), len(rows) - 1)
        return rows[index]

    def move(self, delta: int) -> int:
        rows = self.rows()
        if not rows:
            return 0
        index = (self.cursor.get(self.family, 0) + delta) % len(rows)
        self.cursor[self.family] = index
        return index

    def set_search(self, text: str) -> None:
        self.search = text
        self.cursor[self.family] = 0

    # -- execution ----------------------------------------------------
    def target(self) -> tuple[str, dict[str, str]]:
        """(module, options) for the selection, resolving Home actions."""
        row = self.selected
        if row is None:
            raise ValueError("nothing selected")
        if row.action:
            if row.name == "action.report":
                return "action.report", {}
            module, options = ACTION_TARGETS[row.name]
            return module, dict(options)
        return row.name, parse_overrides(self.values)

    def command(self) -> list[str]:
        """argv for the selection with its overrides applied."""
        module, options = self.target()
        return ["run", module] + [f"{k}={v}" for k, v in options.items()]

    def save_overrides(self, store) -> None:
        """Remember this module's overrides for the next session."""
        row = self.selected
        if store is None or row is None or row.action or not self.values:
            return
        store.set_value(f"dash.last.{row.name}", " ".join(self.values))

    def load_overrides(self, store) -> None:
        """Restore the overrides last used with the selected module."""
        if store is None:
            return
        row = self.selected
        if row is None or row.action:
            return
        raw = str(store.get_value(f"dash.last.{row.name}", "") or "")
        if raw and not self.values:
            self.values = raw.split()

    def command_text(self) -> str:
        return "omni " + " ".join(shlex.quote(part) for part in self.command())

    def clear_values(self) -> None:
        self.values = []

    def log(self, text: str, limit: int = 500) -> None:
        for line in text.splitlines():
            self.output.append(line)
        del self.output[:-limit]

    @property
    def ready_count(self) -> int:
        return sum(1 for row in self.rows() if row.ready)

    def missing_of_selection(self) -> list[str]:
        row = self.selected
        return list(row.missing) if row else []
