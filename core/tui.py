"""Dashboard: a tabbed front end over the module registry.

The first tab is **Home** and its rows are buttons: one-click audit, full
audit, this box, tool readiness, install missing tools, open the last report.
Select a row and press Enter; nothing has to be typed.

Every other tab is one trade with a readiness count (`ready/total`), so an
empty capability is visible before it is run. Keys: TAB/shift-TAB switch
trade, up/down move, Enter or `r` run, `a` one-click, `f` full audit,
`d` devices, `t` doctor, `i` install missing, `o` options, `/` filter,
`PgUp/PgDn` scroll output, `?` help, `q` quit.

The curses view needs a real terminal. Without one (no windows-curses, output
piped, a tiny terminal) the same state is served by a plain text dashboard,
so `omni dash` never ends in an error.
"""

from __future__ import annotations

import os
import queue
import sys
import threading

from omni.core import console
from omni.core.dashboard import (ACTION_TARGETS, HOME_ACTIONS, TABS, Model,
                                 latest_report)
from omni.core.module import registry

__all__ = ["run_dashboard", "run_plain_dashboard", "collect_modules",
           "collect_needs", "Dashboard", "HELP", "ACTION_KEYS"]


def _curses():
    """Return the curses module, or None where it is unavailable."""
    try:
        import curses
    except ImportError:
        return None
    return curses


HELP = (
    ("TAB / shift-TAB", "next / previous trade"),
    ("up / down", "move selection"),
    ("Enter or r", "run the selected module / Home action"),
    ("a / f", "one-click audit / full audit"),
    ("d / t / i", "this box / tool readiness / install missing tools"),
    ("o", "add an OPT=value override (e.g. SSID=Office)"),
    ("c", "clear overrides"),
    ("/", "filter the module list"),
    ("PgUp / PgDn", "scroll the output"),
    ("?", "this help"),
    ("q", "quit"),
)

#: global keys that run a Home action without leaving the current tab
ACTION_KEYS = {
    ord("a"): "action.auto",
    ord("f"): "action.full",
    ord("d"): "action.devices",
    ord("t"): "action.doctor",
    ord("i"): "action.install",
}


def collect_modules() -> dict[str, list[tuple[str, str]]]:
    """family -> [(module name, description)] from the live registry."""
    found: dict[str, list[tuple[str, str]]] = {
        "home": [(name, description)
                 for name, _label, description in HOME_ACTIONS]}
    for family, _title, _hint in TABS:
        if family == "home":
            continue
        found[family] = [(cls.NAME, cls.DESCRIPTION)
                         for cls in registry.all(family)]
    return found


def collect_needs() -> dict[str, tuple[str, ...]]:
    """module name -> external tools it declares."""
    needs: dict[str, tuple[str, ...]] = {}
    for family, _title, _hint in TABS:
        if family == "home":
            continue
        for cls in registry.all(family):
            needs[cls.NAME] = tuple(getattr(cls, "NEEDS", ()) or ())
    return needs


class Dashboard:
    """The curses application (curses is imported lazily per instance)."""

    def __init__(self, screen, model: Model, store=None):
        self.curses = _curses()
        self.screen = screen
        self.model = model
        self.store = store
        self.queue: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.show_help = False
        self.scroll = 0

    def _attr(self, name: str, default: int = 0) -> int:
        return getattr(self.curses, name, default) if self.curses else default

    # -- painting -----------------------------------------------------
    def _labels(self) -> list[str]:
        counts = self._counts()
        labels = []
        for family, title, _hint in TABS:
            total, ready = counts.get(family, (0, 0))
            if family == "home":
                labels.append("Home")
            elif total:
                labels.append(f"{title} {ready}/{total}")
            else:
                labels.append(title)
        return labels

    def _tab_bar(self, width: int) -> str:
        """Active tab is always visible; the strip scrolls around it."""
        labels = self._labels()
        active = self.model.tab
        left = right = 0
        chunks = [f"[{labels[active]}]"]
        used = len(chunks[0])
        while True:
            grew = False
            if active + right + 1 < len(labels):
                candidate = f" {labels[active + right + 1]} "
                if used + len(candidate) + 4 <= width - 4:
                    chunks.append(candidate)
                    used += len(candidate)
                    right += 1
                    grew = True
            if active - left - 1 >= 0:
                candidate = f" {labels[active - left - 1]} "
                if used + len(candidate) + 4 <= width - 4:
                    chunks.insert(0, candidate)
                    used += len(candidate)
                    left += 1
                    grew = True
            if not grew:
                break
        prefix = "‹ " if left else ""
        suffix = " ›" if active + right + 1 < len(labels) else ""
        return (prefix + "".join(chunks) + suffix)[:width]

    def _counts(self) -> dict[str, tuple[int, int]]:
        counts: dict[str, tuple[int, int]] = {}
        for family, _title, _hint in TABS:
            rows = self.model.rows_for(family)
            counts[family] = (len(rows),
                              sum(1 for row in rows if row.ready))
        return counts

    def draw(self) -> None:
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        try:
            self.screen.addnstr(0, 0, self._tab_bar(width).ljust(width), width,
                                self._attr('A_REVERSE'))
            rows = self.model.rows()
            head = (f" {self.model.title} — {self.model.hint}  "
                    f"({self.model.ready_count}/{len(rows)} ready)")
            self.screen.addnstr(1, 0, head.ljust(width), width,
                                self._attr('A_BOLD'))

            index = min(self.model.cursor.get(self.model.family, 0),
                        max(0, len(rows) - 1))
            list_h = max(3, height - 13)
            start = max(0, index - list_h + 2)
            for offset, row in enumerate(rows[start:start + list_h]):
                attr = self._attr('A_REVERSE') if row is self.model.selected else 0
                if row.action:
                    attr |= self._attr('A_BOLD')
                if not row.ready:
                    attr |= self._attr('A_DIM')
                if row.action:
                    label = f" {row.mark} ▶ {row.description}"
                else:
                    label = f" {row.mark} {row.name:<26}{row.description}"
                self.screen.addnstr(2 + offset, 0, label.ljust(width), width,
                                    attr)

            footer_y = max(2, height - 10)
            missing = self.model.missing_of_selection()
            state = f"tool(s): {', '.join(missing)}" if missing else "ready to run"
            self.screen.addnstr(footer_y, 0,
                                f" {state}"[:width].ljust(width),
                                width, self._attr('A_BOLD'))
            self.screen.addnstr(footer_y + 1, 0,
                                f" cmd: {self.model.command_text()}"[:width],
                                width)

            if self.show_help:
                for offset, (key, what) in enumerate(HELP):
                    self.screen.addnstr(footer_y + 2 + offset, 2,
                                        f"{key:<16}{what}"[:width], width)
            else:
                lines = self.model.output
                if self.scroll:
                    end = max(0, len(lines) - self.scroll)
                    shown = lines[max(0, end - 4):end]
                else:
                    shown = lines[-4:]
                for offset, line in enumerate(shown):
                    self.screen.addnstr(footer_y + 2 + offset, 1,
                                        line[:width - 1], width - 1)

            bar = (" [a] one-click  [f] full  [d] devices  [t] doctor  "
                   "[i] install  [r] run  [o] opts  [?] help  [q] quit")
            self.screen.addnstr(height - 2, 0, bar[:width].ljust(width),
                                width, self._attr('A_REVERSE'))
            self.screen.addnstr(height - 1, 0,
                                f" {self.model.status} "[:width].ljust(width),
                                width, self._attr('A_REVERSE'))
            self.screen.refresh()
        except self.curses.error:
            pass                      # a too-small terminal is not fatal

    # -- actions ------------------------------------------------------
    def ask(self, prompt: str) -> str:
        height, width = self.screen.getmaxyx()
        self.curses.echo()
        try:
            self.screen.addnstr(height - 1, 0, f" {prompt} ".ljust(width), width,
                                self._attr('A_REVERSE'))
            self.screen.refresh()
            raw = self.screen.getstr(height - 1, len(prompt) + 2,
                                     max(8, width - len(prompt) - 3))
            return raw.decode("utf-8", "replace").strip()
        finally:
            self.curses.noecho()
            self.screen.move(height - 1, 0)

    def _busy(self) -> bool:
        return bool(self.worker and self.worker.is_alive())

    def start_run(self, action: str | None = None) -> None:
        if self._busy():
            self.model.status = "still running — wait"
            return
        if action:
            if action == "action.report":
                self.reveal_report()
                return
            module, options = ACTION_TARGETS[action]
        else:
            try:
                module, options = self.model.target()
            except ValueError as exc:
                self.model.status = str(exc)
                return
            if module == "action.report":
                self.reveal_report()
                return
        values = dict(options)
        if not action:
            values.update({part.split("=", 1)[0]: part.split("=", 1)[1]
                           for part in self.model.values if "=" in part})
        self.model.status = f"running {module} …"
        self.model.log(f"$ omni run {module}")

        def target() -> None:
            try:
                mod = registry.build(module, **values)
                mod.validate()
                self.queue.put(("done", mod.run()))
            except Exception as exc:        # noqa: BLE001 - surface, never crash
                self.queue.put(("fail", exc))

        self.worker = threading.Thread(target=target, daemon=True)
        self.worker.start()

    def reveal_report(self) -> None:
        path = latest_report()
        if not path:
            self.model.status = "no report yet — run the one-click audit"
            return
        from omni.core import auto
        auto.reveal(path)
        self.model.log(f"report: {path}")
        self.model.status = "opened the newest report"

    def drain(self) -> None:
        while not self.queue.empty():
            kind, value = self.queue.get_nowait()
            if kind == "done":
                self.model.log(_describe(value))
                self.model.status = "finished — output above"
            else:
                self.model.log(f"{type(value).__name__}: {value}")
                self.model.status = "finished with a warning (details above)"

    # -- loop ---------------------------------------------------------
    def switch_tab(self, direction: int) -> None:
        self.model.save_overrides(self.store)
        self.model.clear_values()
        (self.model.next_tab if direction > 0 else self.model.prev_tab)()
        self.model.load_overrides(self.store)
        self.scroll = 0

    def loop(self) -> None:
        self.curses.curs_set(0)
        self.screen.keypad(True)
        while True:
            self.drain()
            self.draw()
            key = self.screen.getch()
            if key in (ord("q"), 27):
                return
            if key == self.curses.KEY_RESIZE:
                continue
            if key == 9:                       # TAB
                self.switch_tab(1)
            elif key == self.curses.KEY_BTAB:
                self.switch_tab(-1)
            elif key == self.curses.KEY_DOWN:
                self.model.move(1)
                self.scroll = 0
            elif key == self.curses.KEY_UP:
                self.model.move(-1)
                self.scroll = 0
            elif key == self.curses.KEY_PPAGE:
                self.scroll = min(self.scroll + 4,
                                  max(0, len(self.model.output) - 1))
            elif key == self.curses.KEY_NPAGE:
                self.scroll = max(0, self.scroll - 4)
            elif key in (ord("r"), 10, 13):
                self.model.save_overrides(self.store)
                self.start_run()
            elif key in ACTION_KEYS:
                self.start_run(ACTION_KEYS[key])
            elif key == ord("o"):
                raw = self.ask("OPT=value")
                if raw:
                    for part in raw.split():
                        if "=" in part:
                            self.model.values.append(part.upper())
            elif key == ord("c"):
                self.model.clear_values()
            elif key == ord("/"):
                self.model.set_search(self.ask("filter"))
            elif key == ord("?"):
                self.show_help = not self.show_help


def _describe(value) -> str:
    """One readable line (or a small block) for a module result."""
    if isinstance(value, list):
        return f"{len(value)} row(s)"
    if isinstance(value, dict):
        bits = []
        for key in ("done", "total", "count", "sent", "installed", "missing"):
            if key in value:
                item = value[key]
                bits.append(f"{key}={len(item) if isinstance(item, list) else item}")
        return ", ".join(bits) or f"{len(value)} key(s)"
    return str(value)[:160]


# ---------------------------------------------------------------------------
# plain fallback — works without curses and without a full-screen terminal
# ---------------------------------------------------------------------------

def run_plain_dashboard() -> int:
    """Text dashboard: readiness, actions and a module browser."""
    from omni.core import auto, devices, menu, setup

    while True:
        modules = collect_modules()
        model = Model(modules)
        model.set_needs(collect_needs())
        counts = []
        for family, title, _hint in TABS:
            if family == "home":
                continue
            rows = model.rows_for(family)
            counts.append([title, str(sum(1 for row in rows if row.ready)),
                           str(len(rows))])
        console.banner(__import__("omni").__version__, "dashboard")
        console.table(["trade", "ready", "modules"], counts)
        print("  [a] one-click   [f] full audit   [d] this box   "
              "[t] doctor")
        print("  [i] install missing   [m] browse modules   [q] quit")
        try:
            answer = input(f"{console.C.G}dash>{console.C.X} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if answer in ("q", "quit", "exit"):
            return 0
        try:
            if answer == "a":
                auto.run()
            elif answer == "f":
                auto.run(profile="full")
            elif answer == "d":
                devices.render(devices.inventory())
            elif answer == "t":
                registry.build("core.doctor").run()
            elif answer == "i":
                menu.offer_install(setup.recommended(), menu._read)
            elif answer in ("m", ""):
                menu.browse()
            else:
                console.info("pick one of the letters")
        except (KeyboardInterrupt, EOFError):
            print()
            return 0
        except Exception as exc:                     # noqa: BLE001 - stay alive
            console.err(f"{type(exc).__name__}: {exc} — back at the dashboard")
        print()


def run_dashboard() -> int:
    """Entry point. Never fails: falls back to the text dashboard."""
    if not registry.all():
        console.err("registry is empty — nothing to show")
        return 1
    curses = _curses()
    if curses is None or not (sys.stdin.isatty() and sys.stdout.isatty()):
        if not sys.stdin.isatty():
            # non-interactive: print the readiness matrix and leave cleanly
            model = Model(collect_modules())
            model.set_needs(collect_needs())
            rows = []
            for family, title, _hint in TABS:
                if family == "home":
                    continue
                items = model.rows_for(family)
                rows.append([title, str(sum(1 for row in items if row.ready)),
                             str(len(items))])
            console.banner(__import__("omni").__version__, "dashboard")
            console.table(["trade", "ready", "modules"], rows)
            console.info("run `omni dash` in a terminal for buttons, or "
                         "`omni auto` for the one-click audit")
            return 0
        return run_plain_dashboard()
    model = Model(collect_modules())
    model.set_needs(collect_needs())
    from omni.core import config
    model.load_overrides(config)               # last session's values
    try:
        curses.wrapper(lambda screen: Dashboard(screen, model, config).loop())
    except curses.error as exc:
        console.warn(f"terminal does not support the full-screen dashboard "
                     f"({exc}) — using the text dashboard")
        return run_plain_dashboard()
    return 0
