"""Clickable dashboard: plain-English goal cards, one click each.

The window is deliberately not a module browser. It shows the things a person
actually says out loud ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â Wi-Fi attack, iPhone takeover, Windows takeover,
Android attack, Wi-Fi jam ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â with a one-line explanation and a READY / NEEDS
SETUP badge. Click a card and the whole chain runs, target discovery included.

Advanced users can open the full module list from the header. Every job runs
on a worker thread, streams its output, and a missing tool is a yellow line
with the install command, never a traceback or a modal error.
"""

from __future__ import annotations

import io
import queue
import threading

from omni.core import goals
from omni.core.module import registry

__all__ = ["available", "run", "App", "Card"]

#: card colours (dark, high contrast, colour-blind friendly enough)
BG = "#0b1117"
PANEL = "#121a23"
CARD = "#17212c"
CARD_HOVER = "#203040"
TEXT = "#e8eef5"
MUTED = "#93a4b8"
GREEN = "#2ecc71"
AMBER = "#f5b041"
RED = "#e74c3c"


def available() -> bool:
    """True when Tk can be imported on this Python."""
    try:
        import tkinter  # noqa: F401
    except ImportError:
        return False
    return True


class _Writer(io.TextIOBase):
    """stdout replacement that posts lines to the Tk queue."""

    def __init__(self, post):
        self.post = post
        self._buffer = ""

    def write(self, text: str) -> int:
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            self.post(line)
        return len(text)

    def flush(self) -> None:
        if self._buffer:
            self.post(self._buffer)
            self._buffer = ""


class Card:
    """One large clickable goal card with a readiness badge."""

    def __init__(self, parent, goal: goals.Goal, on_click, tk):
        self.goal = goal
        self.on_click = on_click
        self.tk = tk
        self.frame = tk.Frame(parent, bg=CARD, cursor="hand2",
                              highlightthickness=1,
                              highlightbackground="#243241")
        self.frame.grid_propagate(False)
        self.accent = tk.Frame(self.frame, bg=GREEN, width=6)
        self.accent.pack(side="left", fill="y")
        body = tk.Frame(self.frame, bg=CARD)
        body.pack(side="left", fill="both", expand=True, padx=14, pady=7)
        self.title = tk.Label(body, text=goal.title, bg=CARD, fg=TEXT,
                              font=("Segoe UI", 12, "bold"), anchor="w")
        self.title.pack(fill="x")
        self.subtitle = tk.Label(body, text=goal.subtitle, bg=CARD, fg=MUTED,
                                 font=("Segoe UI", 9), anchor="w",
                                 justify="left", wraplength=330)
        self.subtitle.pack(fill="x", pady=(3, 6))
        self.badge = tk.Label(body, text="", bg=CARD, fg=GREEN,
                              font=("Segoe UI", 8, "bold"), anchor="w")
        self.badge.pack(fill="x")
        for widget in (self.frame, body, self.title, self.subtitle,
                       self.badge, self.accent):
            widget.bind("<Button-1>", lambda _e: self.on_click(goal.key))
            widget.bind("<Enter>", self._hover_on)
            widget.bind("<Leave>", self._hover_off)

    def _paint(self, colour: str) -> None:
        self.frame.configure(bg=colour)
        for widget in self.frame.winfo_children():
            if widget is not self.accent:
                widget.configure(bg=colour)
                for child in widget.winfo_children():
                    child.configure(bg=colour)

    def _hover_on(self, _event=None) -> None:
        self._paint(CARD_HOVER)

    def _hover_off(self, _event=None) -> None:
        self._paint(CARD)

    def set_readiness(self, ready: bool, note: str) -> None:
        self.accent.configure(bg=GREEN if ready else AMBER)
        self.badge.configure(text=("READY" if ready else "NEEDS SETUP") +
                             (f" ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â· {note}" if note and not ready else ""),
                             fg=GREEN if ready else AMBER)


class App:
    """The Tk application; created only on the main thread."""

    def __init__(self, root):
        import tkinter as tk

        self.tk = tk
        self.root = root
        self.queue: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.cards: dict[str, Card] = {}
        self.auto_install = False

        root.title("Cyberdeck ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â pick a goal")
        root.configure(bg=BG)
        root.geometry("940x880")
        root.minsize(820, 680)

        header = tk.Frame(root, bg=BG)
        header.pack(fill="x", padx=18, pady=(14, 8))
        tk.Label(header, text="CYBERDECK", bg=BG, fg=TEXT,
                 font=("Segoe UI", 22, "bold")).pack(side="left")
        tk.Label(header, text="  what do you want to do?", bg=BG, fg=MUTED,
                 font=("Segoe UI", 11)).pack(side="left", padx=(8, 0))
        tk.Button(header, text="Install missing tools", bg=PANEL, fg=TEXT,
                  activebackground=CARD_HOVER, activeforeground=TEXT,
                  relief="flat", padx=12, pady=6,
                  command=self.install_tools).pack(side="right")
        tk.Button(header, text="All modules", bg=PANEL, fg=TEXT,
                  activebackground=CARD_HOVER, activeforeground=TEXT,
                  relief="flat", padx=12, pady=6,
                  command=self.open_advanced).pack(side="right", padx=(0, 8))

        attacks = tk.LabelFrame(root, text=" Pick one ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â it finds its target "
                                           "and runs ", bg=BG, fg=MUTED,
                                font=("Segoe UI", 9), borderwidth=0,
                                highlightthickness=1,
                                highlightbackground="#243241")
        attacks.pack(fill="x", padx=18, pady=(2, 6))
        for index, key in enumerate(goals.PRIMARY):
            goal = goals.get(key)
            card = Card(attacks, goal, self.run_goal, tk)
            card.frame.grid(row=index // 2, column=index % 2,
                            sticky="nsew", padx=8, pady=6)
            card.frame.configure(height=98)
            self.cards[key] = card
        attacks.columnconfigure(0, weight=1)
        attacks.columnconfigure(1, weight=1)

        quick = tk.Frame(root, bg=BG)
        quick.pack(fill="x", padx=18, pady=(0, 6))
        for key in goals.SECONDARY:
            goal = goals.get(key)
            button = tk.Button(quick, text=goal.title, bg=PANEL, fg=TEXT,
                               activebackground=CARD_HOVER,
                               activeforeground=TEXT, relief="flat",
                               padx=10, pady=8, font=("Segoe UI", 9),
                               command=lambda k=key: self.run_goal(k))
            button.pack(side="left", expand=True, fill="x", padx=(0, 6))

        footer = tk.Frame(root, bg=BG)
        footer.pack(fill="x", padx=18)
        self.status = tk.Label(footer, text="pick a card", bg=BG, fg=GREEN,
                               font=("Segoe UI", 10, "bold"))
        self.status.pack(side="right")
        self.progress = tk.Frame(footer, bg=PANEL, height=8, width=180)
        self.progress.pack(side="right", padx=10)
        self.bar = tk.Frame(self.progress, bg=GREEN, width=0, height=8)
        self.bar.place(x=0, y=0, relheight=1)

        out = tk.Frame(root, bg=PANEL, highlightthickness=1,
                       highlightbackground="#243241")
        out.pack(fill="both", expand=True, padx=18, pady=(6, 14))
        self.output = tk.Text(out, wrap="word", font=("Consolas", 9),
                              bg=PANEL, fg=TEXT, relief="flat",
                              insertbackground=TEXT, state="disabled")
        scroll = tk.Scrollbar(out, orient="vertical",
                              command=self.output.yview)
        self.output.configure(yscrollcommand=scroll.set)
        self.output.pack(side="left", fill="both", expand=True, padx=(8, 0),
                         pady=8)
        scroll.pack(side="right", fill="y", pady=8)

        self.refresh_readiness()
        self.root.after(120, self._pump)

    # -- readiness -----------------------------------------------------
    def refresh_readiness(self) -> None:
        for key, card in self.cards.items():
            ready, note = goals.readiness(card.goal)
            card.set_readiness(ready, note)

    # -- execution -----------------------------------------------------
    def _busy(self) -> bool:
        return bool(self.worker and self.worker.is_alive())

    def run_goal(self, key: str) -> None:
        if self._busy():
            self.post("still running ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â wait for this one to finish")
            return
        try:
            title = goals.get(key).title
        except KeyError:
            title = key
        self.clear_output()
        self.status.configure(text=f"running {title} ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¦", fg=AMBER)
        self.bar.place(x=0, y=0, relheight=1, relwidth=0)
        self.post(f"=== {title} ===")
        # Tk variables may only be read on the main thread; capture it now
        install = bool(self.auto_install)

        def progress(index: int, total: int, name: str) -> None:
            rel = min(1.0, index / max(1, total))
            self.queue.put(("progress", rel))

        def target() -> None:
            writer = _Writer(self.post)
            old = __import__("sys").stdout
            try:
                __import__("sys").stdout = writer
                report = goals.run_goal(
                    key, log=self.post, progress=progress,
                    install=install)
                outcome = report.get("outcome", "done")
                self.queue.put(("done", (report, outcome)))
            except Exception as exc:          # noqa: BLE001 - never crash
                self.post(f"[failed] {type(exc).__name__}: {exc}")
                self.queue.put(("done", ({"outcome": "partial"}, "partial")))
            finally:
                __import__("sys").stdout = old
                writer.flush()

        self.worker = threading.Thread(target=target, daemon=True)
        self.worker.start()

    def install_tools(self) -> None:
        self.run_module("core.setup", {"PRESET": "recommended"})

    def run_module(self, module: str, options: dict) -> None:
        if self._busy():
            self.post("still running ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â wait for this one to finish")
            return
        self.clear_output()
        self.status.configure(text=f"running {module} ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¦", fg=AMBER)
        self.post(f"$ omni run {module}")

        def target() -> None:
            writer = _Writer(self.post)
            old = __import__("sys").stdout
            try:
                __import__("sys").stdout = writer
                mod = registry.build(module, **options)
                mod.validate()
                mod.run()
                self.post(f"[done] {module}")
            except Exception as exc:          # noqa: BLE001 - show it
                self.post(f"[failed] {type(exc).__name__}: {exc}")
            finally:
                __import__("sys").stdout = old
                writer.flush()
                self.queue.put(("module-done", module))

        self.worker = threading.Thread(target=target, daemon=True)
        self.worker.start()

    def post(self, line: str) -> None:
        self.queue.put(("line", line))

    def clear_output(self) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")

    def append(self, line: str) -> None:
        self.output.configure(state="normal")
        self.output.insert("end", str(line) + "\n")
        self.output.see("end")
        self.output.configure(state="disabled")

    def _pump(self) -> None:
        try:
            while True:
                kind, value = self.queue.get_nowait()
                if kind == "line":
                    self.append(value)
                elif kind == "progress":
                    self.bar.place(x=0, y=0, relheight=1,
                                   relwidth=max(0.02, float(value)))
                elif kind == "done":
                    report, outcome = value
                    colour = GREEN if outcome == "done" else AMBER
                    self.status.configure(text=f"{outcome} ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â see output",
                                          fg=colour)
                    self.bar.place(x=0, y=0, relheight=1, relwidth=1)
                    self.refresh_readiness()
                elif kind == "module-done":
                    self.status.configure(text="finished ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â see output",
                                          fg=GREEN)
                    self.bar.place(x=0, y=0, relheight=1, relwidth=1)
                    self.refresh_readiness()
        except queue.Empty:
            pass
        self.root.after(120, self._pump)

    # -- advanced module browser --------------------------------------
    def open_advanced(self) -> None:
        """A separate window with every module and its options."""
        tk = self.tk
        win = tk.Toplevel(self.root)
        win.title("OMNI ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â all modules")
        win.configure(bg=BG)
        win.geometry("900x620")
        top = tk.Frame(win, bg=BG)
        top.pack(fill="x", padx=12, pady=10)
        tk.Label(top, text="Trade", bg=BG, fg=MUTED).pack(side="left")
        families = ["all"] + [f for f in registry.families()]
        family = tk.StringVar(value="all")
        combo = tk.Frame(top, bg=BG)
        combo.pack(side="left", padx=8)
        tk.OptionMenu(combo, family, *families,
                      command=lambda _v: fill()).pack()
        left = tk.Frame(win, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(12, 6),
                  pady=(0, 12))
        listing = tk.Listbox(left, bg=PANEL, fg=TEXT, relief="flat",
                             selectbackground="#2c4057", font=("Consolas", 9))
        listing.pack(fill="both", expand=True)
        right = tk.Frame(win, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(6, 12),
                   pady=(0, 12))
        options = tk.Frame(right, bg=PANEL)
        options.pack(fill="x")
        entries: dict[str, object] = {}
        mods: list = []

        def fill() -> None:
            listing.delete(0, "end")
            mods.clear()
            for cls in registry.all(None if family.get() == "all"
                                    else family.get()):
                mods.append(cls)
                listing.insert("end", cls.NAME)
            if mods:
                listing.selection_set(0)
                show()

        def show(_event=None) -> None:
            for widget in options.winfo_children():
                widget.destroy()
            entries.clear()
            picked = listing.curselection()
            if not picked:
                return
            cls = mods[picked[0]]
            tk.Label(options, text=cls.NAME, bg=PANEL, fg=TEXT,
                     font=("Segoe UI", 10, "bold")).grid(row=0, column=0,
                                                        columnspan=2,
                                                        sticky="w", padx=8,
                                                        pady=(8, 2))
            for index, opt in enumerate(cls.OPTIONS):
                tk.Label(options, text=opt.name, bg=PANEL, fg=MUTED,
                         anchor="w").grid(row=index + 1, column=0, sticky="w",
                                          padx=8)
                entry = tk.Entry(options, width=28)
                entry.insert(0, opt.default or "")
                entry.grid(row=index + 1, column=1, sticky="ew", pady=2,
                           padx=(0, 8))
                entries[opt.name] = entry

        def run_picked() -> None:
            picked = listing.curselection()
            if not picked:
                return
            cls = mods[picked[0]]
            values = {name: entry.get().strip()
                      for name, entry in entries.items()
                      if entry.get().strip()}
            win.destroy()
            self.run_module(cls.NAME, values)

        listing.bind("<<ListboxSelect>>", show)
        listing.bind("<Double-Button-1>", lambda _e: run_picked())
        buttons = tk.Frame(right, bg=BG)
        buttons.pack(fill="x", pady=8)
        tk.Button(buttons, text="Run selected", bg=GREEN, fg="#08110b",
                  relief="flat", padx=14, pady=7,
                  command=run_picked).pack(side="left")
        tk.Button(buttons, text="Close", bg=PANEL, fg=TEXT, relief="flat",
                  padx=14, pady=7, command=win.destroy).pack(side="left",
                                                             padx=8)
        fill()


_MUTEX = None


def _focus_running() -> bool:
    """Bring an already-open Cyberdeck window forward; True if one exists.

    Double-clicking the shortcut repeatedly should never leave a pile of
    identical windows behind, each with its own half-finished job.
    """
    global _MUTEX
    if __import__("sys").platform != "win32":
        return False
    try:
        import ctypes
        _MUTEX = ctypes.windll.kernel32.CreateMutexW(
            None, False, "Local\\CyberdeckWindow")
        if ctypes.windll.kernel32.GetLastError() != 183:   # ALREADY_EXISTS
            return False
        hwnd = ctypes.windll.user32.FindWindowW(None,
                                                 "Cyberdeck â€” pick a goal")
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 9)       # SW_RESTORE
            ctypes.windll.user32.SetForegroundWindow(hwnd)
        return True
    except (AttributeError, OSError):
        return False


def run(check: bool = False) -> int:
    """Open the window; returns a process exit code."""
    if not check and _focus_running():
        return 0
    if not available():
        from omni.core import console
        console.err("Tkinter is not available ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â using the text dashboard")
        from omni.core.tui import run_plain_dashboard
        return run_plain_dashboard()
    import tkinter as tk
    try:
        root = tk.Tk()
        if (not check and __import__("sys").platform == "win32"
                and getattr(__import__("sys"), "frozen", False)):
            try:
                import ctypes
                ctypes.windll.user32.ShowWindow(
                    ctypes.windll.kernel32.GetConsoleWindow(), 0)
            except (AttributeError, OSError):
                pass
    except tk.TclError as exc:
        from omni.core import console
        console.warn(f"no display for the GUI ({exc}) ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â using the text "
                     "dashboard")
        from omni.core.tui import run_plain_dashboard
        return run_plain_dashboard()
    app = App(root)
    if check:
        import time
        root.update()
        # click every headline card for real: this is what used to raise the
        # Tk thread error and leave the button looking dead
        states = {}
        for key in goals.PRIMARY:
            app.run_goal(key)
            deadline = time.time() + 90
            while app._busy() and time.time() < deadline:
                root.update()
                time.sleep(0.05)
            root.update()
            app._pump()
            states[key] = app.status.cget("text")
        bad = [k for k, state in states.items() if "running" in state]
        print(f"GUI OK â€” {len(app.cards)} cards; clicks: " +
              ", ".join(f"{k}={states[k].split(' ')[0]}" for k in states))
        root.destroy()
        return 1 if bad else 0
    root.mainloop()
    return 0






