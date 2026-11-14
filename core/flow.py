"""One tiny script grammar, shared by the device takeovers.

An unattended takeover is a list of actions in order with **per-step** results:
both the Android and the iPhone path need "wait for this label, type that, tap,
screenshot", and both need the run to survive a step the UI no longer agrees
with. The parser lives here once; each trade supplies its own verb handlers, so
``tap`` is an ADB tap on Android and an HID tap on iOS.

    # one step per line (';' works too, '#' starts a comment)
    wait "Sign in" 10
    tap "Sign in"
    type hunter2
    key enter
    swipe up
    sleep 1.5
    shot loot/login.png

Quoting follows shell rules, so an argument with spaces must be quoted. A line
whose verb this trade does not implement fails alone: it is a UI that moved, not
a broken script.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Callable, Iterable

__all__ = ["Step", "split", "parse", "execute", "describe", "CORE_VERBS"]


#: verbs every trade that drives a screen can implement
CORE_VERBS = ("tap", "wait", "type", "key", "swipe", "scroll", "sleep",
              "shot", "launch", "unlock")


@dataclass(frozen=True)
class Step:
    """One parsed script step."""

    verb: str
    args: tuple[str, ...] = ()
    line: int = 0
    raw: str = ""

    # -- argument accessors ------------------------------------------------
    def arg(self, index: int, default: str = "") -> str:
        return self.args[index] if 0 <= index < len(self.args) else default

    def number(self, index: int, default: float = 0.0) -> float:
        raw = self.arg(index)
        try:
            return float(raw)
        except (TypeError, ValueError):
            return default

    def integer(self, index: int, default: int = 0) -> int:
        return int(self.number(index, float(default)))

    def flag(self, index: int, default: bool = False) -> bool:
        raw = self.arg(index).strip().lower()
        if not raw:
            return default
        return raw in ("1", "true", "yes", "y", "on")

    # -- display -----------------------------------------------------------
    def text(self) -> str:
        return " ".join((self.verb,) + self.args)

    def __str__(self) -> str:                       # pragma: no cover - trivial
        return self.text()


def _tokens(raw: str) -> list[str]:
    """Shell-ish tokens for one chunk; raises ``ValueError`` on a bad quote."""
    lexer = shlex.shlex(raw, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError as exc:
        raise ValueError(f"unbalanced quote in {raw!r} ({exc})") from None


def split(text: str) -> list[tuple[int, str]]:
    """Chunks of a script as ``(first_line_number, chunk)``.

    ``;`` and newlines separate steps, ``#`` outside quotes comments out the
    rest of the line, and quotes protect both separators — so
    ``type "a;b"  # note`` stays one step.
    """
    chunks: list[tuple[int, str]] = []
    buffer: list[str] = []
    quote = ""
    in_comment = False
    line_no = 1
    started = 1
    for char in (text or "").replace("\r\n", "\n").replace("\r", "\n"):
        if char == "\n":
            if "".join(buffer).strip():
                chunks.append((started, "".join(buffer).strip()))
            buffer, quote = [], ""
            in_comment = False
            line_no, started = line_no + 1, line_no + 1
            continue
        if quote:
            buffer.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            if not buffer:
                started = line_no
            quote = char
            buffer.append(char)
            continue
        if char == "#":
            if "".join(buffer).strip():
                chunks.append((started, "".join(buffer).strip()))
            buffer = []
            in_comment = True
            continue
        if in_comment:
            continue
        if char == ";":
            if "".join(buffer).strip():
                chunks.append((started, "".join(buffer).strip()))
            buffer, started = [], line_no
            continue
        if not buffer and char in " \t":
            started = line_no
            continue
        buffer.append(char)
    if "".join(buffer).strip():
        chunks.append((started, "".join(buffer).strip()))
    return chunks


def parse(text: str, verbs: Iterable[str] | None = None) -> list[Step]:
    """Parse a script; ``verbs`` restricts and validates the vocabulary."""
    allowed = {v.lower() for v in verbs} if verbs else None
    steps: list[Step] = []
    for line_no, raw in split(text):
        tokens = _tokens(raw)
        if not tokens:
            continue
        verb = tokens[0].lower()
        if allowed is not None and verb not in allowed:
            raise ValueError(f"line {line_no}: unknown step {verb!r} "
                             f"(known: {', '.join(sorted(allowed))})")
        steps.append(Step(verb, tuple(tokens[1:]), line_no, raw))
    return steps


def execute(steps: list[Step], handlers: dict[str, Callable[[Step], object]],
            stop_on_error: bool = True,
            observer: Callable[[dict], None] | None = None) -> dict:
    """Run parsed steps; failures are recorded, not raised.

    Returns ``{"ok", "ran", "failed", "results"}`` where each result carries
    the step, its source line, and either ``value`` or ``error``.
    """
    results: list[dict] = []
    for step in steps:
        handler = handlers.get(step.verb)
        if handler is None:
            results.append({"line": step.line, "step": step.text(),
                            "ok": False,
                            "error": f"no handler for {step.verb!r}"})
        else:
            try:
                results.append({"line": step.line, "step": step.text(),
                                "ok": True, "value": handler(step)})
            except Exception as exc:              # noqa: BLE001 - reported
                results.append({"line": step.line, "step": step.text(),
                                "ok": False,
                                "error": f"{type(exc).__name__}: {exc}"})
        if observer is not None:
            observer(results[-1])
        if not results[-1]["ok"] and stop_on_error:
            break
    failed = sum(1 for row in results if not row["ok"])
    return {"ok": failed == 0, "ran": len(results), "failed": failed,
            "results": results}


def describe(steps: list[Step]) -> list[str]:
    """One display line per step, numbered by source line."""
    return [f"{step.line:>3}  {step.text()}" for step in steps]

