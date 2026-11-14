"""Raw device streams: the input event tap and the notification dump.

Two things a rooted phone shows a shell that a screenshot never does:

* ``getevent -lt`` — every touch and key event, with the *key name*
  (``KEY_A``), so a PIN or a search query typed on the phone can be rebuilt
  from the event stream without any injected code;
* ``dumpsys notification --noredact`` — the notification shade, with the
  full title and body text of every posted notification.

Both are pure text parsers, so the decoding is testable without a phone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["Event", "parse_getevent", "decode_text", "is_key", "key_counts",
           "KEY_TEXT", "NAMED_KEYS", "parse_notifications",
           "notification_rows"]


#: linux input keycode -> the character it produces (unshifted)
_KEY_TEXT: dict[str, str] = {
    "KEY_SPACE": " ", "KEY_ENTER": "\n", "KEY_KPENTER": "\n",
    "KEY_TAB": "\t", "KEY_DOT": ".", "KEY_COMMA": ",", "KEY_MINUS": "-",
    "KEY_SLASH": "/", "KEY_AT": "@", "KEY_SEMICOLON": ";",
    "KEY_APOSTROPHE": "'", "KEY_GRAVE": "`", "KEY_EQUAL": "=",
    "KEY_LEFTBRACE": "[", "KEY_RIGHTBRACE": "]", "KEY_BACKSLASH": "\\",
    "KEY_STAR": "*", "KEY_POUND": "#", "KEY_PLUS": "+",
}
for _index, _letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    _KEY_TEXT[f"KEY_{_letter}"] = _letter.lower()
for _digit in range(10):
    _KEY_TEXT[f"KEY_{_digit}"] = str(_digit)

KEY_TEXT = _KEY_TEXT

#: keys that change state instead of producing a character
NAMED_KEYS = {
    "KEY_LEFTSHIFT": "shift", "KEY_RIGHTSHIFT": "shift",
    "KEY_BACKSPACE": "backspace", "KEY_FORWARD_DEL": "delete",
    "KEY_LEFTCTRL": "ctrl", "KEY_RIGHTCTRL": "ctrl",
    "KEY_LEFTALT": "alt", "KEY_RIGHTALT": "alt",
    "KEY_ESC": "escape", "KEY_HOME": "home", "KEY_BACK": "back",
    "KEY_VOLUMEUP": "volume_up", "KEY_VOLUMEDOWN": "volume_down",
    "KEY_POWER": "power", "KEY_MENU": "menu", "KEY_APP_SWITCH": "app_switch",
}

#: hex event types we care about, from ``getevent`` without ``-l``
_EVENT_TYPES = {"0000": "EV_SYN", "0001": "EV_KEY", "0002": "EV_REL",
                "0003": "EV_ABS"}

#: linux input codes for the keys we decode, so a capture taken *without*
#: ``-l`` (numeric only) still becomes text
_HEX_TO_NAME: dict[str, str] = {
    "0001": "KEY_ESC", "000e": "KEY_BACKSPACE", "000f": "KEY_TAB",
    "001c": "KEY_ENTER", "002a": "KEY_LEFTSHIFT", "0036": "KEY_RIGHTSHIFT",
    "0039": "KEY_SPACE", "0033": "KEY_COMMA", "0034": "KEY_DOT",
    "0035": "KEY_SLASH", "0027": "KEY_APOSTROPHE", "0029": "KEY_GRAVE",
    "000c": "KEY_MINUS", "000d": "KEY_EQUAL", "001a": "KEY_LEFTBRACE",
    "001b": "KEY_RIGHTBRACE", "002b": "KEY_BACKSLASH",
}
for _code, _letter in zip(range(0x02, 0x0C), "1234567890"):
    _HEX_TO_NAME[f"{_code:04x}"] = f"KEY_{_letter}"
for _code, _letter in zip(range(0x10, 0x1A), "qwertyuiop"):
    _HEX_TO_NAME[f"{_code:04x}"] = f"KEY_{_letter.upper()}"
for _code, _letter in zip(range(0x1E, 0x27), "asdfghjkl"):
    _HEX_TO_NAME[f"{_code:04x}"] = f"KEY_{_letter.upper()}"
for _code, _letter in zip(range(0x2C, 0x33), "zxcvbnm"):
    _HEX_TO_NAME[f"{_code:04x}"] = f"KEY_{_letter.upper()}"


_LINE_RE = re.compile(r"^\s*(?P<device>[^:]+):\s+(?P<rest>\S.*)$")
_KIND_RE = re.compile(r"\b(EV_[A-Z]+)\b")
_NAME_RE = re.compile(r"\b(KEY_[A-Z0-9_]+)\b")
#: non-key names that still matter (touch points, synchronisation, switches)
_OTHER_RE = re.compile(r"\b((?:ABS|SYN|REL|SW|MSC)_[A-Z0-9_]+)\b")
_HEX_RE = re.compile(r"^(?:\([0-9a-fA-F]+\)\s*)?([0-9a-fA-F]{4})\s+"
                     r"(?:\([0-9a-fA-F]+\)\s*)?([0-9a-fA-F]{4})\s+"
                     r"([0-9a-fA-F]{8})$")


@dataclass(frozen=True)
class Event:
    """One line of ``getevent`` output."""

    device: str = ""
    kind: str = ""
    code: str = ""
    value: str = ""

    @property
    def down(self) -> bool:
        return self.value == "DOWN"

    @property
    def up(self) -> bool:
        return self.value == "UP"

    @property
    def repeat(self) -> bool:
        return self.value == "REPEAT"

    def to_row(self) -> dict:
        return {"device": self.device, "kind": self.kind, "code": self.code,
                "value": self.value}


def parse_getevent(text: str) -> list[Event]:
    """Events from ``getevent -lt`` (named) or plain ``getevent`` (hex).

    Lines that are not events (the ``add device`` header, shell noise) are
    skipped, so a bounded capture can be parsed whole.
    """
    events: list[Event] = []
    for line in (text or "").splitlines():
        match = _LINE_RE.match(line)
        if not match:
            continue
        device, rest = match.group("device").strip(), match.group("rest")
        kind_match = _KIND_RE.search(rest)
        kind = kind_match.group(1) if kind_match else ""
        hex_match = _HEX_RE.match(rest.strip())
        if not kind and hex_match:
            kind = _EVENT_TYPES.get(hex_match.group(1).lower(), "")
        if not kind:
            continue
        name_match = _NAME_RE.search(rest)
        if name_match:
            code = name_match.group(1)
        elif hex_match:
            numeric = hex_match.group(2).lower()
            code = _HEX_TO_NAME.get(numeric, f"0x{numeric}")
        else:
            other = _OTHER_RE.search(rest)
            code = other.group(1) if other else ""
        if not code:
            continue
        if "DOWN" in rest:
            value = "DOWN"
        elif "UP" in rest:
            value = "UP"
        elif "REPEAT" in rest:
            value = "REPEAT"
        else:
            value = hex_match.group(3) if hex_match else ""
        events.append(Event(device, kind, code, value))
    return events


def is_key(event: Event) -> bool:
    """True for a key press we can turn into a character or a named key."""
    return event.kind == "EV_KEY" and event.code.startswith("KEY_")


def decode_text(events: list[Event]) -> str:
    """Rebuild the typed text from a key event stream.

    Only ``DOWN`` events count (a ``REPEAT`` is a held key, an ``UP`` closes
    it), shift is tracked as a state, and backspace deletes from the buffer —
    which is what makes a corrected PIN or a corrected search term come out
    the way the operator typed it.
    """
    out: list[str] = []
    shift = False
    for event in events:
        if not is_key(event):
            continue
        role = NAMED_KEYS.get(event.code, "")
        if role == "shift":
            shift = event.value != "UP"
            continue
        if not event.down:
            continue
        if role == "backspace":
            if out:
                out.pop()
            continue
        char = KEY_TEXT.get(event.code)
        if char is None:
            continue
        out.append(char.upper() if shift and char.isalpha() else char)
    return "".join(out)


def key_counts(events: list[Event]) -> dict[str, int]:
    """How often each key went down — the report when text is unreadable."""
    counts: dict[str, int] = {}
    for event in events:
        if is_key(event) and event.down:
            counts[event.code] = counts.get(event.code, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))



# ---------------------------------------------------------------------------
# notification shade
# ---------------------------------------------------------------------------

_RECORD_RE = re.compile(r"NotificationRecord\(0x[0-9a-fA-F]+")
_PKG_RE = re.compile(r"\bpkg=([\w.]+)")
_ID_RE = re.compile(r"\bid=(-?\d+)")
_WHEN_RE = re.compile(r"\bwhen=(-?\d+)")
_CHANNEL_RE = re.compile(r"\bchannel=([\w.-]+)")
_ATTR_RE = re.compile(r"^\s*(android\.\w+|[a-zA-Z]+Text)=(.+?)\s*$")
#: ``String (hello)`` / ``SpannableString (hi)`` / ``CharSequence (x)``
_VALUE_RE = re.compile(r"^(?:[\w.$]*String|CharSequence)\s*\((.*)\)$", re.S)


def _attr_value(raw: str) -> str:
    """Unwrap a ``dumpsys`` extras value into plain text (``''`` if empty)."""
    text = raw.strip()
    if text in ("null", "[]", ""):
        return ""
    match = _VALUE_RE.match(text)
    if match:
        text = match.group(1)
    return text.replace("\\n", " ").strip()


def parse_notifications(text: str) -> list[dict]:
    """Structured rows from ``dumpsys notification --noredact``.

    The dump is a flat list of properties grouped by a leading
    ``NotificationRecord(...)`` line, so that header opens a block and the
    ``android.*`` extras inside it fill the block in.
    """
    notices: list[dict] = []
    current: dict | None = None
    for line in (text or "").splitlines():
        if _RECORD_RE.search(line):
            if current:
                notices.append(current)
            package = _PKG_RE.search(line)
            ident = _ID_RE.search(line)
            when = _WHEN_RE.search(line)
            channel = _CHANNEL_RE.search(line)
            current = {"package": package.group(1) if package else "",
                       "id": int(ident.group(1)) if ident else 0,
                       "when": int(when.group(1)) if when else 0,
                       "channel": channel.group(1) if channel else "",
                       "title": "", "text": ""}
            continue
        if current is None:
            continue
        match = _ATTR_RE.match(line)
        if not match:
            continue
        key, raw = match.group(1), _attr_value(match.group(2))
        if key in ("android.title", "tickerText") and not current["title"]:
            current["title"] = raw
        elif key in ("android.text", "android.bigText") and not current["text"]:
            current["text"] = raw
    if current:
        notices.append(current)

    seen: list[dict] = []
    for note in notices:
        if not (note["package"] or note["title"] or note["text"]):
            continue
        if note not in seen:
            seen.append(note)
    return seen


def notification_rows(notices: list[dict], limit: int = 40) -> list[list[str]]:
    """Table rows for the console (package / title / text)."""
    rows = []
    for note in notices[:max(1, limit)]:
        rows.append([note.get("package", "")[:26],
                     (note.get("title") or "-")[:26],
                     (note.get("text") or "-")[:46]])
    return rows
