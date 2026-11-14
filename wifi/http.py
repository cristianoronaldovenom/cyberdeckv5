"""Streaming HTTP/1.x decoding: requests, hosts, URLs and credentials.

``wifi.extract`` parses HTTP *after* a capture has been reassembled. A live
sniffer cannot wait for that: it sees one TCP segment at a time and a header
can be split anywhere — mid-method, mid-``Host``, mid-body. :class:`Decoder`
is the incremental form of the same parse: feed it segments and get back each
message as soon as it completes, then read the interesting parts off it with
the parsers ``wifi.extract`` already uses.

Bodies are followed through ``Content-Length`` and ``Transfer-Encoding:
chunked`` (that is where a login form lives), gunzipped when the server said
so, and mined for ``user``/``password`` pairs. Everything is bytes in and
plain objects out — no sockets, no files — so it is testable without a radio.
"""

from __future__ import annotations

import gzip
import zlib

from omni.wifi import extract

__all__ = ["Message", "Decoder", "decode_text", "MAX_BODY", "METHODS"]

#: bodies kept for credential mining; a firmware upload is not a login form
MAX_BODY = 256 * 1024

#: a first line longer than this is not HTTP, it is a binary stream
MAX_LINE = 8192

METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"PATCH",
           b"OPTIONS", b"TRACE", b"CONNECT")


def decode_text(body: bytes, headers: dict[str, str] | None = None) -> str:
    """Best-effort text of a body: undo gzip/deflate, then UTF-8/latin-1.

    A live capture often holds a partially received body, so a decompression
    failure falls back to the bytes as they arrived instead of raising.
    """
    if not body:
        return ""
    encoding = (headers or {}).get("content-encoding", "").lower()
    raw = body
    if "gzip" in encoding:
        try:
            raw = gzip.decompress(body)
        except (OSError, EOFError, zlib.error):
            raw = body
    elif "deflate" in encoding:
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                raw = zlib.decompress(body, wbits)
                break
            except zlib.error:
                continue
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", "replace")


def _looks_http(head: bytes) -> bool:
    """True when the header block starts with a request or status line."""
    line = head.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
    parts = line.split()
    if len(parts) < 2:
        return False
    if parts[0].startswith(METHODS) and parts[-1].upper().startswith(b"HTTP/"):
        return True
    return bool(parts[0].upper().startswith(b"HTTP/")
                and parts[1][:1].isdigit())


def _content_length(headers: dict[str, str]) -> int:
    try:
        return max(0, min(MAX_BODY, int(headers.get("content-length", "0"))))
    except (TypeError, ValueError):
        return 0


def _dechunk(buf: bytes) -> tuple[bytes, int] | None:
    """(body, bytes consumed) for a chunked body, or None while incomplete."""
    out: list[bytes] = []
    index = 0
    while True:
        crlf = buf.find(b"\r\n", index)
        if crlf == -1:
            return None
        try:
            size = int(buf[index:crlf].split(b";", 1)[0].strip() or b"0", 16)
        except ValueError:
            return None
        index = crlf + 2
        if size == 0:                       # last chunk, then the trailer
            if buf[index:index + 2] == b"\r\n":
                return b"".join(out), index + 2
            trailer = buf.find(b"\r\n\r\n", index)
            return None if trailer == -1 else (b"".join(out), trailer + 4)
        if len(buf) < index + size + 2:
            return None
        out.append(buf[index:index + size])
        index += size + 2


class Message:
    """One complete HTTP message (request or response)."""

    __slots__ = ("start", "headers", "body", "raw", "head")

    def __init__(self, start: str, headers: dict[str, str], body: bytes,
                 raw: bytes, head: bytes):
        self.start, self.headers, self.body = start, headers, body
        self.raw, self.head = raw, head

    # -- what the start line said ------------------------------------------
    @property
    def parts(self) -> list[str]:
        return self.start.split()

    @property
    def is_response(self) -> bool:
        return self.start.upper().startswith("HTTP/")

    @property
    def method(self) -> str:
        return "" if self.is_response or not self.parts else self.parts[0]

    @property
    def target(self) -> str:
        return "" if self.is_response or len(self.parts) < 2 else self.parts[1]

    @property
    def version(self) -> str:
        return self.parts[-1] if self.parts else ""

    @property
    def status(self) -> str:
        return " ".join(self.parts[1:]) if self.is_response else ""

    # -- where it went -----------------------------------------------------
    @property
    def host(self) -> str:
        host = self.headers.get("host", "")
        if host:
            return host.split(":", 1)[0] if host.count(":") == 1 else host
        target = self.target
        if "://" in target:
            authority = target.split("://", 1)[1].split("/", 1)[0]
            return authority.split("@")[-1].split(":")[0]
        return ""

    @property
    def path(self) -> str:
        target = self.target
        if "://" in target:
            return "/" + target.split("://", 1)[1].partition("/")[2]
        return target or "/"

    @property
    def url(self) -> str:
        target = self.target
        if "://" in target:
            return target
        host = self.host
        return f"http://{host}{target}" if host and target else target

    @property
    def agent(self) -> str:
        return self.headers.get("user-agent", "")

    @property
    def cookies(self) -> str:
        return self.headers.get("cookie", "")

    @property
    def ctype(self) -> str:
        return self.headers.get("content-type", "")

    # -- what it carried ---------------------------------------------------
    def credentials(self) -> list[tuple[str, str, str]]:
        """(source, user, password) triples hiding in this message."""
        found: list[tuple[str, str, str]] = []
        for user, pwd in extract.basic_auth(self.head):
            found.append(("basic", user, pwd))
        for user, pwd in extract.url_creds(self.url):
            found.append(("url", user, pwd))
        body = decode_text(self.body, self.headers).encode("latin-1", "replace")
        for user, pwd in extract.form_creds(
                body + b"&" + self.target.encode("latin-1", "replace")):
            found.append(("form", user, pwd))
        seen, unique = set(), []
        for item in found:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

    def row(self) -> list[str]:
        user = passwd = ""
        for _source, name, secret in self.credentials():
            user = user or name
            passwd = passwd or secret
        return [self.method or "HTTP", self.url, user, passwd]

    def as_dict(self) -> dict:
        return {"method": self.method, "url": self.url, "host": self.host,
                "path": self.path, "agent": self.agent,
                "ctype": self.ctype, "bytes": len(self.body),
                "creds": [list(c) for c in self.credentials()]}


class Decoder:
    """Split one TCP direction into complete HTTP messages as they arrive."""

    def __init__(self) -> None:
        self._buf = b""
        self.messages = 0
        self.skipped = 0            # bytes discarded because they were not HTTP

    @property
    def pending(self) -> int:
        return len(self._buf)

    def feed(self, chunk: bytes) -> list[Message]:
        if chunk:
            self._buf += chunk
        out: list[Message] = []
        while True:
            message = self._take()
            if message is None:
                break
            out.append(message)
        if len(self._buf) > 4 * MAX_BODY:       # binary stream: stop hoarding
            self.skipped += len(self._buf) - MAX_BODY
            self._buf = self._buf[-MAX_BODY:]
        return out

    # -- internals ---------------------------------------------------------
    def _drop(self) -> None:
        """Throw away one header block's worth of non-HTTP bytes."""
        end = self._buf.find(b"\r\n\r\n")
        if end == -1:
            end = self._buf.find(b"\n\n")
            cut = len(self._buf) if end == -1 else end + 2
        else:
            cut = end + 4
        self.skipped += cut
        self._buf = self._buf[cut:]

    def _take(self) -> Message | None:
        buf = self._buf
        if not buf:
            return None
        end = buf.find(b"\r\n\r\n")
        sep = 4
        if end == -1:
            end = buf.find(b"\n\n")
            sep = 2
            if end == -1:
                if len(buf) >= MAX_LINE:       # no header block in sight
                    self._drop()
                return None
        head = buf[:end]
        if not _looks_http(head):
            self._drop()
            return None
        parsed = extract.parse_http(head)
        headers = parsed["headers"]
        offset = end + sep
        if "chunked" in headers.get("transfer-encoding", "").lower():
            decoded = _dechunk(buf[offset:])
            if decoded is None:
                return None
            body, used = decoded
            offset += used
        else:
            length = _content_length(headers)
            if len(buf) < offset + length:
                return None
            body = buf[offset:offset + length]
            offset += length
        raw = buf[:offset]
        self._buf = buf[offset:]
        self.messages += 1
        return Message(parsed["start"], headers, body[:MAX_BODY], raw, raw[:end])
